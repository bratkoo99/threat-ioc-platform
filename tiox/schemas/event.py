"""
Canonical event schema for the threat platform.

Every source (endpoint agent, EDR connector, feed poller, cloud audit log, IdP log)
normalizes into `Event`. This is the spine of the platform: if two events can be
joined, it is because they share a field in this schema.

Design rules, in priority order:
  1. Every event is a pivot carrier. `entities` is the reason the schema exists.
  2. `ts` (when it happened) and `ingest_ts` (when we learned) are always distinct.
     Late-arriving data is normal, not exceptional.
  3. Never reject an event for having unknown extra fields. Forward compatibility
     beats strictness at the ingest boundary; validation lives in the store.
  4. `raw` always holds the original payload. Normalization is a view, not a
     replacement, so a bad normalizer can always be fixed and re-run.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any


SCHEMA_VERSION = "1.0.0"


# ============================ ENUMS ============================
# Fixed sets, not free text. Analytics and UI filters depend on these being closed.


class EventType(str, Enum):
    FILE = "file"
    PROCESS = "process"
    NETWORK_CONN = "network_conn"
    DNS = "dns"
    AUTH = "auth"
    REGISTRY = "registry"
    THREAT_HIT = "threat_hit"
    ALERT = "alert"
    INCIDENT = "incident"
    AGENT_STATUS = "agent_status"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Ordered for comparisons: _RANK["high"] > _RANK["low"].
_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_at_least(sev: "str | Severity", floor: "str | Severity") -> bool:
    return _RANK[Severity(sev)] >= _RANK[Severity(floor)]


# ============================ ENTITY TYPES ============================
# The pivot vocabulary. Adding a type here is a schema migration, so only add one
# when a real connector needs it.


class EntityType(str, Enum):
    FILE_HASH = "file_hash"
    FILE_PATH = "file_path"
    FILE_NAME = "file_name"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    PROCESS = "process"
    REGISTRY_KEY = "registry_key"
    USER = "user"
    HOST = "host"
    MUTEX = "mutex"
    SCHEDULED_TASK = "scheduled_task"
    CERT = "cert"
    EMAIL = "email"


# Entity values are normalized (lowercased) so that pivots join reliably.
_NORMALIZE_ENTITY_TYPES = {
    EntityType.FILE_HASH,
    EntityType.DOMAIN,
    EntityType.URL,
    EntityType.USER,
    EntityType.REGISTRY_KEY,
}


# ============================ TIME ============================


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(ts: datetime | None = None) -> str:
    return (ts or utcnow()).astimezone(timezone.utc).isoformat()


# ============================ VALIDATION ============================

_HASH_RE = re.compile(r"^[a-f0-9]{64}$")           # sha256
_HASH_ANY_RE = re.compile(r"^[a-f0-9]{32,128}$")   # md5 / sha1 / sha256
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _is_ipv4(value: str) -> bool:
    """Validate IPv4 including octet range. Regex alone accepts 999.1.1.1."""
    v = value.strip()
    if not _IPV4_RE.match(v):
        return False
    parts = v.split(".")
    return all(0 <= int(p) <= 255 and (p == "0" or not p.startswith("0")) for p in parts)


class SchemaError(ValueError):
    """Raised when an event cannot be normalized. Always carries the reason."""


def _norm_entity_value(etype: EntityType, value: str) -> str:
    v = value.strip()
    if etype in _NORMALIZE_ENTITY_TYPES:
        v = v.lower()
    if etype is EntityType.FILE_HASH:
        if not _HASH_ANY_RE.match(v):
            raise SchemaError(f"not a valid hash: {value!r}")
    return v


# ============================ EVENT ============================


@dataclass(slots=True)
class Event:
    """
    One normalized observation. Construct via `Event.create` or a connector;
    validation is deliberately lenient about extra keys.

    Entities are the pivot surface. An event with no entities is legal (a heartbeat)
    but almost never useful, so connectors should populate them.
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ts: str = field(default_factory=iso)             # when it happened
    ingest_ts: str = field(default_factory=iso)      # when we learned about it
    source: str = "unknown"                          # which connector
    type: str = EventType.FILE.value
    severity: str = Severity.INFO.value
    host: str | None = None
    user: str | None = None
    entities: dict[str, list[str]] = field(default_factory=dict)
    title: str = ""
    description: str = ""
    rule_id: str | None = None
    tlp: str = "amber"                               # amber/green/amber+strict, white
    raw: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    schema_version: str = SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.severity not in {s.value for s in Severity}:
            raise SchemaError(
                f"invalid severity {self.severity!r}; expected one of "
                f"{[s.value for s in Severity]}"
            )
        if self.type not in {t.value for t in EventType}:
            raise SchemaError(
                f"invalid type {self.type!r}; expected one of "
                f"{[t.value for t in EventType]}"
            )
        # Normalize entity values and drop empties rather than rejecting the event.
        cleaned: dict[str, list[str]] = {}
        for etype, values in (self.entities or {}).items():
            if etype not in {e.value for e in EntityType}:
                # Unknown entity type: keep it under raw, do not fail ingest.
                self.raw.setdefault("_unmapped_entities", {})[etype] = list(values or [])
                continue
            out: list[str] = []
            for val in values or []:
                try:
                    n = _norm_entity_value(EntityType(etype), val)
                except SchemaError:
                    continue
                if n and n not in out:
                    out.append(n)
            if out:
                cleaned[etype] = out
        self.entities = cleaned
        if not self.title:
            self.title = self.description[:120] or f"{self.type} event"

    # ---------- serialization ----------

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        known = set(cls.__dataclass_fields__)
        kwargs = {k: v for k, v in data.items() if k in known}
        ev = cls(**kwargs)
        extra = {k: v for k, v in data.items() if k not in known}
        if extra:
            ev.raw.setdefault("_extra_fields", {}).update(extra)
        return ev

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @classmethod
    def from_json(cls, blob: str | bytes) -> "Event":
        return cls.from_dict(json.loads(blob))

    def __str__(self) -> str:
        ents = " ".join(f"{k}={v}" for k, v in self.entities.items())
        return f"<Event {self.type} {self.severity} src={self.source} {ents}>"

    # ---------- dedupe ----------

    def dedupe_key(self) -> str:
        """
        Content fingerprint, stable across re-ingest of the same fact.

        `event_id` is a random UUID and is the primary key, so it cannot dedupe
        anything by itself. A retried agent POST, a re-run of a scan over an
        unchanged tree, and a replayed feed all produce *new* UUIDs for the same
        underlying observation. This key is what makes insert idempotent.

        Deliberately excludes: event_id, ingest_ts, description, severity. Those
        can legitimately differ between a first sighting and a later re-report of
        the same thing, and including them would defeat the purpose.

        `ts` is included only when the source actually supplied it (the connector
        sets `raw._ts_derived` when it had to invent one). That distinction
        matters: two identical agent POSTs for the same file carry no time of
        their own, so a fresh `now()` per normalize would make them look like
        distinct observations and double-count every alert. But a source that
        *does* report occurrence times is re-reporting, and two sightings at
        different instants are genuinely two events.

        `title` is deliberately NOT included even though it participates in
        display. `Event.__post_init__` derives title from description, so
        including it would make the fingerprint change whenever prose changes —
        which defeats the point of ignoring description.
        """
        derived = bool(self.raw.get("_ts_derived"))
        payload = json.dumps(
            {
                "source": self.source,
                "type": self.type,
                "ts": None if derived else self.ts,
                "host": (self.host or "").lower(),
                "user": (self.user or "").lower(),
                "rule_id": self.rule_id or "",
                "entities": {k: sorted(v) for k, v in sorted(self.entities.items())},
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()


# ============================ ENTITY EXTRACTION ============================
# Shared helpers so every connector derives pivot values the same way. This is
# where normalization bugs get expensive, so it is centralized on purpose.


def hash_entities(hashes: dict[str, str]) -> dict[str, list[str]]:
    """{'sha256': 'AB12...'} -> {'file_hash': ['ab12...']}"""
    out: list[str] = []
    for value in hashes.values():
        v = (value or "").strip().lower()
        if _HASH_ANY_RE.match(v):
            out.append(v)
    return {"file_hash": out} if out else {}


def host_entities(hostname: str | None, ip: str | None = None) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    if hostname:
        out["host"] = [hostname.strip()]
    if ip and _is_ipv4(ip):
        out["ip"] = [ip.strip()]
    return out


def network_entities(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    domain: str | None = None,
    url: str | None = None,
) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for val in (src_ip, dst_ip):
        if val and _is_ipv4(val):
            bucket = out.setdefault("ip", [])
            if val.strip() not in bucket:
                bucket.append(val.strip())
    if domain and _DOMAIN_RE.match(domain.strip().lower()):
        out["domain"] = [domain.strip().lower()]
    if url:
        u = url.strip()
        if u.startswith(("http://", "https://")):
            out.setdefault("url", []).append(u)
            # A URL also yields its host, which is a useful pivot.
            host_part = u.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
            if _DOMAIN_RE.match(host_part):
                bucket = out.setdefault("domain", [])
                if host_part not in bucket:
                    bucket.append(host_part)
    return {k: v for k, v in out.items() if v}


def merge_entities(*maps: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """Union several entity maps, preserving order, dropping empties."""
    out: dict[str, list[str]] = {}
    for m in maps:
        for etype, values in (m or {}).items():
            bucket = out.setdefault(etype, [])
            for v in values:
                if v and v not in bucket:
                    bucket.append(v)
    return {k: v for k, v in out.items() if v}
