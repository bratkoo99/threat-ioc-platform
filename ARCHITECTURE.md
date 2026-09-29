# Architecture

## Why this document exists

The goal is a Cortex-style platform: a normalized data lake plus an investigation
workbench, not a scanner with a dashboard. The scan capability is real but it is
the smallest part. This document records the decisions that are expensive to
reverse, so later phases build on them instead of around them.

## The canonical event

Everything a connector produces is an `Event` (`tiox/schemas/event.py`). One
schema, one shape, so that any two observations can be joined.

```python
Event(
    event_id,          # uuid, PK
    ts,                # when it happened (UTC)
    ingest_ts,         # when we learned (UTC) -- always distinct from ts
    source,            # connector name: "agent", "edr", "stix", ...
    type,              # closed enum: file, process, network_conn, dns, auth, ...
    severity,          # info | low | medium | high | critical
    host, user,
    entities,          # the pivot surface -- see below
    title, description, rule_id, tlp, raw, tags,
)
```

`entities` is the reason the schema exists:

```python
entities = {
    "file_hash": ["275a021b..."],
    "ip":       ["10.0.0.5"],
    "domain":   ["c2.evil.com"],
    "host":     ["ws-01"],
}
```

When an analyst clicks a hash, the platform runs one indexed query against
`event_entities` and returns everything ever seen for that value, across all
sources and all time. That is the "pivot" — the single feature that makes a lake
platform worth more than a set of separate tools. It is why `entities` had to be
designed before any UI existed.

Entity types are a closed enum on purpose. Adding one is a schema migration, so
it only happens when a real connector needs it.

### Rules the schema enforces

- `ts` and `ingest_ts` are never the same field. Late-arriving data is normal, and
  a lake that cannot distinguish "when" from "when we heard" cannot do
  retrospective detection.
- Invalid enum values reject the event. Invalid *entity values* are dropped, not
  fatal — one bad hash in a feed must not discard the other 9,999 indicators.
- Unknown entity types are preserved under `raw._unmapped_entities` instead of
  being silently dropped, so a new source's data is recoverable.
- `raw` always holds the original payload. Normalization is a view, not a
  replacement: a bad normalizer can be fixed and re-run over stored raw data.

## Deduplication

`event_id` is a random uuid and cannot dedupe anything. A retried agent POST, a
re-run of a scan over an unchanged tree, and a replayed STIX bundle all mint fresh
uuids for the same underlying fact. So `Event.dedupe_key()` computes a content
fingerprint, enforced by a unique index in the store.

Included in the fingerprint: `source`, `type`, `ts`, `host`, `user`, `rule_id`,
normalized `entities`.

Excluded, deliberately:
- `event_id`, `ingest_ts` — bookkeeping, not identity.
- `description`, `severity` — a re-report can legitimately re-score a finding;
  including them would make every wording tweak a "new" event.
- `title` — because `__post_init__` derives it from `description`, so including it
  would smuggle prose back into identity.
- `ts`, **when the connector had to invent it** (`raw._ts_derived`). The agent
  sends no occurrence time, so a fresh `now()` per normalize would make two
  identical POSTs look like two observations and double-count every alert. A
  source that *does* report occurrence times keeps `ts` in the fingerprint,
  because two sightings at different instants genuinely are two events.

## Connectors

A connector is a class with one method:

```python
class MyConnector(Connector):
    NAME = "my_source"
    SCHEMA_VER = "1"

    def normalize(self, payload, context=None) -> list[Event]:
        ...
```

Connectors are pure: no storage, no decisions, no knowledge of what detection
does downstream. `tiox/store/pipeline.py:ingest()` is the only path into the lake —
it owns normalization, dedupe, and persistence, and contains connector failures
so one bad feed cannot take down the agent path.

`registry.py` holds name -> instance and owns the major-version compatibility
check between a source's schema and the platform's.

`agent.py` is the reference implementation, mapping the existing
`/api/agent/*` payloads onto events. Copy its shape for the EDR and STIX
connectors, not its content.

## Layers

```
collectors        agent (existing), STIX/TAXII, abuse.ch, cloud, IdP
    |             each a Connector, emits canonical Events
    v
pipeline          ingest(): normalize -> dedupe -> persist. Failure-isolated.
    v
control plane     SQLite now, Postgres in Phase 1. Endpoints, incidents, config.
    |             NOT the event lake.
    v
event lake        Phase 1: ClickHouse. This is where events live long-term.
```

The control plane and the lake are separate on purpose. Config and workflow state
want transactions and small tables; events want columnar scans over billions of
rows. `tiox/store/control.py` keeps a `POSTGRES_SQL` constant with the equivalent
DDL so the Phase 1 swap is a reviewed diff rather than a rewrite from memory.

## Authentication

Two credentials, so a compromised endpoint cannot reach operator functions:

| credential | scope | storage |
|---|---|---|
| agent key | `/api/agent/*` only | `.agent_key`, mode 0600, or `TIOX_AGENT_KEY` |
| session key | everything else | printed at startup, or `TIOX_SESSION_KEY` |

The gate lives in `Handler.is_authorized()` and is called at the top of `do_GET`
and `do_POST`, so a newly added endpoint is protected by default rather than by
remembering to guard it. Public routes are an explicit allowlist. Comparison is
`hmac.compare_digest`, and the test suite asserts that a one-character-short key
is rejected.

The browser exchanges the session key for an `HttpOnly; SameSite=Strict` cookie at
`/api/login`, because `EventSource` cannot set request headers and the live event
stream would otherwise be the one authenticated request with no way to carry a
credential. `Secure` is added automatically when the connection is TLS.

## Transport

TLS is on by default (`TIOX_TLS=1`). Port 8443 was previously bound in cleartext
with no `ssl` anywhere in the file, so the agent key and every scan report crossed
the network in the open while the port number implied encryption. A missing cert
is now a hard startup error with the `openssl` command to fix it, not a silent
downgrade. `TIOX_BIND` defaults to `127.0.0.1` rather than `0.0.0.0`.

## Known deliberate limitations

- The agent sends naive local timestamps. The connector treats them as UTC and
  records `raw._ts_assumed_utc` so the assumption stays auditable. Phase 0 does
  not change the agent's wire format, because that would require redeploying
  every agent.
- `incidents.json` and `inventory.json` are still what the legacy web server
  reads. `tiox.control.migrate` replays them into the control plane
  (idempotently); wiring the live server to the new store is Phase 0.6.
- SQLite is not the lake. It is here so Phase 0 is testable end to end.
- Detection is still exact SHA-256 plus filename patterns. Imphash, fuzzy
  hashing, YARA, and entropy are Phase 4, and they are cheap to add later
  precisely because hashes are already first-class entities here.
