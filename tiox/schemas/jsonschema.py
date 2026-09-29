"""
JSON Schema (draft 2020-12) for the canonical event.

Generated from the dataclass rather than hand-written, so the two can't drift.
Regenerate after changing event.py:
    python3 -m tiox.schemas.jsonschema
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

if __package__ in (None, ""):  # allow direct script execution
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tiox.schemas.event import (  # noqa: E402
    SCHEMA_VERSION,
    EntityType,
    Event,
    EventType,
    Severity,
)

SCHEMA_FILENAME = "event.schema.json"


def build_json_schema() -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"https://threat-ioc-platform.local/schemas/event/{SCHEMA_VERSION}.json",
        "title": "Canonical Event",
        "description": (
            "Normalized security event. All connectors emit this shape so any two "
            "observations can be joined on shared entities."
        ),
        "type": "object",
        "required": ["event_id", "ts", "ingest_ts", "source", "type", "severity"],
        "additionalProperties": False,
        "properties": {
            "event_id": {
                "type": "string",
                "format": "uuid",
                "description": "Dedupe key. Stable across re-ingest of the same fact.",
            },
            "ts": {
                "type": "string",
                "format": "date-time",
                "description": "When the observation happened (UTC).",
            },
            "ingest_ts": {
                "type": "string",
                "format": "date-time",
                "description": "When this platform learned about it (UTC).",
            },
            "source": {
                "type": "string",
                "description": "Connector that produced this, e.g. 'agent', 'edr', 'stix'.",
            },
            "type": {"type": "string", "enum": [t.value for t in EventType]},
            "severity": {"type": "string", "enum": [s.value for s in Severity]},
            "host": {"type": ["string", "null"]},
            "user": {"type": ["string", "null"]},
            "entities": {
                "type": "object",
                "description": "Pivot surface. Keys are EntityType values.",
                "propertyNames": {"enum": [e.value for e in EntityType]},
                "additionalProperties": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                },
            },
            "title": {"type": "string", "maxLength": 512},
            "description": {"type": "string"},
            "rule_id": {
                "type": ["string", "null"],
                "description": "Detection rule that fired, if any. Sigma/YARA/builtin id.",
            },
            "tlp": {
                "type": "string",
                "enum": ["white", "green", "amber", "amber+strict"],
                "default": "amber",
                "description": "Sensitivity label; enforces sharing boundaries.",
            },
            "raw": {
                "type": "object",
                "description": "Original connector payload, unmodified.",
            },
            "tags": {"type": "array", "items": {"type": "string"}},
            "schema_version": {"type": "string", "default": SCHEMA_VERSION},
        },
        "allOf": [
            {
                "if": {"properties": {"type": {"const": "network_conn"}}},
                "then": {
                    "description": "Network events should carry at least one endpoint entity.",
                    "anyOf": [
                        {"properties": {"entities": {"required": ["ip"]}}},
                        {"properties": {"entities": {"required": ["domain"]}}},
                    ],
                },
            }
        ],
        "$comment": f"generated from tiox.schemas.event SCHEMA_VERSION={SCHEMA_VERSION}",
    }


def emit(out_dir: Path | None = None) -> Path:
    out_dir = out_dir or Path(__file__).resolve().parent
    path = out_dir / SCHEMA_FILENAME
    path.write_text(json.dumps(build_json_schema(), indent=2) + "\n")
    return path


if __name__ == "__main__":
    print(f"wrote {emit()}")
