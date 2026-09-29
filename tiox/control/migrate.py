"""
One-shot migration from the pre-Phase-0 JSON stores into the control plane + lake.

    python3 -m tiox.control.migrate                     # migrate if data exists
    python3 -m tiox.control.migrate --dry-run           # report, change nothing
    python3 -m tiox.control.migrate --db path/to.db    # custom target

Idempotent: incidents carry their legacy id in the event fingerprint and endpoints
upsert by hostname, so re-running will not duplicate history. The JSON files are
left in place; delete them yourself once you have verified the migration.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tiox.store.control import ControlPlane  # noqa: E402
from tiox.store.pipeline import migrate_legacy  # noqa: E402

PLATFORM_DIR = Path(__file__).resolve().parents[2]


def load_json(path: Path, default):
    if not path.exists():
        return default
    try:
        with open(path) as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  [!] cannot read {path.name}: {exc}", file=sys.stderr)
        return default


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--db", default=str(PLATFORM_DIR / "tiox.db"),
                    help="target SQLite file (default: ./tiox.db)")
    ap.add_argument("--incidents", default=str(PLATFORM_DIR / "incidents.json"))
    ap.add_argument("--inventory", default=str(PLATFORM_DIR / "inventory.json"))
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    incidents = load_json(Path(args.incidents), {}).get("incidents", [])
    inventory = load_json(Path(args.inventory), {})
    endpoints = inventory.get("endpoints", [])

    print("Phase 0 migration")
    print(f"  incidents.json: {len(incidents)} incident(s)")
    print(f"  inventory.json: {len(endpoints)} endpoint(s)")
    print(f"  target:         {args.db}")

    if not incidents and not endpoints:
        print("\nNothing to migrate (no legacy files found).")
        print("The control plane starts empty and is ready for ingest.")
        return 0

    if args.dry_run:
        print("\n--dry-run: no changes written.")
        print("Re-run without --dry-run to perform the migration.")
        return 0

    store = ControlPlane(args.db)
    try:
        print(f"  existing schema version in target: {store.schema_version}")
        summary = migrate_legacy(store, incidents, inventory)
        counts = store.incident_counts()
        stats = store.event_stats()
        print("\nResult:")
        print(f"  endpoints migrated: {summary['endpoints']}")
        print(f"  incidents migrated: {summary['incidents']}")
        print(f"  events written:     {summary['events']} "
              f"({summary['duplicates']} duplicate(s) skipped)")
        if summary["errors"]:
            print(f"  errors:             {len(summary['errors'])}")
            for e in summary["errors"][:10]:
                print(f"    - {e}")
        print(f"\nControl plane now holds: {counts['total']} incident(s), "
              f"{stats['total']} event(s) across {stats['hosts']} host(s)")
        print("\nLegacy JSON files were left untouched. Verify, then remove them.")
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
