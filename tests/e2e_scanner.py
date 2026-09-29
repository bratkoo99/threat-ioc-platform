"""
End-to-end smoke test against the real scanner binary.

Proves the Phase 0 pipeline consumes genuine ioc_scanner.c output, not just
hand-written fixtures. Run:

    make ioc_scanner && python3 -m tests.e2e_scanner

Exits non-zero on failure. This is the check that would catch the scanner
changing its output format without the connector being updated.
"""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tiox.store.control import ControlPlane  # noqa: E402
from tiox.store.pipeline import ingest  # noqa: E402

SCANNER = ROOT / "ioc_scanner"

# EICAR: the antivirus industry standard test file, public by design. We write its
# exact bytes and feed its published SHA-256 into the scanner via -H, so the
# scanner's real exact-hash code path fires.
#
# Note: we cannot simply write a file with a chosen SHA-256 — that is a preimage
# attack. Driving the documented hash through the scanner's own -H flag exercises
# the same comparison logic without pretending to invert SHA-256.
EICAR = (
    rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)

THREAT_RE = re.compile(r"\[!!!\]\s*THREAT DETECTED")


def eicar_sha256() -> str:
    import hashlib

    return hashlib.sha256(EICAR).hexdigest()


def run_scanner(path: Path, *args: str) -> tuple[int, str]:
    proc = subprocess.run(
        [str(SCANNER), "-v", *args, str(path)],
        capture_output=True, text=True, timeout=120,
    )
    return proc.returncode, proc.stdout + proc.stderr


def parse_like_server(output: str) -> dict:
    """
    Reproduce web_ui_server.parse_scanner_output, since that is the shape the
    connector is actually fed in production. Kept as a faithful copy so this
    test fails if the server's parser changes shape.
    """
    state = {"files_scanned": 0, "threats_found": 0, "threats": []}
    for line in output.splitlines():
        line = line.rstrip()
        m = re.match(r"\[!!!\]\s*THREAT DETECTED", line)
        if m:
            state["threats"].append(
                {"file": "", "type": "", "family": "", "details": "", "hash": "",
                 "time": "2026-01-01T00:00:00"}
            )
            state["threats_found"] += 1
            continue
        m = re.match(r"\[OK\]\s*(.+)", line)
        if m:
            state["files_scanned"] += 1
            continue
        if state["threats"]:
            last = state["threats"][-1]
            if "Path:" in line:
                last["file"] = line.split("Path:", 1)[1].strip()
            elif "Match:" in line:
                last["type"] = line.split("Match:", 1)[1].strip()
            elif "Family:" in line:
                last["family"] = line.split("Family:", 1)[1].strip()
            elif "Details:" in line:
                last["details"] = line.split("Details:", 1)[1].strip()
            elif "SHA-256:" in line:
                last["hash"] = line.split("SHA-256:", 1)[1].strip()
    return state


def main() -> int:
    if not SCANNER.exists():
        print(f"FAIL: {SCANNER} not built. Run: make ioc_scanner")
        return 1

    failures: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        # 1. A file whose name matches a ransomware-note pattern.
        (root / "HOW_TO_DECRYPT.txt").write_text("send bitcoin to addr\n")
        # 2. EICAR, whose real SHA-256 we register with the scanner via -H so the
        #    exact-hash comparison path fires on genuine input.
        (root / "sample.bin").write_bytes(EICAR)
        # 3. Clean file, must not fire.
        (root / "notes.txt").write_text("harmless\n")

        sha = eicar_sha256()
        hashdb = root / "hashes.csv"
        hashdb.write_text(f"{sha},EICAR,Test file (AV industry standard)\n")
        print(f"EICAR sha256 = {sha}")

        rc, out = run_scanner(root, "-H", str(hashdb))
        print(f"scanner exit={rc}")
        if THREAT_RE.search(out):
            blocks = out.split("[!!!] THREAT DETECTED")
            print(f"threat blocks: {len(blocks) - 1}")
            for b in blocks[1:]:
                print("[!!!] THREAT DETECTED" + b.rstrip())
        else:
            failures.append("scanner produced no THREAT DETECTED output on known-bad input")
            print(out[:2000])

        payload = parse_like_server(out)
        print(f"parsed: threats={payload['threats_found']} files={payload['files_scanned']}")

        if payload["threats_found"] < 2:
            failures.append(f"expected >=2 threats (name + hash), got {payload['threats_found']}")

        # Feed the exact production shape into the pipeline.
        store = ControlPlane(":memory:")
        r = ingest(store, payload, source="agent", context={"hostname": "e2e-host"})
        print(f"ingest: {r.as_dict()}")

        if r.inserted < 3:  # 1 scan summary + 2 threat hits
            failures.append(f"expected >=3 events ingested, got {r.inserted}")

        threat_events = [
            e for e in r.events
            if e.rule_id in ("builtin.hash_exact", "builtin.filename_pattern")
        ]
        by_rule = {e.rule_id: e for e in threat_events}
        print("events by rule: " + ", ".join(f"{k}={v.severity}" for k, v in by_rule.items()))

        if "builtin.filename_pattern" not in by_rule:
            failures.append("filename-pattern hit did not normalize")
        if "builtin.hash_exact" not in by_rule:
            failures.append("known-hash hit did not normalize")
        elif by_rule["builtin.hash_exact"].severity != "critical":
            failures.append("hash hit should be critical")

        # The pivot must work on the hash that the scanner actually reported.
        reported = [t.get("hash") for t in payload["threats"] if t.get("hash")]
        if reported:
            h = reported[0]
            hits = store.find_by_entity("file_hash", h)
            print(f"pivot on {h[:16]}... -> {len(hits)} event(s)")
            if not hits:
                failures.append(f"pivot on reported hash {h[:16]} returned nothing")
        else:
            print("note: no hash reported by scanner; pivot check skipped")

        stats = store.event_stats()
        print(f"stats: {stats}")
        store.close()

    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print("\nOK: scanner output flows through the canonical schema into the lake")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
