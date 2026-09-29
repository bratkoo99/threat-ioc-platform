"""
MITRE ATT&CK technique tagging.

A detection without a technique id cannot be aggregated, correlated, or reported
as part of a kill chain. Tagging at ingest means a case can later be written as
a sequence (T1566 -> T1105 -> T1486) instead of three unrelated alerts.

Design notes:

  * The catalog is a small, curated subset, not a vendored copy of ATT&CK. Only
    techniques this platform can actually detect are listed. Shipping the full
    200+ technique matrix would imply coverage that does not exist, and an
    analyst who sees a technique they cannot hunt for stops trusting the labels.
    Tactic names and ids were verified against attack.mitre.org.
  * `rule_id -> techniques` is the mapping, not the event type. Rules are what a
    detection engine emits, so this is the join point. Adding a rule means adding
    a line here, and an unmapped rule is a visible gap rather than a silent
    mislabel.
  * Sub-technique support is included (T1485.001) because "data destruction" and
    "lifecycle-triggered deletion" are genuinely different things to hunt for.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# T1486, T1485, T1105 and the ids below were checked against attack.mitre.org.
TECHNIQUES: dict[str, dict[str, str]] = {
    # --- Impact: the ransomware story this platform is built around ---
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "impact"},
    "T1485": {"name": "Data Destruction", "tactic": "impact"},
    "T1485.001": {"name": "Lifecycle-Triggered Deletion", "tactic": "impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "impact"},
    # --- Command and Control ---
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command-and-control"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "command-and-control"},
    "T1573": {"name": "Encrypted Channel", "tactic": "command-and-control"},
    "T1090": {"name": "Proxy", "tactic": "command-and-control"},
    "T1219": {"name": "Remote Access Software", "tactic": "command-and-control"},
    # --- Credential access ---
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential-access"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "credential-access"},
    "T1056": {"name": "Input Capture", "tactic": "credential-access"},
    # --- Execution ---
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "execution"},
    "T1204": {"name": "User Execution", "tactic": "execution"},
    # --- Persistence ---
    "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "persistence"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "persistence"},
    # --- Exfiltration ---
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "exfiltration"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration"},
    # --- Collection / discovery ---
    "T1005": {"name": "Data from Local System", "tactic": "collection"},
    "T1082": {"name": "System Information Discovery", "tactic": "discovery"},
    "T1016": {"name": "System Network Configuration Discovery", "tactic": "discovery"},
    # --- Defense evasion ---
    "T1562": {"name": "Impair Defenses", "tactic": "defense-evasion"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense-evasion"},
    "T1070": {"name": "Indicator Removal", "tactic": "defense-evasion"},
    # --- Resource development ---
    "T1583": {"name": "Acquire Infrastructure", "tactic": "resource-development"},
    "T1587": {"name": "Develop Capabilities", "tactic": "resource-development"},
}

# Detection rules currently emitted by this platform, mapped to techniques.
#
# The mapping is deliberately conservative. A filename substring like
# "anydesk" is a lead worth triaging, not a confirmed T1219 execution, so it is
# tagged as the technique it *relates to* and the event's severity carries how
# much the analyst should trust it. Over-claiming here is how ATT&CK labels
# become noise.
RULE_TECHNIQUES: dict[str, tuple[str, ...]] = {
    # Confirmed malicious artifacts.
    "builtin.hash_exact": ("T1486",),
    # A ransom note on disk means encryption already happened or is happening.
    "builtin.filename_pattern": ("T1486",),
    # Dual-use tooling found on a host.
    "mimikatz": ("T1003",),
    "procdump": ("T1003",),
    "rclone": ("T1567",),
    "ngrok": ("T1090",),
    "ligolo": ("T1090",),
    "chisel": ("T1090",),
    "anydesk": ("T1219",),
    # Stolen or generated artefacts worth tracking as a campaign marker.
    "stealbit": ("T1567",),
    # C2 infrastructure contact.
    "c2_contact": ("T1071",),
    # Operational hygiene events. Not adversary behaviour, so no technique:
    # tagging an agent heartbeat as ATT&CK would pollute every report.
    "agent.register": (),
    "agent.heartbeat": (),
    "agent.scan_complete": (),
    "system.operator": (),
}

# Prefixes whose rules are operational, not adversary behaviour. Matched on the
# leading segment so a per-record rule id like "system.operator.INC-0001" is
# recognised as the same class rather than reported as an unmapped rule.
NON_TECHNIQUE_PREFIXES = ("agent.", "system.", "legacy.")

# Families of malware map to techniques even when the specific rule varies.
FAMILY_TECHNIQUES: dict[str, tuple[str, ...]] = {
    "ransomnote": ("T1486",),
    "lockbit": ("T1486",),
    "blackcat": ("T1486",),
    "alphv": ("T1486",),
    "royal": ("T1486",),
    "conti": ("T1486",),
    "bianlian": ("T1486",),
    "cl0p": ("T1486",),
    "play": ("T1486",),
    "akira": ("T1486",),
    "interlock": ("T1486",),
    "snatch": ("T1486",),
    "avoslocker": ("T1486",),
    "medusa": ("T1486",),
    "blackbasta": ("T1486",),
    "cobaltstrike": ("T1071",),
    "mimikatz": ("T1003",),
    "stealbit": ("T1567",),
    "generic": ("T1486",),
}

_TID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    url: str

    def as_dict(self) -> dict[str, str]:
        return {"id": self.id, "name": self.name, "tactic": self.tactic, "url": self.url}


def is_valid(technique_id: str) -> bool:
    return bool(_TID_RE.match(technique_id or ""))


def get(technique_id: str) -> Technique | None:
    meta = TECHNIQUES.get(technique_id)
    if not meta:
        return None
    return Technique(
        id=technique_id,
        name=meta["name"],
        tactic=meta["tactic"],
        url=f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
    )


def tactics() -> list[str]:
    return sorted({t["tactic"] for t in TECHNIQUES.values()})


def techniques_for_rule(rule_id: str) -> list[str]:
    """Techniques for a detection rule id, accepting a bare or namespaced form."""
    if not rule_id:
        return []
    base = rule_id.split(".")[-1]
    for key in (rule_id, base):
        if key in RULE_TECHNIQUES:
            return list(RULE_TECHNIQUES[key])
    return []


def techniques_for_family(family: str) -> list[str]:
    if not family:
        return []
    return list(FAMILY_TECHNIQUES.get(family.strip().lower(), []))


def techniques_for_event(rule_id: str, family: str = "") -> list[str]:
    """
    Resolve techniques for an event, preferring the rule and falling back to the
    malware family. Deduped and ordered so output is stable.
    """
    found = list(techniques_for_rule(rule_id))
    if not found:
        found = techniques_for_family(family)
    return sorted(dict.fromkeys(found))


def unmapped_rules(known_rules: list[str]) -> list[str]:
    """
    Detection rules with no technique mapping.

    A coverage report, not a bug list. A new rule that nobody has classified yet
    is exactly the thing that silently disappears from technique-level reporting.
    """
    out = []
    for rule in known_rules:
        if techniques_for_rule(rule) or techniques_for_family(rule):
            continue
        if rule in RULE_TECHNIQUES:
            # Mapped to nothing on purpose: an agent heartbeat is not adversary
            # behaviour. A decision, not a coverage gap.
            continue
        if any(rule.startswith(p) for p in NON_TECHNIQUE_PREFIXES):
            continue
        out.append(rule)
    return sorted(out)


def catalog() -> list[dict[str, str]]:
    return [
        t.as_dict()
        for t in sorted(
            filter(None, (get(tid) for tid in TECHNIQUES)),
            key=lambda t: t.id,
        )
    ]
