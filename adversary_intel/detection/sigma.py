"""
Sigma rule generation from discovered infrastructure fingerprints.

Translates JARM fingerprints, JA3 hashes, and C2 behavioral indicators
into Sigma rules that can be imported into any SIEM supporting the Sigma format.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

from adversary_intel.models import JARMResult, TLSCertInfo

_SIGMA_STATUS = "experimental"


def jarm_rule(
    jarm: str,
    title: str,
    description: str = "",
    severity: str = "high",
    tags: list[str] | None = None,
    false_positives: list[str] | None = None,
) -> str:
    """Generate a Sigma rule to detect the given JARM fingerprint in network logs."""
    rule = {
        "title": title,
        "id": _rule_id(jarm),
        "status": _SIGMA_STATUS,
        "description": description or f"Detects C2 infrastructure with JARM fingerprint {jarm}",
        "references": ["https://github.com/salesforce/jarm"],
        "author": "adversary-intel",
        "date": datetime.utcnow().strftime("%Y/%m/%d"),
        "tags": (tags or []) + ["attack.command-and-control", "attack.t1071.001"],
        "logsource": {
            "category": "network_connection",
        },
        "detection": {
            "selection": {
                "jarm_hash": jarm,
            },
            "filter_legit": {
                "dst_ip|cidr": [
                    "1.1.1.0/24",
                    "8.8.8.0/24",
                    "208.67.222.0/24",
                ],
            },
            "condition": "selection and not filter_legit",
        },
        "falsepositives": false_positives or ["Legitimate services using the same TLS stack"],
        "level": severity,
    }
    return yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True)


def ja3_rule(
    ja3_hashes: list[str],
    title: str,
    description: str = "",
    severity: str = "high",
    tags: list[str] | None = None,
) -> str:
    """Generate a Sigma rule to detect specific JA3 fingerprints in proxy/firewall logs."""
    rule = {
        "title": title,
        "id": _rule_id("|".join(ja3_hashes)),
        "status": _SIGMA_STATUS,
        "description": description or f"Detects malware C2 by JA3 TLS fingerprint",
        "author": "adversary-intel",
        "date": datetime.utcnow().strftime("%Y/%m/%d"),
        "tags": (tags or []) + ["attack.command-and-control", "attack.t1071.001"],
        "logsource": {
            "category": "network_connection",
        },
        "detection": {
            "selection": {
                "ja3_hash": ja3_hashes,
            },
            "filter_legit": {
                "dst_ip|cidr": ["1.1.1.0/24", "8.8.8.0/24"],
            },
            "condition": "selection and not filter_legit",
        },
        "falsepositives": ["Red team operations", "Security research tools"],
        "level": severity,
    }
    return yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True)


def c2_ip_rule(
    ips: list[str],
    title: str,
    description: str = "",
    severity: str = "critical",
    malware_family: str = "",
    tags: list[str] | None = None,
) -> str:
    """Generate a Sigma rule for a list of discovered C2 IPs."""
    mitre_tags = ["attack.command-and-control", "attack.t1071.001"]
    if malware_family:
        mitre_tags.append(f"detection.emerging_threats.{malware_family.lower()}")

    rule = {
        "title": title,
        "id": _rule_id("|".join(sorted(ips))),
        "status": _SIGMA_STATUS,
        "description": description or f"Detects connections to {malware_family or 'C2'} infrastructure",
        "author": "adversary-intel",
        "date": datetime.utcnow().strftime("%Y/%m/%d"),
        "tags": (tags or []) + mitre_tags,
        "logsource": {
            "category": "network_connection",
        },
        "detection": {
            "selection": {
                "dst_ip": ips,
            },
            "condition": "selection",
        },
        "falsepositives": ["None expected — verified C2 infrastructure"],
        "level": severity,
    }
    return yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True)


def cert_fingerprint_rule(
    sha1_fingerprints: list[str],
    title: str,
    description: str = "",
    severity: str = "high",
) -> str:
    """Generate a Sigma rule to detect traffic using known malicious TLS certificates."""
    rule = {
        "title": title,
        "id": _rule_id("|".join(sorted(sha1_fingerprints))),
        "status": _SIGMA_STATUS,
        "description": description or "Detects TLS connections using certificates associated with C2 infrastructure",
        "author": "adversary-intel",
        "date": datetime.utcnow().strftime("%Y/%m/%d"),
        "tags": ["attack.command-and-control", "attack.t1071.001", "attack.t1587.003"],
        "logsource": {
            "product": "zeek",
            "service": "ssl",
        },
        "detection": {
            "selection": {
                "certificate.fingerprint|contains": sha1_fingerprints,
            },
            "condition": "selection",
        },
        "falsepositives": ["None expected"],
        "level": severity,
    }
    return yaml.dump(rule, default_flow_style=False, sort_keys=False, allow_unicode=True)


def save_rules(rules: list[str], output_dir: Path, prefix: str = "rule") -> list[Path]:
    """Write sigma rules to individual YAML files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for i, rule in enumerate(rules):
        path = output_dir / f"{prefix}_{i:03d}.yml"
        path.write_text(rule)
        paths.append(path)
    return paths


def cobalt_strike_jarm_rule() -> str:
    return jarm_rule(
        jarm="07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
        title="Cobalt Strike C2 JARM Fingerprint",
        description="Detects default Cobalt Strike C2 server by JARM TLS fingerprint",
        severity="critical",
        tags=["attack.t1059", "attack.t1071"],
        false_positives=["Red team operations using default Cobalt Strike configuration"],
    )


def sliver_jarm_rule() -> str:
    return jarm_rule(
        jarm="2ad2ad0002ad2ad22c2ad2ad2ad2adce53373cc5b6fc3afc0d849cfe7b6b2",
        title="Sliver C2 JARM Fingerprint",
        description="Detects Sliver C2 framework by JARM TLS fingerprint",
        severity="critical",
        tags=["attack.t1059", "attack.t1071"],
        false_positives=["Red team operations using Sliver"],
    )


# ── Helpers ──────────────────────────────────────────────────────────────────

def _rule_id(seed: str) -> str:
    """Deterministic UUID-style ID from a seed string."""
    import hashlib
    h = hashlib.md5(seed.encode()).hexdigest()  # noqa: S324
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
