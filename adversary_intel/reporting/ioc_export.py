"""
IOC and hunt-session export in multiple formats.

Supported output formats:
  - JSON  (full enriched report)
  - CSV   (flat IOC list for SIEM import)
  - MISP  (MISP-compatible event JSON)
  - STIX  (STIX 2.1 Bundle — basic)
  - TXT   (newline-delimited indicator list)
"""
from __future__ import annotations

import csv
import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class IOC:
    value: str
    ioc_type: str          # ip, domain, url, hash, jarm, cert_serial
    confidence: str = "medium"   # low / medium / high
    malicious: bool = False
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    source: str = ""
    context: str = ""


@dataclass
class HuntReport:
    hunt_id: str
    seed: str
    seed_type: str
    started_at: str
    analyst: str = "adversary-intel"
    tlp: str = "TLP:AMBER"
    summary: str = ""
    cluster_name: str = ""
    iocs: list[IOC] = field(default_factory=list)
    pivot_graph: dict[str, Any] = field(default_factory=dict)
    sigma_rules: list[str] = field(default_factory=list)
    nuclei_templates: list[str] = field(default_factory=list)
    raw_findings: dict[str, Any] = field(default_factory=dict)

    def add_ip(self, ip: str, malicious: bool = False, confidence: str = "medium",
               tags: list[str] | None = None, source: str = "", context: str = "") -> None:
        self.iocs.append(IOC(
            value=ip, ioc_type="ip", confidence=confidence,
            malicious=malicious, tags=tags or [], source=source, context=context,
        ))

    def add_domain(self, domain: str, malicious: bool = False, confidence: str = "medium",
                   tags: list[str] | None = None, source: str = "", context: str = "") -> None:
        self.iocs.append(IOC(
            value=domain, ioc_type="domain", confidence=confidence,
            malicious=malicious, tags=tags or [], source=source, context=context,
        ))

    def add_jarm(self, jarm: str, framework: str = "", confidence: str = "high",
                 source: str = "") -> None:
        self.iocs.append(IOC(
            value=jarm, ioc_type="jarm", confidence=confidence,
            malicious=bool(framework), tags=[framework] if framework else [],
            source=source, context=f"C2 framework: {framework}" if framework else "",
        ))

    def add_cert_serial(self, serial: str, cn: str = "", confidence: str = "medium",
                        source: str = "") -> None:
        self.iocs.append(IOC(
            value=serial, ioc_type="cert_serial", confidence=confidence,
            malicious=True, tags=["tls", "self-signed"],
            source=source, context=f"CN={cn}" if cn else "",
        ))


class IOCExporter:
    """Export a HuntReport to multiple formats."""

    def __init__(self, report: HuntReport) -> None:
        self.report = report

    def to_json(self, indent: int = 2) -> str:
        d = asdict(self.report)
        return json.dumps(d, indent=indent, ensure_ascii=False)

    def to_csv(self) -> str:
        import io
        buf = io.StringIO()
        writer = csv.DictWriter(
            buf,
            fieldnames=["value", "ioc_type", "confidence", "malicious",
                        "tags", "first_seen", "last_seen", "source", "context"],
        )
        writer.writeheader()
        for ioc in self.report.iocs:
            row = asdict(ioc)
            row["tags"] = "|".join(ioc.tags)
            row["malicious"] = str(ioc.malicious)
            writer.writerow(row)
        return buf.getvalue()

    def to_txt(self, malicious_only: bool = True) -> str:
        """Newline-delimited indicator list — paste directly into a firewall or EDR."""
        lines = []
        for ioc in self.report.iocs:
            if malicious_only and not ioc.malicious:
                continue
            lines.append(ioc.value)
        return "\n".join(sorted(set(lines)))

    def to_misp_event(self) -> dict[str, Any]:
        """MISP-compatible event JSON."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        attrs = []
        type_map = {
            "ip": "ip-dst",
            "domain": "domain",
            "url": "url",
            "hash": "sha256",
            "jarm": "other",
            "cert_serial": "x509-fingerprint-sha1",
        }
        for ioc in self.report.iocs:
            attrs.append({
                "type": type_map.get(ioc.ioc_type, "other"),
                "value": ioc.value,
                "comment": ioc.context,
                "Tag": [{"name": t} for t in ioc.tags],
                "to_ids": ioc.malicious,
                "distribution": 1,
            })
        return {
            "Event": {
                "uuid": str(uuid.uuid4()),
                "info": f"[{self.report.tlp}] {self.report.cluster_name} — Hunt {self.report.hunt_id}",
                "date": now,
                "threat_level_id": "2",
                "analysis": "2",
                "distribution": "1",
                "Attribute": attrs,
            }
        }

    def to_stix_bundle(self) -> dict[str, Any]:
        """STIX 2.1 Bundle with Indicator SDOs."""
        now = datetime.now(timezone.utc).isoformat()
        objects = []
        identity_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "name": "adversary-intel",
            "identity_class": "system",
            "created": now,
            "modified": now,
        })
        stix_type_map = {
            "ip": "network-traffic",
            "domain": "domain-name",
            "url": "url",
            "jarm": "x-custom-jarm",
        }
        for ioc in self.report.iocs:
            if not ioc.malicious:
                continue
            ind_id = f"indicator--{uuid.uuid4()}"
            if ioc.ioc_type == "ip":
                pattern = f"[ipv4-addr:value = '{ioc.value}']"
            elif ioc.ioc_type == "domain":
                pattern = f"[domain-name:value = '{ioc.value}']"
            elif ioc.ioc_type == "url":
                pattern = f"[url:value = '{ioc.value}']"
            else:
                pattern = f"[x-custom:value = '{ioc.value}']"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "name": ioc.value,
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": ioc.first_seen or now,
                "created": now,
                "modified": now,
                "created_by_ref": identity_id,
                "labels": ioc.tags,
                "description": ioc.context,
            })
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid4()}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def save_all(self, output_dir: Path) -> dict[str, Path]:
        """Write all formats to output_dir. Returns {format: path} map."""
        output_dir.mkdir(parents=True, exist_ok=True)
        paths: dict[str, Path] = {}

        p = output_dir / "report.json"
        p.write_text(self.to_json())
        paths["json"] = p

        p = output_dir / "iocs.csv"
        p.write_text(self.to_csv())
        paths["csv"] = p

        p = output_dir / "iocs_malicious.txt"
        p.write_text(self.to_txt(malicious_only=True))
        paths["txt"] = p

        p = output_dir / "misp_event.json"
        p.write_text(json.dumps(self.to_misp_event(), indent=2))
        paths["misp"] = p

        p = output_dir / "stix_bundle.json"
        p.write_text(json.dumps(self.to_stix_bundle(), indent=2))
        paths["stix"] = p

        return paths
