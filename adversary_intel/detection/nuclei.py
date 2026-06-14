"""
Nuclei template generation for automated C2 detection.

Generates YAML templates compatible with ProjectDiscovery's Nuclei scanner.
These templates encode C2 fingerprints (JARM, cert serials, HTTP patterns)
and can scan IP lists to classify infrastructure at scale.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

import yaml


def cobalt_strike_template(
    jarm: str = "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
    cert_serial: str | None = None,
) -> str:
    """
    Multi-signal Cobalt Strike detection template.
    Layer 1: JARM fingerprint match
    Layer 2: HTTP 404 empty-body validation (reduces false positives)
    """
    template: dict = {
        "id": "cobalt-strike-c2-detection",
        "info": {
            "name": "Cobalt Strike C2 Detection",
            "author": "adversary-intel",
            "severity": "critical",
            "description": "Detects Cobalt Strike C2 via JARM fingerprint + HTTP response pattern",
            "tags": ["cobalt-strike", "c2", "jarm", "threat-hunting"],
            "metadata": {
                "shodan-query": f'ssl.jarm:"{jarm}"',
            },
        },
        "tcp": [{
            "host": ["{{Hostname}}"],
            "matchers": [{
                "type": "word",
                "words": [jarm],
                "condition": "and",
            }],
        }],
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}"],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [404]},
                {"type": "word", "words": [""], "part": "body"},
                {"type": "dsl", "dsl": ['len(body) == 0']},
            ],
        }],
    }
    if cert_serial:
        template["info"]["metadata"]["cert-serial"] = cert_serial
    return yaml.dump(template, default_flow_style=False, sort_keys=False, allow_unicode=True)


def sliver_template(
    jarm: str = "2ad2ad0002ad2ad22c2ad2ad2ad2adce53373cc5b6fc3afc0d849cfe7b6b20",
) -> str:
    template: dict = {
        "id": "sliver-c2-detection",
        "info": {
            "name": "Sliver C2 Detection",
            "author": "adversary-intel",
            "severity": "critical",
            "description": "Detects Sliver C2 framework via JARM fingerprint",
            "tags": ["sliver", "c2", "jarm", "threat-hunting"],
            "metadata": {
                "shodan-query": f'ssl.jarm:"{jarm}"',
            },
        },
        "tcp": [{
            "host": ["{{Hostname}}"],
            "matchers": [{
                "type": "word",
                "words": [jarm],
            }],
        }],
    }
    return yaml.dump(template, default_flow_style=False, sort_keys=False, allow_unicode=True)


def custom_jarm_template(
    template_id: str,
    name: str,
    jarm: str,
    severity: str = "high",
    http_matchers: list[dict] | None = None,
    tags: list[str] | None = None,
) -> str:
    """Generate a custom JARM-based detection template for any C2 framework."""
    template: dict = {
        "id": template_id,
        "info": {
            "name": name,
            "author": "adversary-intel",
            "severity": severity,
            "description": f"Detects {name} via JARM fingerprint",
            "tags": (tags or []) + ["jarm", "c2", "threat-hunting"],
            "metadata": {
                "created": datetime.utcnow().strftime("%Y-%m-%d"),
                "jarm": jarm,
                "shodan-query": f'ssl.jarm:"{jarm}"',
            },
        },
        "tcp": [{
            "host": ["{{Hostname}}"],
            "matchers": [{"type": "word", "words": [jarm]}],
        }],
    }
    if http_matchers:
        template["http"] = [{
            "method": "GET",
            "path": ["{{BaseURL}}"],
            "matchers-condition": "and",
            "matchers": http_matchers,
        }]
    return yaml.dump(template, default_flow_style=False, sort_keys=False, allow_unicode=True)


def favicon_template(
    mmh3_hash: int,
    name: str,
    severity: str = "medium",
) -> str:
    """Template to detect phishing or C2 panels by favicon hash."""
    template: dict = {
        "id": f"favicon-{abs(mmh3_hash)}",
        "info": {
            "name": f"Favicon Detection: {name}",
            "author": "adversary-intel",
            "severity": severity,
            "tags": ["favicon", "phishing", "c2"],
            "metadata": {
                "shodan-query": f"http.favicon.hash:{mmh3_hash}",
                "fofa-query": f'icon_hash="{mmh3_hash}"',
            },
        },
        "http": [{
            "method": "GET",
            "path": ["{{BaseURL}}/favicon.ico"],
            "matchers": [{
                "type": "dsl",
                "dsl": [f"mmh3(base64(body)) == {mmh3_hash}"],
            }],
        }],
    }
    return yaml.dump(template, default_flow_style=False, sort_keys=False, allow_unicode=True)


def save_template(template_yaml: str, output_dir: Path, filename: str) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    if not filename.endswith(".yaml") and not filename.endswith(".yml"):
        filename += ".yaml"
    path = output_dir / filename
    path.write_text(template_yaml)
    return path


def get_builtin_templates() -> dict[str, str]:
    """Return all built-in detection templates keyed by C2 framework name."""
    return {
        "cobalt_strike": cobalt_strike_template(),
        "sliver": sliver_template(),
    }
