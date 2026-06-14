"""Tests for Sigma rule generation."""
import pytest
import yaml

from adversary_intel.detection.sigma import (
    jarm_rule,
    ja3_rule,
    c2_ip_rule,
    cert_fingerprint_rule,
    cobalt_strike_jarm_rule,
    sliver_jarm_rule,
)


def test_jarm_rule_valid_yaml():
    rule = jarm_rule(
        jarm="07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2",
        title="Test JARM Rule",
    )
    parsed = yaml.safe_load(rule)
    assert parsed["title"] == "Test JARM Rule"
    assert "detection" in parsed
    assert "level" in parsed


def test_jarm_rule_contains_fingerprint():
    jarm = "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"
    rule = jarm_rule(jarm=jarm, title="Test")
    assert jarm in rule


def test_c2_ip_rule_valid():
    rule = c2_ip_rule(
        ips=["1.2.3.4", "5.6.7.8"],
        title="Test IP Rule",
        severity="critical",
    )
    parsed = yaml.safe_load(rule)
    assert parsed["level"] == "critical"
    detection = parsed["detection"]
    assert "1.2.3.4" in str(detection)


def test_ja3_rule_contains_hashes():
    hashes = ["51c64c77e60f3980eea90869b68c58a8", "72a589da586844d7f0818ce684948eea"]
    rule = ja3_rule(ja3_hashes=hashes, title="Test JA3")
    parsed = yaml.safe_load(rule)
    selection = parsed["detection"]["selection"]
    assert all(h in str(selection) for h in hashes)


def test_cert_rule_valid():
    rule = cert_fingerprint_rule(
        sha1_fingerprints=["AABBCC112233445566778899AABBCC1122334455"],
        title="Test Cert Rule",
    )
    parsed = yaml.safe_load(rule)
    assert "logsource" in parsed


def test_cobalt_strike_builtin():
    rule = cobalt_strike_jarm_rule()
    parsed = yaml.safe_load(rule)
    assert "cobalt" in parsed["title"].lower() or "Cobalt" in parsed["title"]
    assert parsed["level"] == "critical"


def test_sliver_builtin():
    rule = sliver_jarm_rule()
    parsed = yaml.safe_load(rule)
    assert "Sliver" in parsed["title"] or "sliver" in parsed["title"].lower()
