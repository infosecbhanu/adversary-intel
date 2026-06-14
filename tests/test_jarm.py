"""Tests for JARM fingerprinting module."""
import pytest
from unittest.mock import patch, MagicMock

from adversary_intel.core.jarm import classify, is_c2, KNOWN_JARMS, _compute_jarm


def test_classify_known_cs():
    cs_jarm = "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"
    result = classify(cs_jarm)
    assert result is not None
    assert "Cobalt Strike" in result


def test_classify_unknown():
    result = classify("0" * 62)
    assert result is None or "not supported" in (result or "")


def test_is_c2_known():
    cs_jarm = "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2"
    assert is_c2(cs_jarm) is True


def test_is_c2_unknown():
    assert is_c2("1234567890abcdef" * 3 + "1234567890ab") is False


def test_compute_jarm_deterministic():
    raw = ["||a|b", "||c|d", "||e|f"] * 3 + ["||g|h"]
    h1 = _compute_jarm(raw)
    h2 = _compute_jarm(raw)
    assert h1 == h2
    assert len(h1) == 62


def test_known_jarms_format():
    for jarm, name in KNOWN_JARMS.items():
        assert len(jarm) == 62, f"JARM {jarm} should be 62 chars"
        assert isinstance(name, str)
