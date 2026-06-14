"""Tests for favicon hash module."""
import pytest
from unittest.mock import patch, MagicMock

from adversary_intel.core.favicon import hash_bytes, shodan_query, fofa_query, classify, KNOWN_HASHES


def test_hash_bytes_deterministic():
    data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
    h1 = hash_bytes(data)
    h2 = hash_bytes(data)
    assert h1 == h2


def test_hash_bytes_different_data():
    h1 = hash_bytes(b"data1" * 10)
    h2 = hash_bytes(b"data2" * 10)
    assert h1 != h2


def test_shodan_query_format():
    q = shodan_query(-1627975581)
    assert "http.favicon.hash:" in q
    assert "-1627975581" in q


def test_fofa_query_format():
    q = fofa_query(-1627975581)
    assert "icon_hash=" in q
    assert "-1627975581" in q


def test_classify_known_cs():
    cs_hash = -1627975581
    result = classify(cs_hash)
    assert result is not None
    assert "Cobalt Strike" in result


def test_classify_unknown():
    result = classify(99999999)
    assert result is None


def test_known_hashes_not_empty():
    assert len(KNOWN_HASHES) > 0
    for h, name in KNOWN_HASHES.items():
        assert isinstance(h, int)
        assert isinstance(name, str)
