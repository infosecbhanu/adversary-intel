"""
Favicon hash computation for infrastructure fingerprinting.

Shodan indexes favicon hashes using MurmurHash3 (mmh3) on the
base64-encoded favicon bytes. This module computes that hash so
you can pivot on http.favicon.hash in Shodan/FOFA/ZoomEye.
"""
from __future__ import annotations

import base64
from datetime import datetime
from urllib.parse import urljoin, urlparse

import mmh3
import requests

from adversary_intel.models import FaviconResult

# Shodan-compatible favicon hash (MurmurHash3 of base64-encoded bytes,
# matching Shodan's specific encoding — base64.encodebytes adds newlines)
def _shodan_mmh3(data: bytes) -> int:
    b64 = base64.encodebytes(data)
    return mmh3.hash(b64)


def _favicon_urls(target: str) -> list[str]:
    """Generate candidate favicon URLs for a target host."""
    if not target.startswith("http"):
        candidates = [f"https://{target}/favicon.ico", f"http://{target}/favicon.ico"]
    else:
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        candidates = [
            urljoin(base, "/favicon.ico"),
            urljoin(target, "favicon.ico"),
        ]
    return candidates


def fetch(target: str, timeout: float = 8.0) -> FaviconResult | None:
    """
    Fetch the favicon from a target host and return its Shodan-compatible
    MurmurHash3 hash. Returns None if no favicon is found.
    """
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "image/x-icon,image/*,*/*;q=0.8",
    }
    for url in _favicon_urls(target):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
            if r.status_code == 200 and r.content:
                h = _shodan_mmh3(r.content)
                return FaviconResult(
                    url=url,
                    hash_mmh3=h,
                    hash_hex=hex(h & 0xFFFFFFFF),
                    content_length=len(r.content),
                    scanned_at=datetime.utcnow(),
                )
        except requests.RequestException:
            continue
    return None


def hash_bytes(data: bytes) -> int:
    """Hash raw favicon bytes — useful when you already have the content."""
    return _shodan_mmh3(data)


def shodan_query(mmh3_hash: int) -> str:
    """Return the Shodan search query string for this favicon hash."""
    return f"http.favicon.hash:{mmh3_hash}"


def fofa_query(mmh3_hash: int) -> str:
    """Return the FOFA search query string for this favicon hash."""
    return f'icon_hash="{mmh3_hash}"'


# Known malicious favicon hashes (regularly updated by community)
KNOWN_HASHES: dict[int, str] = {
    -1627975581: "Cobalt Strike default panel",
    -1504224205: "Cobalt Strike (alt)",
    1078677607:  "Metasploit web UI",
    -2013662638: "Sliver C2 panel",
    -1003316662: "Covenant C2",
    699798153:   "PoshC2 panel",
}


def classify(mmh3_hash: int) -> str | None:
    return KNOWN_HASHES.get(mmh3_hash)
