"""
HTTP response fingerprinting for C2 and phishing infrastructure detection.

Probes a host and extracts structural artifacts: headers, status code,
body hash, page title, Content-Length — building a composite fingerprint
for Shodan/FOFA pivot queries.
"""
from __future__ import annotations

import hashlib
import re
from typing import Optional
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from adversary_intel.models import HTTPFingerprint

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)

_TECH_HINTS: dict[str, list[str]] = {
    "Cobalt Strike": [
        "HTTP/1.1 404 Not Found|Content-Length: 0",
        "Content-Length: 0",
    ],
    "Brute Ratel C4": [
        "X-Idc-Auth",
        "Brute Ratel",
    ],
    "Sliver": [
        "X-Sliver",
        "application/grpc",
    ],
    "Metasploit": [
        "msf",
        "Metasploit",
    ],
    "Havoc C2": [
        "X-Havoc",
    ],
}


def _detect_tech(headers: dict[str, str], body: str) -> list[str]:
    hints = []
    combined = str(headers) + body
    for tech, signatures in _TECH_HINTS.items():
        for sig in signatures:
            if sig.lower() in combined.lower():
                hints.append(tech)
                break
    return hints


def probe(
    target: str,
    port: int = 443,
    path: str = "/",
    scheme: str = "https",
    timeout: float = 8.0,
) -> HTTPFingerprint | None:
    """
    Probe a target and return its HTTP fingerprint.
    """
    if "://" in target:
        url = target if path == "/" else target.rstrip("/") + path
    else:
        url = f"{scheme}://{target}:{port}{path}"

    headers_req = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept": "text/html,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "close",
    }

    try:
        r = requests.get(
            url,
            headers=headers_req,
            timeout=timeout,
            verify=False,       # noqa: S501 — intentional for adversary infra analysis
            allow_redirects=False,
        )
    except RequestException:
        return None

    body = r.text[:4096]
    body_md5 = hashlib.md5((r.content or b"")).hexdigest()  # noqa: S324

    title_match = _TITLE_RE.search(body)
    title = title_match.group(1).strip() if title_match else None

    response_headers = {k: v for k, v in r.headers.items()}
    tech = _detect_tech(response_headers, body)

    return HTTPFingerprint(
        target=target,
        status_code=r.status_code,
        server_header=r.headers.get("Server"),
        content_type=r.headers.get("Content-Type"),
        content_length=int(r.headers.get("Content-Length", len(r.content))),
        response_headers=response_headers,
        body_hash_md5=body_md5,
        body_preview=body[:512],
        page_title=title,
        technology_hints=tech,
    )


def build_shodan_query(fp: HTTPFingerprint) -> list[str]:
    """Generate Shodan search queries from a fingerprint."""
    queries: list[str] = []
    if fp.page_title:
        queries.append(f'http.title:"{fp.page_title}"')
    if fp.server_header:
        queries.append(f'http.headers.server:"{fp.server_header}"')
    if fp.status_code == 404 and fp.content_length == 0:
        queries.append('"HTTP/1.1 404 Not Found" "Content-Length: 0"')
    return queries


def is_default_c2_response(fp: HTTPFingerprint) -> bool:
    """Heuristic: empty 404 is the Cobalt Strike default response."""
    return fp.status_code == 404 and (fp.content_length or 0) == 0


def cobalt_strike_watermark_query(watermark: int) -> str:
    """VT / Shodan search for CS license watermark embedded in beacons."""
    return f"content:{watermark} type:file"
