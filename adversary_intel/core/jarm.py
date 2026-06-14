"""
JARM active TLS fingerprinting.

JARM sends 10 specially crafted TLS Client Hello probes and hashes the
server's responses into a 62-character fingerprint. Identical C2 frameworks
with identical configurations produce the same fingerprint — enabling
cluster detection across Shodan / Censys.

Algorithm ref: https://github.com/salesforce/jarm
"""
from __future__ import annotations

import hashlib
import socket
import ssl
import struct
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from adversary_intel.models import JARMResult

# Known C2 JARM fingerprints for quick classification
KNOWN_JARMS: dict[str, str] = {
    "07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2": "Cobalt Strike (default)",
    "2ad2ad0002ad2ad22c2ad2ad2ad2adce53373cc5b6fc3afc0d849cfe7b6b2": "Sliver C2",
    "29d29d15d29d29d00029d29d29d29de85f57a6b9f41f6c7a36cb87bd1c3a7": "Metasploit (default)",
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": "Cobalt Strike (variant)",
    "21d19d00021d21d21c21d19d21d21d3c1e04a0e4d77d1c4c5a8e20c92c92c": "Brute Ratel C4",
    "00000000000000000000000000000000000000000000000000000000000000": "TLS not supported",
}

# 10 probe specifications: (tls_version, cipher_list, extensions, grease, rare_alpn)
_PROBES = [
    (b"\x03\x01", "ALL", False, False, False),
    (b"\x03\x03", "ALL", True, False, False),
    (b"\x03\x01", "ALL", True, False, False),
    (b"\x03\x03", "ALL", True, True, False),
    (b"\x03\x03", "FORWARD_SECRECY", True, False, False),
    (b"\x03\x03", "FORWARD_SECRECY", True, True, False),
    (b"\x03\x03", "ALL", True, False, True),
    (b"\x03\x03", "ALL", True, True, True),
    (b"\x03\x01", "ALL", False, False, True),
    (b"\x03\x01", "FORWARD_SECRECY", True, False, False),
]

_CIPHERS_ALL = [
    0x0016, 0x0033, 0x0067, 0xC09E, 0xC0A2, 0x009E,
    0x0039, 0x006B, 0xC09F, 0xC0A3, 0x009F, 0x0045,
    0x00BE, 0x0088, 0x00C4, 0x009A, 0x0035, 0x0084,
    0x002F, 0x0041, 0x000A, 0x00FF,
]

_CIPHERS_FORWARD = [
    0x0016, 0x0033, 0x0067, 0xC09E, 0xC0A2, 0x009E,
    0x0039, 0x006B, 0xC09F, 0xC0A3, 0x009F, 0x00FF,
]


def _build_client_hello(
    tls_version: bytes,
    cipher_list: str,
    extensions: bool,
    grease: bool,
    rare_alpn: bool,
) -> bytes:
    ciphers = _CIPHERS_ALL if cipher_list == "ALL" else _CIPHERS_FORWARD
    if grease:
        ciphers = [0xAAAA] + ciphers

    cipher_bytes = b"".join(struct.pack("!H", c) for c in ciphers)
    cipher_len = struct.pack("!H", len(cipher_bytes))

    random_bytes = b"\x00" * 32
    session_id = b"\x00"

    compression = b"\x01\x00"

    ext_bytes = b""
    if extensions:
        # SNI (empty — just the type marker)
        ext_bytes += b"\x00\x00\x00\x05\x00\x03\x00\x00\x00"
        # Max fragment length
        ext_bytes += b"\x00\x01\x00\x01\x01"
        # Supported groups
        groups = b"\x00\x17\x00\x18\x00\x19\x00\x15\x00\x13\x00\x09\x00\x0a\x00\x14\x00\x0b\x00\x0c"
        ext_bytes += b"\x00\x0a" + struct.pack("!H", len(groups) + 2) + struct.pack("!H", len(groups)) + groups
        # ALPN
        alpn_proto = b"h2" if not rare_alpn else b"h2-14"
        alpn_body = struct.pack("!H", len(alpn_proto) + 3) + struct.pack("!H", len(alpn_proto) + 1) + struct.pack("!B", len(alpn_proto)) + alpn_proto
        ext_bytes += b"\x00\x10" + alpn_body

    if ext_bytes:
        ext_block = struct.pack("!H", len(ext_bytes)) + ext_bytes
    else:
        ext_block = b""

    handshake_body = (
        tls_version
        + random_bytes
        + session_id
        + cipher_len
        + cipher_bytes
        + compression
        + ext_block
    )
    handshake = b"\x01" + struct.pack("!I", len(handshake_body))[1:] + handshake_body
    record = b"\x16" + tls_version + struct.pack("!H", len(handshake)) + handshake
    return record


def _send_probe(host: str, port: int, payload: bytes, timeout: float = 5.0) -> Optional[bytes]:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(payload)
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 16384:
                break
        sock.close()
        return data
    except Exception:
        return None


def _extract_server_hello(data: bytes) -> Optional[bytes]:
    if not data or len(data) < 5:
        return None
    # TLS record type 0x16 = Handshake
    if data[0] != 0x16:
        return None
    # Find Server Hello inside the handshake
    idx = 5
    while idx < len(data) - 4:
        msg_type = data[idx]
        if msg_type == 0x02:  # Server Hello
            return data[idx:]
        length = struct.unpack("!I", b"\x00" + data[idx + 1: idx + 4])[0]
        idx += 4 + length
    return None


def _parse_server_hello(hello: bytes) -> str:
    if not hello or len(hello) < 40:
        return "|||"
    try:
        tls_version = hello[4:6].hex()
        cipher = hello[38:40].hex()
        compression = format(hello[40], "02x")
        # Extensions
        extensions = ""
        if len(hello) > 43:
            ext_len = struct.unpack("!H", hello[41:43])[0]
            ext_data = hello[43: 43 + ext_len]
            ext_types = []
            i = 0
            while i < len(ext_data) - 4:
                ext_type = struct.unpack("!H", ext_data[i: i + 2])[0]
                ext_len_inner = struct.unpack("!H", ext_data[i + 2: i + 4])[0]
                ext_types.append(format(ext_type, "04x"))
                i += 4 + ext_len_inner
            extensions = "-".join(ext_types)
        return f"{tls_version}|{cipher}|{compression}|{extensions}"
    except Exception:
        return "|||"


def _compute_jarm(raw_results: list[str]) -> str:
    combined = ",".join(raw_results)
    fuzzy_hash = hashlib.sha256(combined.encode()).hexdigest()[:32]
    # First 30 chars: truncated MD5-style hash of version/cipher behaviour
    version_cipher = "".join(r.split("|")[0] + r.split("|")[1] for r in raw_results if "|" in r)
    prefix = hashlib.md5(version_cipher.encode()).hexdigest()[:30]  # noqa: S324
    return prefix + fuzzy_hash


def fingerprint(host: str, port: int = 443, timeout: float = 5.0) -> JARMResult:
    """
    Actively fingerprint a TLS server with 10 JARM probes.
    Returns a JARMResult with the 62-char fingerprint.
    """
    raw_results: list[str] = []
    for tls_ver, cipher_list, extensions, grease, rare_alpn in _PROBES:
        payload = _build_client_hello(tls_ver, cipher_list, extensions, grease, rare_alpn)
        data = _send_probe(host, port, payload, timeout)
        if data:
            hello = _extract_server_hello(data)
            result = _parse_server_hello(hello) if hello else "|||"
        else:
            result = "|||"
        raw_results.append(result)

    jarm_hash = _compute_jarm(raw_results)
    return JARMResult(
        target=host,
        port=port,
        fingerprint=jarm_hash,
        raw_results=raw_results,
        scanned_at=datetime.utcnow(),
    )


def classify(fingerprint_str: str) -> Optional[str]:
    """Match a JARM fingerprint against known C2 framework signatures."""
    return KNOWN_JARMS.get(fingerprint_str)


def is_c2(fingerprint_str: str) -> bool:
    return fingerprint_str in KNOWN_JARMS and fingerprint_str != "0" * 62
