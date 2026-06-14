"""
TLS certificate extraction and analysis.

Pulls the full certificate chain from a live server and extracts
structured metadata for pivot analysis (CN, SANs, serial, fingerprints).
"""
from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization

from adversary_intel.models import TLSCertInfo


def _utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def fetch(host: str, port: int = 443, timeout: float = 8.0) -> TLSCertInfo | None:
    """
    Connect to host:port and return the leaf TLS certificate's metadata.
    Does NOT verify the certificate chain — intentional, we want to inspect
    self-signed and expired certs that adversaries commonly use.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                der_bytes = tls_sock.getpeercert(binary_form=True)
    except (socket.error, ssl.SSLError, OSError):
        return None

    if not der_bytes:
        return None

    cert = x509.load_der_x509_certificate(der_bytes, default_backend())
    return _parse_cert(cert)


def from_pem(pem: str) -> TLSCertInfo:
    cert = x509.load_pem_x509_certificate(pem.encode(), default_backend())
    return _parse_cert(cert)


def from_der(der: bytes) -> TLSCertInfo:
    cert = x509.load_der_x509_certificate(der, default_backend())
    return _parse_cert(cert)


def _parse_cert(cert: x509.Certificate) -> TLSCertInfo:
    def _attr(name_obj, oid):
        try:
            return name_obj.get_attributes_for_oid(oid)[0].value
        except Exception:
            return None

    subject_cn = _attr(cert.subject, x509.NameOID.COMMON_NAME)
    subject_org = _attr(cert.subject, x509.NameOID.ORGANIZATION_NAME)
    issuer_cn = _attr(cert.issuer, x509.NameOID.COMMON_NAME)
    issuer_org = _attr(cert.issuer, x509.NameOID.ORGANIZATION_NAME)

    serial = format(cert.serial_number, "x").upper()

    der = cert.public_bytes(serialization.Encoding.DER)
    sha1_fp = hashlib.sha1(der).hexdigest().upper()  # noqa: S324
    sha256_fp = hashlib.sha256(der).hexdigest().upper()

    sans: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(v) for v in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    is_self_signed = cert.issuer == cert.subject

    not_before = _utc(cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before)
    not_after = _utc(cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after)

    return TLSCertInfo(
        subject_cn=subject_cn,
        subject_org=subject_org,
        issuer_cn=issuer_cn,
        issuer_org=issuer_org,
        serial_number=serial,
        sha1_fingerprint=sha1_fp,
        sha256_fingerprint=sha256_fp,
        not_before=not_before,
        not_after=not_after,
        sans=sans,
        is_self_signed=is_self_signed,
    )


def shodan_cert_query(sha1_fingerprint: str) -> str:
    return f'ssl.cert.fingerprint:"{sha1_fingerprint}"'


def shodan_serial_query(serial: str) -> str:
    """Decimal serial number query for Shodan."""
    try:
        decimal = int(serial, 16)
        return f"ssl.cert.serial:{decimal}"
    except ValueError:
        return f"ssl.cert.serial:{serial}"


def censys_cert_query(sha256_fingerprint: str) -> str:
    return f"parsed.fingerprint_sha256:{sha256_fingerprint.lower()}"


def is_suspicious(cert: TLSCertInfo) -> list[str]:
    """
    Heuristic checks for certificates commonly seen on adversary infrastructure.
    Returns a list of suspicion reasons (empty = nothing flagged).
    """
    reasons: list[str] = []
    if cert.is_self_signed:
        reasons.append("self-signed certificate")
    if cert.subject_cn in ("localhost", "example.com", "test", "server"):
        reasons.append(f"default/generic CN: {cert.subject_cn}")
    if cert.not_after and cert.not_after < datetime.now(timezone.utc):
        reasons.append("certificate is expired")
    if cert.not_before and cert.not_after:
        validity_days = (cert.not_after - cert.not_before).days
        if validity_days > 3650:
            reasons.append(f"unusually long validity ({validity_days} days)")
    if cert.subject_org in (None, "") and not cert.is_self_signed:
        reasons.append("no organization in subject")
    return reasons
