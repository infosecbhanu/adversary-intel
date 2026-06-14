"""Shared Pydantic models for all platform data types."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    CERTIFICATE = "certificate"
    ASN = "asn"
    HASH = "hash"
    EMAIL = "email"
    NAMESERVER = "nameserver"
    URL = "url"


class EdgeType(str, Enum):
    RESOLVES_TO = "resolves_to"
    SHARES_CERT = "shares_cert"
    SHARES_JARM = "shares_jarm"
    SHARES_FAVICON = "shares_favicon"
    REGISTERED_WITH = "registered_with"
    USES_NAMESERVER = "uses_nameserver"
    HOSTED_ON = "hosted_on"
    SAME_ASN = "same_asn"
    SAME_REGISTRAR = "same_registrar"
    BATCH_REGISTERED = "batch_registered"
    CONTAINS = "contains"


class TLSCertInfo(BaseModel):
    subject_cn: Optional[str] = None
    subject_org: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_org: Optional[str] = None
    serial_number: Optional[str] = None
    sha1_fingerprint: Optional[str] = None
    sha256_fingerprint: Optional[str] = None
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    sans: list[str] = Field(default_factory=list)
    is_self_signed: bool = False


class JARMResult(BaseModel):
    target: str
    port: int = 443
    fingerprint: str
    raw_results: list[str] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class FaviconResult(BaseModel):
    url: str
    hash_mmh3: int
    hash_hex: str
    content_length: int
    scanned_at: datetime = Field(default_factory=datetime.utcnow)


class HTTPFingerprint(BaseModel):
    target: str
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    body_hash_md5: Optional[str] = None
    body_preview: Optional[str] = None
    page_title: Optional[str] = None
    technology_hints: list[str] = Field(default_factory=list)


class PassiveDNSRecord(BaseModel):
    query: str
    answer: str
    record_type: str = "A"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    count: int = 0
    source: str = "unknown"


class WHOISData(BaseModel):
    domain: str
    registrar: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_org: Optional[str] = None
    nameservers: list[str] = Field(default_factory=list)
    creation_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    privacy_protected: bool = False
    raw: Optional[str] = None


class ASNInfo(BaseModel):
    asn: str
    asn_name: Optional[str] = None
    asn_description: Optional[str] = None
    country: Optional[str] = None
    prefix: Optional[str] = None
    is_bulletproof: bool = False
    abuse_contacts: list[str] = Field(default_factory=list)


class Indicator(BaseModel):
    value: str
    ioc_type: NodeType
    confidence: int = Field(ge=0, le=100, default=50)
    tags: list[str] = Field(default_factory=list)
    tlp: str = "white"
    source: str = "local"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    malware_families: list[str] = Field(default_factory=list)
    threat_actors: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)


class InfraNode(BaseModel):
    id: str
    node_type: NodeType
    value: str
    reported: bool = False        # appeared in a public feed
    confidence: int = 50
    tags: list[str] = Field(default_factory=list)
    meta: dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class InfraEdge(BaseModel):
    source: str
    target: str
    edge_type: EdgeType
    confidence: int = 50
    meta: dict[str, Any] = Field(default_factory=dict)
    first_seen: Optional[datetime] = None


class HuntResult(BaseModel):
    seed: str
    nodes_discovered: int = 0
    edges_discovered: int = 0
    unreported_nodes: int = 0
    nodes: list[InfraNode] = Field(default_factory=list)
    edges: list[InfraEdge] = Field(default_factory=list)
    jarm_clusters: dict[str, list[str]] = Field(default_factory=dict)
    cert_clusters: dict[str, list[str]] = Field(default_factory=dict)
    pdns_batch_activations: list[dict] = Field(default_factory=list)
    sigma_rules: list[str] = Field(default_factory=list)
    nuclei_templates: list[str] = Field(default_factory=list)
    duration_seconds: float = 0.0
    errors: list[str] = Field(default_factory=list)
