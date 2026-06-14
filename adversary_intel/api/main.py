"""
adversary-intel REST API (FastAPI).

All hunting, fingerprinting, and feed operations available as JSON endpoints.
Swagger UI: http://localhost:8000/docs
ReDoc: http://localhost:8000/redoc
"""
from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from adversary_intel.config import settings
from adversary_intel.models import NodeType

app = FastAPI(
    title="adversary-intel",
    description="Proactive adversary infrastructure tracking API",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response models ─────────────────────────────────────────────────

class HuntRequest(BaseModel):
    seed: str
    seed_type: str = "auto"
    max_depth: int = 3


class JARMRequest(BaseModel):
    host: str
    port: int = 443


class CertRequest(BaseModel):
    host: str
    port: int = 443


class PDNSRequest(BaseModel):
    query: str
    detect_batch: bool = True


class FaviconRequest(BaseModel):
    target: str


class CTMonitorRequest(BaseModel):
    query: str
    detect_bulk: bool = True


class FeedCheckRequest(BaseModel):
    indicator: str
    ioc_type: str = "auto"


class SigmaRequest(BaseModel):
    jarm: Optional[str] = None
    ips: Optional[list[str]] = None
    title: str = "Discovered C2 Infrastructure"


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "available_feeds": settings.available_feeds(),
        "available_scanners": settings.available_scanners(),
    }


@app.get("/config")
def config_info():
    return {
        "feeds": settings.available_feeds(),
        "scanners": settings.available_scanners(),
        "max_pivot_depth": settings.max_pivot_depth,
        "rate_limit_delay": settings.rate_limit_delay,
    }


# ── Fingerprinting ────────────────────────────────────────────────────────────

@app.post("/jarm")
def jarm_fingerprint(req: JARMRequest):
    from adversary_intel.core import jarm as jarm_module
    try:
        result = jarm_module.fingerprint(req.host, req.port)
        c2_match = jarm_module.classify(result.fingerprint)
        return {
            "host": req.host,
            "port": req.port,
            "jarm": result.fingerprint,
            "c2_match": c2_match,
            "is_c2": jarm_module.is_c2(result.fingerprint),
            "shodan_query": f'ssl.jarm:"{result.fingerprint}"',
            "scanned_at": result.scanned_at.isoformat(),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/cert")
def cert_analysis(req: CertRequest):
    from adversary_intel.core import tls_cert
    cert = tls_cert.fetch(req.host, req.port)
    if not cert:
        raise HTTPException(status_code=404, detail="Could not retrieve certificate")
    reasons = tls_cert.is_suspicious(cert)
    return {
        **cert.model_dump(),
        "suspicious": reasons,
        "shodan_query": tls_cert.shodan_cert_query(cert.sha1_fingerprint or ""),
        "censys_query": tls_cert.censys_cert_query(cert.sha256_fingerprint or ""),
    }


@app.post("/favicon")
def favicon_hash(req: FaviconRequest):
    from adversary_intel.core import favicon as fav_module
    result = fav_module.fetch(req.target)
    if not result:
        raise HTTPException(status_code=404, detail="No favicon found")
    return {
        **result.model_dump(),
        "shodan_query": fav_module.shodan_query(result.hash_mmh3),
        "fofa_query": fav_module.fofa_query(result.hash_mmh3),
        "known_panel": fav_module.classify(result.hash_mmh3),
    }


@app.post("/http-fingerprint")
def http_fingerprint(host: str, port: int = 443, path: str = "/"):
    from adversary_intel.core import http_fp as http_module
    result = http_module.probe(host, port=port, path=path)
    if not result:
        raise HTTPException(status_code=500, detail="HTTP probe failed")
    return result.model_dump()


# ── Pivoting ──────────────────────────────────────────────────────────────────

@app.post("/pdns")
def passive_dns(req: PDNSRequest):
    from adversary_intel.core.passive_dns import PassiveDNSClient
    import ipaddress
    client = PassiveDNSClient()
    try:
        ipaddress.ip_address(req.query)
        records = client.ip_history(req.query)
    except ValueError:
        records = client.resolve_history(req.query)

    result: dict[str, Any] = {
        "query": req.query,
        "records": [r.model_dump() for r in records],
    }
    if req.detect_batch:
        clusters = client.find_batch_activation(records)
        result["batch_clusters"] = [
            {"records": [r.model_dump() for r in c]}
            for c in clusters
        ]
    return result


@app.post("/whois")
def whois_lookup(domain: str):
    from adversary_intel.intel.whois import lookup
    data = lookup(domain)
    if not data:
        raise HTTPException(status_code=404, detail="WHOIS lookup failed")
    return data.model_dump()


@app.post("/ct-monitor")
def ct_monitor(req: CTMonitorRequest):
    from adversary_intel.scanning.crtsh import search, detect_bulk_issuance, extract_domains
    query = req.query if req.query.startswith("%") else f"%.{req.query}"
    results = search(query)
    domains = extract_domains(results)
    response: dict[str, Any] = {
        "query": query,
        "total_certs": len(results),
        "domains": domains[:50],
    }
    if req.detect_bulk:
        clusters = detect_bulk_issuance(results)
        response["bulk_issuance_clusters"] = len(clusters)
    return response


@app.post("/asn")
def asn_lookup(ip: str):
    from adversary_intel.intel.asn import lookup, is_bulletproof
    info = lookup(ip)
    if not info:
        raise HTTPException(status_code=404, detail="ASN lookup failed")
    return {
        **info.model_dump(),
        "is_bulletproof": is_bulletproof(ip),
    }


# ── Scanning pivots ───────────────────────────────────────────────────────────

@app.post("/shodan/jarm")
def shodan_jarm_pivot(jarm: str, limit: int = 50):
    if not settings.shodan_api_key:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    from adversary_intel.scanning.shodan import ShodanClient
    client = ShodanClient()
    results = client.pivot_jarm(jarm, limit=limit)
    filtered = client.filter_cdn_asns(results)
    return {"total": len(results), "after_cdn_filter": len(filtered), "results": filtered}


@app.post("/shodan/cert")
def shodan_cert_pivot(sha1_fingerprint: str, limit: int = 50):
    if not settings.shodan_api_key:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    from adversary_intel.scanning.shodan import ShodanClient
    client = ShodanClient()
    return client.pivot_cert_fingerprint(sha1_fingerprint, limit=limit)


@app.post("/shodan/favicon")
def shodan_favicon_pivot(mmh3_hash: int, limit: int = 50):
    if not settings.shodan_api_key:
        raise HTTPException(status_code=503, detail="Shodan API key not configured")
    from adversary_intel.scanning.shodan import ShodanClient
    client = ShodanClient()
    return client.pivot_favicon(mmh3_hash, limit=limit)


# ── Feeds ─────────────────────────────────────────────────────────────────────

@app.post("/feeds/check")
def feeds_check(req: FeedCheckRequest):
    from adversary_intel.feeds.abusech import check_all
    import ipaddress

    if req.ioc_type == "auto":
        try:
            ipaddress.ip_address(req.indicator)
            ioc_type = NodeType.IP
        except ValueError:
            ioc_type = NodeType.DOMAIN if len(req.indicator) < 64 else NodeType.HASH
    else:
        ioc_type = NodeType(req.ioc_type)

    results = check_all(req.indicator, ioc_type)
    return {
        "indicator": req.indicator,
        "found_in_feeds": len(results),
        "results": [r.model_dump() for r in results],
    }


@app.get("/feeds/recent")
def feeds_recent(source: str = "abusech", limit: int = 20):
    if source == "abusech":
        from adversary_intel.feeds.abusech import threatfox_recent
        return {"source": source, "indicators": threatfox_recent(limit=limit)}
    raise HTTPException(status_code=400, detail=f"Unknown source: {source}")


# ── Detection rules ───────────────────────────────────────────────────────────

@app.post("/sigma/jarm")
def sigma_jarm(req: SigmaRequest):
    from adversary_intel.detection import sigma as sigma_gen
    if not req.jarm:
        raise HTTPException(status_code=400, detail="jarm field required")
    rule = sigma_gen.jarm_rule(jarm=req.jarm, title=req.title)
    return {"rule": rule}


@app.post("/sigma/ips")
def sigma_ips(req: SigmaRequest):
    from adversary_intel.detection import sigma as sigma_gen
    if not req.ips:
        raise HTTPException(status_code=400, detail="ips field required")
    rule = sigma_gen.c2_ip_rule(ips=req.ips, title=req.title)
    return {"rule": rule}


@app.get("/nuclei/builtin")
def nuclei_builtin():
    from adversary_intel.detection.nuclei import get_builtin_templates
    return get_builtin_templates()


# ── Full hunt (async) ─────────────────────────────────────────────────────────

_hunt_results: dict[str, Any] = {}


@app.post("/hunt")
async def hunt_endpoint(req: HuntRequest, background_tasks: BackgroundTasks):
    """
    Launch a full infrastructure hunt asynchronously.
    Returns a job ID — poll /hunt/{job_id} for results.
    """
    import uuid
    job_id = str(uuid.uuid4())[:8]
    _hunt_results[job_id] = {"status": "running", "seed": req.seed}

    def _run():
        from adversary_intel.workflows.c2_hunt import C2Hunter
        from adversary_intel.models import NodeType
        import ipaddress
        try:
            ipaddress.ip_address(req.seed)
            ioc_type = NodeType.IP
        except ValueError:
            ioc_type = NodeType.DOMAIN if len(req.seed) < 64 else NodeType.HASH

        hunter = C2Hunter(max_pivot_depth=req.max_depth)
        result = hunter.hunt(req.seed, ioc_type)
        _hunt_results[job_id] = {
            "status": "complete",
            "seed": req.seed,
            "nodes_discovered": result.nodes_discovered,
            "unreported_nodes": result.unreported_nodes,
            "jarm_clusters": result.jarm_clusters,
            "cert_clusters": result.cert_clusters,
            "sigma_rules": result.sigma_rules,
            "duration_seconds": result.duration_seconds,
        }

    background_tasks.add_task(_run)
    return {"job_id": job_id, "status": "running"}


@app.get("/hunt/{job_id}")
def hunt_status(job_id: str):
    if job_id not in _hunt_results:
        raise HTTPException(status_code=404, detail="Job not found")
    return _hunt_results[job_id]
