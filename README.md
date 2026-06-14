# adversary-intel

Standalone threat intelligence platform for proactive adversary infrastructure tracking.

Inspired by the methodology from [ThreatSignal — Tracking Adversary Infrastructure: Beyond the IoC](https://www.threatsignal.in/post/tracking-adversary-infrastructure).

> *"Static indicator lists age like milk. By the time an indicator appears in a public feed, the adversary has already pivoted."*

Instead of consuming public threat feeds reactively, this platform lets you **produce** threat intelligence — building internal infrastructure graphs of adversary C2 clusters before they appear in any public feed.

---

## Architecture

```
adversary-intel/
├── adversary_intel/
│   ├── core/               # Active fingerprinting (JARM, favicon, TLS, HTTP, pDNS)
│   ├── scanning/           # Internet-wide scan pivots (Shodan, Censys, crt.sh)
│   ├── intel/              # Enrichment (WHOIS, ASN, VirusTotal)
│   ├── feeds/              # Threat feed integrations
│   │   ├── anomali.py      # Anomali ThreatStream (commercial)
│   │   ├── misp.py         # MISP (open source)
│   │   ├── opencti.py      # OpenCTI (open source)
│   │   ├── otx.py          # AlienVault OTX (free)
│   │   └── abusech.py      # MalwareBazaar, URLhaus, Feodo, ThreatFox, SSLBL (free)
│   ├── graph/              # NetworkX infrastructure graph
│   ├── detection/          # Sigma rule + Nuclei template generation
│   ├── workflows/          # End-to-end C2 hunt workflow
│   └── api/                # FastAPI REST API
├── templates/
│   ├── sigma/              # Built-in Sigma detection rules
│   └── nuclei/             # Built-in Nuclei templates
└── tests/
```

## What it does

### Fingerprinting
| Module | Technique | Pivot |
|--------|-----------|-------|
| `core/jarm.py` | Active TLS fingerprinting (10 probes → 62-char hash) | `ssl.jarm:` on Shodan/Censys |
| `core/tls_cert.py` | X.509 cert extraction (CN, SANs, serial, fingerprint) | `ssl.cert.fingerprint:` on Shodan |
| `core/favicon.py` | MurmurHash3 favicon hash | `http.favicon.hash:` on Shodan/FOFA |
| `core/http_fp.py` | HTTP response fingerprinting (headers, body hash, title) | Compound Shodan queries |
| `core/passive_dns.py` | pDNS history + batch activation detection | Validin, SecurityTrails, VirusTotal |

### Intelligence
| Module | Source | Cost |
|--------|--------|------|
| `intel/whois.py` | WHOIS + SecurityTrails pivot | Free tier available |
| `intel/asn.py` | ASN/hosting clustering + bulletproof ASN flagging | Free (BGP.tools) |
| `intel/virustotal.py` | VT sandbox C2 extraction, JARM, pDNS, reputation | Free tier |
| `scanning/crtsh.py` | CT log monitoring for phishing infra | Free |

### Threat Feeds (zero-key feeds always active)
| Feed | Key Required | Covers |
|------|-------------|--------|
| MalwareBazaar | No | Malware samples + C2 configs |
| URLhaus | No | Malicious URLs |
| Feodo Tracker | No | Botnet C2 IPs (Emotet, QakBot, IcedID) |
| ThreatFox | No | IOC database |
| SSLBL | No | Malicious TLS certificate blacklist |
| AlienVault OTX | Yes (free) | Community threat pulses |
| VirusTotal | Yes (free) | File/IP/domain reputation |
| Anomali ThreatStream | Yes (commercial) | Enterprise threat intel |
| MISP | Yes (self-hosted) | Sharing platform |
| OpenCTI | Yes (self-hosted) | STIX 2.1 CTI platform |

---

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/adversary-intel
cd adversary-intel
pip install -e ".[dev]"
cp .env.example .env
# Edit .env with your API keys (only Shodan + VT needed for basic use)
```

### CLI usage

```bash
# Full end-to-end hunt from a seed IP
adversary-intel hunt 45.142.212.31

# Hunt from a malware hash (extracts C2 via VT sandbox first)
adversary-intel hunt abc123...sha256hash --seed-type hash

# JARM fingerprint a host
adversary-intel jarm 45.142.212.31

# Analyze TLS certificate
adversary-intel cert malicious-c2.example.com

# Passive DNS history + batch activation
adversary-intel pdns 45.142.212.31
adversary-intel pdns evil-domain.com

# WHOIS pivot
adversary-intel whois evil-domain.com

# Favicon hash for Shodan pivot
adversary-intel favicon https://target.com

# CT log monitoring (find phishing infra before first phish)
adversary-intel ct-monitor targetorg.com

# Check indicator across all feeds
adversary-intel feeds check 45.142.212.31
adversary-intel feeds recent

# Generate Sigma rules
adversary-intel sigma --jarm 07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2
adversary-intel sigma --ips "1.2.3.4,5.6.7.8"

# Start REST API
adversary-intel serve
```

### REST API

```bash
adversary-intel serve
# → http://localhost:8000/docs
```

Key endpoints:

```
POST /jarm           { "host": "45.142.212.31" }
POST /cert           { "host": "evil.com" }
POST /favicon        { "target": "https://evil.com" }
POST /pdns           { "query": "45.142.212.31" }
POST /whois          ?domain=evil.com
POST /ct-monitor     { "query": "%.targetorg.com" }
POST /feeds/check    { "indicator": "45.142.212.31" }
POST /shodan/jarm    ?jarm=07d14d...
POST /sigma/jarm     { "jarm": "07d14d...", "title": "Cobalt Strike" }
POST /hunt           { "seed": "45.142.212.31" }   ← full async hunt
GET  /hunt/{job_id}  ← poll for results
```

### Python API

```python
from adversary_intel.workflows.c2_hunt import C2Hunter
from adversary_intel.models import NodeType

hunter = C2Hunter(output_dir="./output")
result = hunter.hunt("45.142.212.31", NodeType.IP)

print(f"Nodes discovered: {result.nodes_discovered}")
print(f"Previously unreported: {result.unreported_nodes}")
print(f"JARM clusters: {result.jarm_clusters}")
print(f"Sigma rules: {len(result.sigma_rules)}")
```

---

## The hunting methodology

This tool implements the pivot chain from the ThreatSignal article:

```
Seed IP / Domain / Hash
    │
    ├─ JARM fingerprint          → "probably Cobalt Strike/Sliver"
    │
    ├─ Shodan JARM pivot         → 34 IPs sharing fingerprint
    │       └─ filter CDN ASNs  → 19 candidates
    │
    ├─ VirusTotal cross-ref      → 6 known, 13 UNREPORTED
    │
    ├─ TLS cert pivot            → 11/19 share cert template
    │       └─ confirms single  → deployment cluster
    │
    ├─ Passive DNS               → 9 domains activated same 48h window
    │       └─ batch activation  → operator fingerprint
    │
    ├─ WHOIS clustering          → same registrar + nameserver pair
    │       └─ confirmed:        → same operator as known campaign
    │
    ├─ ASN analysis              → bulletproof hosting flagged
    │
    └─ Rule generation
            ├─ Sigma rules       → SIEM detection
            └─ Nuclei templates  → automated scanning
```

**Output:** Infrastructure graph (JSON/GEXF/HTML), Sigma rules, Nuclei templates.
All 13 unreported IPs added to detection before any appeared in a public feed.

---

## API keys

| Platform | Key | Get it |
|----------|-----|--------|
| Shodan | `SHODAN_API_KEY` | [shodan.io](https://shodan.io) — $49/mo or free developer |
| Censys | `CENSYS_API_ID` + `CENSYS_API_SECRET` | [censys.io](https://censys.io) — free researcher tier |
| VirusTotal | `VIRUSTOTAL_API_KEY` | [virustotal.com](https://virustotal.com) — free 4 req/min |
| OTX | `OTX_API_KEY` | [otx.alienvault.com](https://otx.alienvault.com) — free |
| SecurityTrails | `SECURITYTRAILS_API_KEY` | [securitytrails.com](https://securitytrails.com) — free tier |
| Validin | `VALIDIN_API_KEY` | [validin.com](https://validin.com) |
| Anomali | `ANOMALI_USERNAME` + `ANOMALI_API_KEY` | [anomali.com](https://anomali.com) — trial available |
| MISP | `MISP_URL` + `MISP_KEY` | Self-host: [github.com/MISP/MISP](https://github.com/MISP/MISP) |
| OpenCTI | `OPENCTI_URL` + `OPENCTI_TOKEN` | Self-host or [filigran.io](https://filigran.io) |

Zero-key feeds (always active): MalwareBazaar, URLhaus, Feodo Tracker, ThreatFox, SSLBL, crt.sh

---

## Built-in detection templates

### Sigma rules (`templates/sigma/`)
- `cobalt_strike_jarm.yml` — CS default JARM detection
- `ja3_c2_detection.yml` — JA3 fingerprint matching for CS/Sliver/Metasploit

### Nuclei templates (`templates/nuclei/`)
- `cobalt_strike_multi_signal.yaml` — JARM + HTTP 404 pattern (low false positive)
- `sliver_c2_detection.yaml` — Sliver C2 JARM detection

---

## MITRE ATT&CK coverage

| Technique | ID | Tracking approach |
|-----------|----|--------------------|
| C2 via HTTP/S | T1071.001 | JARM + HTTP response fingerprinting |
| Encrypted C2 | T1573.002 | JA3/JA3S + TLS cert analysis |
| Acquire Infrastructure | T1583 | WHOIS batch registration detection |
| Compromise Infrastructure | T1584 | pDNS history + activation clustering |
| Dynamic Resolution | T1568 | Passive DNS pivot chains |
| Protocol Tunneling | T1572 | JARM TLS stack fingerprinting |

---

## Tests

```bash
pytest tests/ -v
```

---

## License

MIT
