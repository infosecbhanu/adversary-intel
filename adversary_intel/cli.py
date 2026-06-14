"""
adversary-intel CLI

Usage:
  adversary-intel hunt 45.142.212.31
  adversary-intel jarm 45.142.212.31
  adversary-intel cert 45.142.212.31
  adversary-intel pdns example.com
  adversary-intel whois example.com
  adversary-intel favicon https://target.com
  adversary-intel ct-monitor targetorg.com
  adversary-intel feeds check 45.142.212.31
  adversary-intel feeds recent
  adversary-intel sigma --jarm 07d14d16d21d21d00042d41d00041de5fb3038104f457d92ba02e9311512c2
  adversary-intel serve
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

app = typer.Typer(
    name="adversary-intel",
    help="Proactive adversary infrastructure tracking platform",
    add_completion=False,
)
console = Console()


# ── Hunt ──────────────────────────────────────────────────────────────────────

@app.command()
def hunt(
    seed: str = typer.Argument(..., help="Seed indicator: IP, domain, or SHA-256 hash"),
    seed_type: str = typer.Option("auto", help="Type: ip / domain / hash / auto"),
    output: Path = typer.Option(Path("./output"), help="Output directory"),
    depth: int = typer.Option(3, help="Maximum pivot depth"),
):
    """Full end-to-end infrastructure hunt from a seed indicator."""
    from adversary_intel.models import NodeType
    from adversary_intel.workflows.c2_hunt import C2Hunter

    ioc_type = _detect_seed_type(seed, seed_type)
    console.print(Panel(f"[bold]Hunting from seed:[/bold] {seed}\nType: {ioc_type.value}", style="red"))

    hunter = C2Hunter(output_dir=output, max_pivot_depth=depth)
    result = hunter.hunt(seed, ioc_type)

    if result.errors:
        console.print("[yellow]Warnings during hunt:")
        for e in result.errors:
            console.print(f"  [dim]{e}")


# ── JARM ──────────────────────────────────────────────────────────────────────

@app.command()
def jarm(
    host: str = typer.Argument(..., help="Target host (IP or domain)"),
    port: int = typer.Option(443, help="Target port"),
):
    """Compute the JARM TLS fingerprint for a host."""
    from adversary_intel.core.jarm import classify, fingerprint

    console.print(f"[cyan]JARM fingerprinting {host}:{port}...")
    result = fingerprint(host, port)
    c2 = classify(result.fingerprint)

    table = Table(show_header=False)
    table.add_row("[bold]Host", result.target)
    table.add_row("[bold]Port", str(result.port))
    table.add_row("[bold]JARM", f"[yellow]{result.fingerprint}")
    table.add_row("[bold]C2 Match", f"[red]{c2}" if c2 else "[green]None (clean or unknown)")
    table.add_row("[bold]Shodan Query", f'ssl.jarm:"{result.fingerprint}"')
    console.print(table)


# ── Certificate ───────────────────────────────────────────────────────────────

@app.command()
def cert(
    host: str = typer.Argument(..., help="Target host"),
    port: int = typer.Option(443, help="Target port"),
):
    """Extract and analyze the TLS certificate from a host."""
    from adversary_intel.core.tls_cert import fetch, is_suspicious, shodan_cert_query

    console.print(f"[cyan]Fetching TLS certificate from {host}:{port}...")
    info = fetch(host, port)
    if not info:
        console.print("[red]Could not retrieve certificate")
        raise typer.Exit(1)

    table = Table(show_header=False)
    table.add_row("[bold]Subject CN", info.subject_cn or "N/A")
    table.add_row("[bold]Subject Org", info.subject_org or "N/A")
    table.add_row("[bold]Issuer CN", info.issuer_cn or "N/A")
    table.add_row("[bold]Serial", info.serial_number or "N/A")
    table.add_row("[bold]SHA-1", info.sha1_fingerprint or "N/A")
    table.add_row("[bold]SANs", "\n".join(info.sans[:5]) if info.sans else "None")
    table.add_row("[bold]Self-Signed", "[red]YES" if info.is_self_signed else "[green]NO")
    table.add_row("[bold]Valid Until", str(info.not_after))
    table.add_row("[bold]Shodan Query", shodan_cert_query(info.sha1_fingerprint or ""))
    console.print(table)

    reasons = is_suspicious(info)
    if reasons:
        console.print(Panel("\n".join(f"⚠  {r}" for r in reasons), title="[red]Suspicious indicators", style="red"))


# ── Passive DNS ───────────────────────────────────────────────────────────────

@app.command()
def pdns(
    query: str = typer.Argument(..., help="IP or domain to query"),
    detect_batch: bool = typer.Option(True, help="Detect batch activation clusters"),
):
    """Query passive DNS history and detect batch activation clusters."""
    from adversary_intel.core.passive_dns import PassiveDNSClient

    client = PassiveDNSClient()
    console.print(f"[cyan]pDNS lookup: {query}")

    # Detect if IP or domain
    import ipaddress
    try:
        ipaddress.ip_address(query)
        records = client.ip_history(query)
    except ValueError:
        records = client.resolve_history(query)

    if not records:
        console.print("[yellow]No pDNS records found")
        return

    table = Table(title=f"pDNS records for {query}", show_header=True)
    table.add_column("Answer", style="green")
    table.add_column("Type")
    table.add_column("First Seen")
    table.add_column("Last Seen")
    table.add_column("Source", style="dim")

    for r in records[:30]:
        table.add_row(
            r.answer,
            r.record_type,
            str(r.first_seen.date()) if r.first_seen else "?",
            str(r.last_seen.date()) if r.last_seen else "?",
            r.source,
        )
    console.print(table)

    if detect_batch:
        clusters = client.find_batch_activation(records)
        if clusters:
            console.print(f"\n[red]Batch activation detected: {len(clusters)} cluster(s)")
            for i, cluster in enumerate(clusters[:3]):
                console.print(f"  Cluster {i+1}: {[r.answer for r in cluster[:5]]}")


# ── WHOIS ─────────────────────────────────────────────────────────────────────

@app.command()
def whois(
    domain: str = typer.Argument(..., help="Domain to look up"),
):
    """WHOIS lookup with nameserver pivot information."""
    from adversary_intel.intel.whois import lookup

    console.print(f"[cyan]WHOIS: {domain}")
    data = lookup(domain)
    if not data:
        console.print("[red]WHOIS lookup failed")
        raise typer.Exit(1)

    table = Table(show_header=False)
    table.add_row("[bold]Registrar", data.registrar or "N/A")
    table.add_row("[bold]Created", str(data.creation_date.date()) if data.creation_date else "N/A")
    table.add_row("[bold]Updated", str(data.updated_date.date()) if data.updated_date else "N/A")
    table.add_row("[bold]Expires", str(data.expiry_date.date()) if data.expiry_date else "N/A")
    table.add_row("[bold]Nameservers", "\n".join(data.nameservers))
    table.add_row("[bold]Privacy", "[yellow]Protected" if data.privacy_protected else "[green]Exposed")
    if data.registrant_email:
        table.add_row("[bold]Email", data.registrant_email)
    console.print(table)


# ── Favicon ───────────────────────────────────────────────────────────────────

@app.command()
def favicon(
    target: str = typer.Argument(..., help="Target URL or host"),
):
    """Fetch favicon and compute Shodan/FOFA MurmurHash3 for pivoting."""
    from adversary_intel.core.favicon import classify, fetch, shodan_query, fofa_query

    console.print(f"[cyan]Favicon hash: {target}")
    result = fetch(target)
    if not result:
        console.print("[yellow]No favicon found")
        return

    table = Table(show_header=False)
    table.add_row("[bold]URL", result.url)
    table.add_row("[bold]MurmurHash3", str(result.hash_mmh3))
    table.add_row("[bold]Shodan Query", shodan_query(result.hash_mmh3))
    table.add_row("[bold]FOFA Query", fofa_query(result.hash_mmh3))
    known = classify(result.hash_mmh3)
    if known:
        table.add_row("[bold]Known Panel", f"[red]{known}")
    console.print(table)


# ── CT Monitor ────────────────────────────────────────────────────────────────

@app.command()
def ct_monitor(
    query: str = typer.Argument(..., help="Domain pattern (e.g. %.targetorg.com)"),
    detect_bulk: bool = typer.Option(True, help="Detect bulk certificate issuance"),
):
    """Monitor Certificate Transparency logs for matching certificates."""
    from adversary_intel.scanning.crtsh import search, detect_bulk_issuance, extract_domains

    if not query.startswith("%"):
        query = f"%.{query}"
    console.print(f"[cyan]CT log search: {query}")

    results = search(query)
    console.print(f"  Found [yellow]{len(results)}[/yellow] certificates")

    domains = extract_domains(results)
    if domains:
        console.print(f"  Unique domains: {len(domains)}")
        for d in domains[:10]:
            console.print(f"    [green]{d}")

    if detect_bulk:
        clusters = detect_bulk_issuance(results)
        if clusters:
            console.print(f"\n  [red]Bulk issuance detected: {len(clusters)} cluster(s)")


# ── Feeds ─────────────────────────────────────────────────────────────────────

feeds_app = typer.Typer(help="Threat feed operations")
app.add_typer(feeds_app, name="feeds")


@feeds_app.command("check")
def feeds_check(
    indicator: str = typer.Argument(..., help="IP, domain, or hash to check"),
):
    """Check an indicator against all configured threat feeds."""
    from adversary_intel.feeds.abusech import check_all
    from adversary_intel.models import NodeType

    import ipaddress
    try:
        ipaddress.ip_address(indicator)
        ioc_type = NodeType.IP
    except ValueError:
        ioc_type = NodeType.DOMAIN if "." in indicator and len(indicator) < 64 else NodeType.HASH

    console.print(f"[cyan]Checking {indicator} ({ioc_type.value}) across feeds...")
    results = check_all(indicator, ioc_type)

    if not results:
        console.print("[green]Not found in any configured feed")
    else:
        for ind in results:
            console.print(f"  [red]Found in {ind.source}: confidence={ind.confidence}, malware={ind.malware_families}")


@feeds_app.command("recent")
def feeds_recent(
    source: str = typer.Option("abusech", help="Feed source: abusech / otx / misp"),
    limit: int = typer.Option(20, help="Number of recent indicators"),
):
    """Fetch recent indicators from a threat feed."""
    if source == "abusech":
        from adversary_intel.feeds.abusech import threatfox_recent
        results = threatfox_recent(limit=limit)
        for r in results[:limit]:
            console.print(f"  [{r.get('threat_type', 'unknown')}] {r.get('ioc')} — {r.get('malware')}")


# ── Sigma generation ──────────────────────────────────────────────────────────

@app.command()
def sigma(
    jarm_fp: Optional[str] = typer.Option(None, "--jarm", help="Generate rule for JARM fingerprint"),
    ips: Optional[str] = typer.Option(None, "--ips", help="Comma-separated C2 IPs"),
    output: Path = typer.Option(Path("./output/rules/sigma"), help="Output directory"),
):
    """Generate Sigma detection rules from discovered fingerprints."""
    from adversary_intel.detection import sigma as sigma_gen

    rules = []
    if jarm_fp:
        rule = sigma_gen.jarm_rule(
            jarm=jarm_fp,
            title=f"C2 JARM Detection: {jarm_fp[:16]}...",
        )
        rules.append(rule)
    if ips:
        ip_list = [i.strip() for i in ips.split(",")]
        rule = sigma_gen.c2_ip_rule(
            ips=ip_list,
            title="Discovered C2 Infrastructure",
        )
        rules.append(rule)

    if not rules:
        console.print("[yellow]No fingerprints provided. Use --jarm or --ips")
        return

    paths = sigma_gen.save_rules(rules, output)
    for path in paths:
        console.print(f"[green]Saved: {path}")
        console.print(Syntax(path.read_text(), "yaml"))


# ── API server ────────────────────────────────────────────────────────────────

@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8000, help="Bind port"),
    reload: bool = typer.Option(False, help="Enable hot reload (dev mode)"),
):
    """Start the adversary-intel REST API server."""
    import uvicorn
    console.print(Panel(f"[bold]adversary-intel API[/bold]\nListening on http://{host}:{port}\nDocs: http://{host}:{port}/docs", style="green"))
    uvicorn.run("adversary_intel.api.main:app", host=host, port=port, reload=reload)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_seed_type(value: str, hint: str = "auto") -> "NodeType":
    from adversary_intel.models import NodeType
    if hint != "auto":
        return NodeType(hint)
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return NodeType.IP
    except ValueError:
        pass
    if len(value) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in value):
        return NodeType.HASH
    return NodeType.DOMAIN


if __name__ == "__main__":
    app()
