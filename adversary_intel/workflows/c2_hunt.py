"""
End-to-end C2 infrastructure hunting workflow.

Implements the full pivot chain from the ThreatSignal article:
  seed indicator
  → JARM fingerprint
  → Shodan JARM pivot (34 IPs → filter CDN → 19 candidates)
  → VT cross-reference (flag known → isolate unreported)
  → TLS cert pivot (cluster confirmation)
  → pDNS batch activation detection
  → WHOIS nameserver clustering
  → Sigma + Nuclei rule generation
  → Infrastructure graph export

All pivots are optional — the workflow gracefully skips steps where
API keys are not configured.
"""
from __future__ import annotations

import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from adversary_intel.config import settings
from adversary_intel.core import jarm as jarm_module
from adversary_intel.core import tls_cert, favicon, http_fp, passive_dns
from adversary_intel.detection import sigma as sigma_gen, nuclei as nuclei_gen
from adversary_intel.graph.infra_graph import InfraGraph
from adversary_intel.intel import asn as asn_module, virustotal
from adversary_intel.models import EdgeType, HuntResult, NodeType

console = Console()


class C2Hunter:
    def __init__(
        self,
        output_dir: Path = Path("./output"),
        max_pivot_depth: int | None = None,
    ):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.max_depth = max_pivot_depth or settings.max_pivot_depth
        self.graph = InfraGraph()
        self._pdns = passive_dns.PassiveDNSClient()

        # Lazy-init API clients based on configured keys
        self._shodan = None
        self._censys = None
        self._vt = None

    def _get_shodan(self):
        if self._shodan is None and settings.shodan_api_key:
            from adversary_intel.scanning.shodan import ShodanClient
            self._shodan = ShodanClient()
        return self._shodan

    def _get_censys(self):
        if self._censys is None and settings.censys_api_id:
            from adversary_intel.scanning.censys import CensysClient
            self._censys = CensysClient()
        return self._censys

    def _get_vt(self):
        if self._vt is None and settings.virustotal_api_key:
            self._vt = virustotal.VirusTotalClient()
        return self._vt

    # ── Main hunt ─────────────────────────────────────────────────────────────

    def hunt(self, seed: str, seed_type: NodeType = NodeType.IP) -> HuntResult:
        """
        Full end-to-end infrastructure hunt from a single seed indicator.

        Usage:
            hunter = C2Hunter()
            result = hunter.hunt("45.142.212.31", NodeType.IP)
        """
        start_time = time.time()
        result = HuntResult(seed=seed)
        errors: list[str] = []

        console.rule(f"[bold red]Infrastructure Hunt: {seed}")

        # ── Step 1: Add seed to graph ─────────────────────────────────────────
        if seed_type == NodeType.IP:
            seed_id = self.graph.add_ip(seed, reported=True, confidence=90)
        elif seed_type == NodeType.DOMAIN:
            seed_id = self.graph.add_domain(seed, reported=True, confidence=90)
        elif seed_type == NodeType.HASH:
            seed_id = self.graph.add_hash(seed)
        else:
            seed_id = f"unknown:{seed}"

        # ── Step 1b: Hash → C2 IP (via VT sandbox) ────────────────────────────
        if seed_type == NodeType.HASH:
            console.print("[cyan]Step 1: Extracting C2 from malware sandbox behavior...")
            c2_ips = self._vt_extract_c2(seed, errors)
            for ip in c2_ips:
                ip_id = self.graph.add_ip(ip, confidence=85)
                self.graph.link(seed_id, ip_id, EdgeType.CONTAINS, confidence=85)
            if c2_ips:
                console.print(f"  [green]Found {len(c2_ips)} C2 IPs from sandbox analysis")
                # Continue hunt from first C2 IP
                ip_result = self.hunt(c2_ips[0], NodeType.IP)
                result.nodes.extend(ip_result.nodes)
                result.edges.extend(ip_result.edges)

        # ── Step 2: JARM fingerprinting ───────────────────────────────────────
        console.print("[cyan]Step 2: JARM fingerprinting...")
        jarm_result = self._fingerprint_jarm(seed if seed_type == NodeType.IP else seed, errors)
        jarm_hash: Optional[str] = None
        if jarm_result:
            jarm_hash = jarm_result.fingerprint
            # Update node metadata
            if seed_id in self.graph._g:
                self.graph._g.nodes[seed_id]["meta"]["jarm"] = jarm_hash
            c2_name = jarm_module.classify(jarm_hash)
            if c2_name:
                console.print(f"  [red]C2 framework identified: [bold]{c2_name}")
            console.print(f"  JARM: {jarm_hash}")

        # ── Step 3: JARM pivot on Shodan ──────────────────────────────────────
        pivot_ips: list[str] = []
        if jarm_hash:
            console.print("[cyan]Step 3: JARM pivot on Shodan...")
            pivot_ips = self._shodan_jarm_pivot(jarm_hash, seed, errors)
            console.print(f"  Found {len(pivot_ips)} IPs sharing JARM fingerprint")
            for ip in pivot_ips:
                ip_id = self.graph.add_ip(ip, confidence=75)
                if jarm_hash:
                    self.graph._g.nodes[ip_id]["meta"]["jarm"] = jarm_hash
                self.graph.link(seed_id, ip_id, EdgeType.SHARES_JARM, confidence=75, jarm=jarm_hash)

        # ── Step 4: VT reputation cross-reference ─────────────────────────────
        console.print("[cyan]Step 4: Cross-referencing against VirusTotal...")
        known_ips, unknown_ips = self._vt_crossref(pivot_ips or [seed], errors)
        console.print(f"  [yellow]{len(known_ips)} known in VT, [green]{len(unknown_ips)} previously unreported")

        for ip in unknown_ips:
            ip_id = f"ip:{ip}"
            if ip_id in self.graph._g:
                self.graph._g.nodes[ip_id]["reported"] = False
                self.graph._g.nodes[ip_id]["confidence"] = 80

        result.unreported_nodes = len(unknown_ips)

        # ── Step 5: TLS cert pivot ─────────────────────────────────────────────
        console.print("[cyan]Step 5: TLS certificate cluster analysis...")
        cert_clusters = self._cert_pivot(pivot_ips or [seed], seed_id, errors)
        if cert_clusters:
            console.print(f"  [green]{len(cert_clusters)} certificate template clusters found")
            result.cert_clusters = cert_clusters

        # ── Step 6: Favicon hash ─────────────────────────────────────────────
        console.print("[cyan]Step 6: Favicon hash fingerprinting...")
        fav_result = self._favicon_check(seed, errors)
        if fav_result:
            console.print(f"  Favicon hash: {fav_result.hash_mmh3}")
            known_panel = favicon.classify(fav_result.hash_mmh3)
            if known_panel:
                console.print(f"  [red]Matches known panel: {known_panel}")

        # ── Step 7: Passive DNS batch activation ──────────────────────────────
        console.print("[cyan]Step 7: Passive DNS batch activation analysis...")
        batch_clusters = self._pdns_analysis(unknown_ips or pivot_ips, errors)
        if batch_clusters:
            console.print(f"  [green]{len(batch_clusters)} batch activation clusters detected")
            result.pdns_batch_activations = [
                {"ips": [r.answer for r in cluster], "window": "48h"}
                for cluster in batch_clusters
            ]

        # ── Step 8: WHOIS nameserver clustering ───────────────────────────────
        console.print("[cyan]Step 8: WHOIS nameserver clustering...")
        all_domains = self.graph.get_domains()
        ns_clusters = self._whois_analysis(all_domains, errors)
        if ns_clusters:
            console.print(f"  [green]{len(ns_clusters)} nameserver clusters found")

        # ── Step 9: ASN analysis ──────────────────────────────────────────────
        console.print("[cyan]Step 9: ASN hosting provider analysis...")
        all_ips = self.graph.get_ips()
        self._asn_analysis(all_ips, errors)

        # ── Step 10: Generate detection rules ─────────────────────────────────
        console.print("[cyan]Step 10: Generating detection rules...")
        sigma_rules, nuclei_templates = self._generate_rules(jarm_hash, unknown_ips, errors)
        result.sigma_rules = sigma_rules
        result.nuclei_templates = nuclei_templates

        # ── Finalize ──────────────────────────────────────────────────────────
        stats = self.graph.stats()
        result.nodes_discovered = stats["total_nodes"]
        result.edges_discovered = stats["total_edges"]
        result.nodes = []
        result.edges = []
        result.jarm_clusters = self.graph.find_jarm_clusters()
        result.errors = errors
        result.duration_seconds = time.time() - start_time

        # Save graph
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        graph_path = self.output_dir / f"hunt_{ts}.json"
        self.graph.save_json(graph_path)
        self.graph.try_interactive_html(self.output_dir / f"hunt_{ts}.html")

        self._print_summary(result, jarm_hash)
        return result

    # ── Internal pivot methods ────────────────────────────────────────────────

    def _fingerprint_jarm(self, host: str, errors: list) -> Optional[object]:
        try:
            return jarm_module.fingerprint(host, port=443)
        except Exception as e:
            errors.append(f"JARM fingerprinting failed for {host}: {e}")
            return None

    def _shodan_jarm_pivot(self, jarm_hash: str, seed: str, errors: list) -> list[str]:
        shodan = self._get_shodan()
        if not shodan:
            console.print("  [dim]Shodan not configured — skipping JARM pivot")
            return []
        try:
            results = shodan.pivot_jarm(jarm_hash, limit=100)
            all_ips = [r["ip"] for r in results if r.get("ip") and r["ip"] != seed]
            # Filter CDN ASNs
            filtered = shodan.filter_cdn_asns(results)
            filtered_ips = [r["ip"] for r in filtered if r.get("ip") and r["ip"] != seed]
            console.print(f"  Shodan: {len(all_ips)} raw → {len(filtered_ips)} after CDN filter")
            return filtered_ips
        except Exception as e:
            errors.append(f"Shodan JARM pivot failed: {e}")
            return []

    def _vt_crossref(self, ips: list[str], errors: list) -> tuple[list[str], list[str]]:
        vt = self._get_vt()
        if not vt:
            return [], ips
        known, unknown = [], []
        for ip in ips:
            try:
                is_mal, count = vt.is_malicious(ip)
                if is_mal or count > 0:
                    known.append(ip)
                    ip_id = f"ip:{ip}"
                    if ip_id in self.graph._g:
                        self.graph._g.nodes[ip_id]["reported"] = True
                        self.graph._g.nodes[ip_id]["meta"]["vt_detections"] = count
                else:
                    unknown.append(ip)
            except Exception as e:
                errors.append(f"VT check failed for {ip}: {e}")
                unknown.append(ip)
        return known, unknown

    def _cert_pivot(self, ips: list[str], seed_id: str, errors: list) -> dict[str, list[str]]:
        clusters: dict[str, list[str]] = {}
        for ip in ips[:20]:  # limit to avoid excessive TLS connections
            try:
                cert = tls_cert.fetch(ip, port=443)
                if not cert:
                    continue
                cert_id = self.graph.add_cert(
                    cert.sha1_fingerprint or cert.sha256_fingerprint or ip,
                    subject_cn=cert.subject_cn or "",
                )
                ip_id = self.graph.add_ip(ip)
                self.graph.link(ip_id, cert_id, EdgeType.SHARES_CERT, confidence=90)

                # CN-based clustering (same subject CN = same deployment template)
                if cert.subject_cn:
                    clusters.setdefault(cert.subject_cn, []).append(ip)

                # Flag suspicious certs
                reasons = tls_cert.is_suspicious(cert)
                if reasons:
                    self.graph._g.nodes[ip_id]["meta"]["cert_suspicious"] = reasons
            except Exception as e:
                errors.append(f"Cert analysis failed for {ip}: {e}")

        return {k: v for k, v in clusters.items() if len(v) > 1}

    def _favicon_check(self, host: str, errors: list) -> Optional[object]:
        try:
            return favicon.fetch(host)
        except Exception as e:
            errors.append(f"Favicon check failed: {e}")
            return None

    def _pdns_analysis(self, ips: list[str], errors: list) -> list[list]:
        batch_clusters = []
        for ip in ips[:10]:  # throttle pDNS calls
            try:
                records = self._pdns.ip_history(ip)
                for rec in records:
                    if rec.answer:
                        domain_id = self.graph.add_domain(rec.answer, confidence=70)
                        ip_id = self.graph.add_ip(ip)
                        self.graph.link(domain_id, ip_id, EdgeType.RESOLVES_TO, confidence=70)

                clusters = self._pdns.find_batch_activation(records)
                batch_clusters.extend(clusters)
            except Exception as e:
                errors.append(f"pDNS analysis failed for {ip}: {e}")
        return batch_clusters

    def _whois_analysis(self, domains: list[str], errors: list) -> dict:
        if not domains:
            return {}
        try:
            from adversary_intel.intel.whois import find_nameserver_cluster
            clusters = find_nameserver_cluster(domains[:20])  # throttle WHOIS calls
            for ns_key, clustered_domains in clusters.items():
                ns_id = self.graph.add_node.__func__  # type hint workaround
                for domain in clustered_domains:
                    domain_id = f"domain:{domain}"
                    ns_node_id = f"nameserver:{ns_key}"
                    if domain_id in self.graph._g:
                        self.graph.link(domain_id, ns_node_id, EdgeType.USES_NAMESERVER)
            return clusters
        except Exception as e:
            errors.append(f"WHOIS analysis failed: {e}")
            return {}

    def _asn_analysis(self, ips: list[str], errors: list) -> None:
        for ip in ips[:20]:
            try:
                info = asn_module.lookup(ip)
                if not info:
                    continue
                asn_id = self.graph.add_asn(
                    info.asn,
                    name=info.asn_name or "",
                    is_bulletproof=info.is_bulletproof,
                )
                ip_id = f"ip:{ip}"
                if ip_id in self.graph._g:
                    self.graph.link(ip_id, asn_id, EdgeType.HOSTED_ON)
                    if info.is_bulletproof:
                        console.print(f"  [red]Bulletproof ASN detected: {info.asn} ({info.asn_name})")
            except Exception as e:
                errors.append(f"ASN lookup failed for {ip}: {e}")

    def _vt_extract_c2(self, sha256: str, errors: list) -> list[str]:
        vt = self._get_vt()
        if not vt:
            return []
        try:
            return vt.extract_c2_from_behavior(sha256)
        except Exception as e:
            errors.append(f"VT C2 extraction failed: {e}")
            return []

    def _generate_rules(
        self,
        jarm_hash: Optional[str],
        unreported_ips: list[str],
        errors: list,
    ) -> tuple[list[str], list[str]]:
        sigma_rules: list[str] = []
        nuclei_templates_list: list[str] = []
        rules_dir = settings.rules_output_dir

        try:
            if jarm_hash:
                c2_name = jarm_module.classify(jarm_hash) or "Unknown C2"
                rule = sigma_gen.jarm_rule(
                    jarm=jarm_hash,
                    title=f"{c2_name} C2 JARM Detection",
                    severity="critical",
                )
                sigma_rules.append(rule)
                sigma_gen.save_rules([rule], rules_dir / "sigma", prefix="jarm_rule")

                tpl = nuclei_gen.custom_jarm_template(
                    template_id=f"c2-jarm-{jarm_hash[:8]}",
                    name=f"{c2_name} Detection",
                    jarm=jarm_hash,
                )
                nuclei_templates_list.append(tpl)
                nuclei_gen.save_template(tpl, rules_dir / "nuclei", f"c2_jarm_{jarm_hash[:8]}.yaml")

            if unreported_ips:
                ip_rule = sigma_gen.c2_ip_rule(
                    ips=unreported_ips[:50],
                    title="Discovered C2 Infrastructure — Unreported IPs",
                    severity="critical",
                )
                sigma_rules.append(ip_rule)
                sigma_gen.save_rules([ip_rule], rules_dir / "sigma", prefix="c2_ips")
        except Exception as e:
            errors.append(f"Rule generation failed: {e}")

        return sigma_rules, nuclei_templates_list

    # ── Summary output ────────────────────────────────────────────────────────

    def _print_summary(self, result: HuntResult, jarm: Optional[str]) -> None:
        console.rule("[bold green]Hunt Summary")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Seed", result.seed)
        table.add_row("Duration", f"{result.duration_seconds:.1f}s")
        table.add_row("Total nodes", str(result.nodes_discovered))
        table.add_row("Total edges", str(result.edges_discovered))
        table.add_row("Unreported nodes", f"[green]{result.unreported_nodes}")
        table.add_row("JARM", jarm or "N/A")
        table.add_row("Cert clusters", str(len(result.cert_clusters)))
        table.add_row("pDNS batch clusters", str(len(result.pdns_batch_activations)))
        table.add_row("Sigma rules generated", str(len(result.sigma_rules)))
        table.add_row("Nuclei templates", str(len(result.nuclei_templates)))
        if result.errors:
            table.add_row("[red]Errors", str(len(result.errors)))

        console.print(table)

        if result.unreported_nodes > 0:
            console.print(
                f"\n[bold green]High-value find: {result.unreported_nodes} previously unreported "
                f"C2 nodes identified. Rules saved to {settings.rules_output_dir}"
            )
