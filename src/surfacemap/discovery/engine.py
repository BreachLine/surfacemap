"""Discovery engine — orchestrates all modules in a concurrent 4-phase pipeline.

Phase 0: LLM BRAINSTORM — deep intelligence gathering, seeds entire pipeline
Phase 1: PASSIVE RECON — DNS, subdomains, OSINT, enrichment (concurrent)
Phase 2: ACTIVE PROBING — HTTP, ports, SSL, cloud, active checks (concurrent)
Phase 3: LLM ANALYSIS — risk scoring, attack paths, executive summary (sequential)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)

from surfacemap import __version__
from surfacemap.core.config import get_config
from surfacemap.core.llm import LLMBrain
from surfacemap.core.models import (
    Asset,
    AssetType,
    ScanResult,
)
from surfacemap.discovery.base import DiscoveryModule
from surfacemap.discovery.dns import (
    CloudDiscoveryModule,
    DNSModule,
    SubdomainModule,
    SubdomainPermutationModule,
    SubdomainTakeoverModule,
)
from surfacemap.discovery.http import HTTPProbeModule, PortScanModule
from surfacemap.discovery.web import (
    AlienVaultURLModule,
    AnubisDBModule,
    CertSpotterModule,
    CertTransparencyModule,
    CommonCrawlModule,
    HackerTargetModule,
    IPInfoModule,
    RapidDNSModule,
    ReverseIPModule,
    SecurityTrailsModule,
    ShodanInternetDBModule,
    SubdomainCenterModule,
    URLScanModule,
    WaybackModule,
    WebTechModule,
)
from surfacemap.discovery.osint import (
    WHOISModule,
    ASNModule,
    ReverseDNSModule,
    SSLAnalysisModule,
    DNSZoneTransferModule,
    EmailSecurityModule,
)
from surfacemap.discovery.active import (
    SensitivePathModule,
    JSAnalysisModule,
    CORSCheckModule,
    CookieSecurityModule,
)
from surfacemap.discovery.enrichment import (
    VirusTotalModule,
    ShodanModule,
    GitHubDorkModule,
    EmailHarvestModule,
)
from surfacemap.discovery.external_apis import (
    CensysModule,
    BinaryEdgeModule,
    FullHuntModule,
    PassiveTotalModule,
    ONYPHEModule,
    GreyNoiseModule,
    FOFAModule,
    LeakIXModule,
    IntelXModule,
    VulnersModule,
    PulsediveModule,
    ZoomEyeModule,
)
from surfacemap.discovery.crawler import WebCrawlerModule
from surfacemap.discovery.nuclei import NucleiModule
from surfacemap.discovery.screenshot import ScreenshotModule
from surfacemap.analysis.risk import RiskScorer, FalsePositiveFilter
from surfacemap.analysis.narrative import AttackPathAnalysis, ExecutiveSummary

logger = logging.getLogger(__name__)
console = Console()

# Total number of macro-phases in the pipeline
_TOTAL_PHASES = 4


class DiscoveryEngine:
    """Orchestrates all discovery modules in a concurrent 3-phase pipeline."""

    def __init__(
        self,
        target: str,
        domain: str | None = None,
        enrich: bool = False,
        passive_only: bool = False,
        skip_analysis: bool = False,
    ) -> None:
        self.target = target
        self.domain = domain or target
        self.config = get_config()
        self.result = ScanResult(target=target)
        self.enrich = enrich
        self.passive_only = passive_only
        self.skip_analysis = skip_analysis

    async def run(self) -> ScanResult:
        """Execute the full discovery pipeline."""
        from datetime import datetime, timezone

        # Count modules
        passive_count = 15  # base passive modules
        active_count = 14   # base active modules
        if self.enrich:
            if self.config.has_virustotal:
                passive_count += 1
            if self.config.has_github:
                passive_count += 1
            if self.config.has_shodan:
                active_count += 1
        total_modules = passive_count + active_count

        mode = "Passive Only" if self.passive_only else "Full Scan"
        if self.enrich:
            mode += " + Enrichment"

        console.print()
        console.print("[bold cyan]  ____              __                __  __           [/]")
        console.print("[bold cyan] / ___| _   _ _ __ / _| __ _  ___ ___|  \\/  | __ _ _ __ [/]")
        console.print("[bold cyan] \\___ \\| | | | '__| |_ / _` |/ __/ _ \\ |\\/| |/ _` | '_ \\[/]")
        console.print("[bold cyan]  ___) | |_| | |  |  _| (_| | (_|  __/ |  | | (_| | |_) |[/]")
        console.print("[bold cyan] |____/ \\__,_|_|  |_|  \\__,_|\\___\\___|_|  |_|\\__,_| .__/[/]")
        console.print(f"[bold cyan]                                                  |_|   [/] [bold white]v{__version__}[/]")
        console.print()
        console.print(f"  [dim]BreachLine Labs[/] [dim]|[/] [dim]LLM-Driven Attack Surface Discovery[/]")
        console.print(f"  [dim]github.com/BreachLine/surfacemap[/]")
        console.print()
        console.print(f"  [bold]Target:[/]   {self.target}")
        console.print(f"  [bold]Domain:[/]   {self.domain}")
        console.print(f"  [bold]Mode:[/]     {mode}")
        console.print(f"  [bold]LLM:[/]      {'[green]' + self.config.llm_model + '[/]' if self.config.has_llm else '[red]disabled (set GEMINI_API_KEY)[/]'}")
        console.print(f"  [bold]Modules:[/]  {total_modules} data sources across {_TOTAL_PHASES} phases")
        console.print(f"  [bold]Started:[/]  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        console.print(f"  [dim]Estimated time: 10-20 min (depends on target size and API availability)[/]")
        console.print()

        # Add the primary domain as the root asset
        self.result.add_asset(Asset(
            value=self.domain,
            type=AssetType.DOMAIN,
            source="user-input",
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            main_task = progress.add_task(
                "[bold green]Discovery Pipeline", total=_TOTAL_PHASES
            )

            # ── Phase 0: LLM BRAINSTORM ─────────────────────────────
            progress.update(
                main_task,
                description="[bold yellow]Phase 0: LLM Brainstorm",
            )
            await self._phase_brainstorm(progress)
            progress.advance(main_task)

            # ── Macro-Phase 1: PASSIVE RECON ──────────────────────────
            progress.update(
                main_task,
                description="[bold yellow]Phase 1: Passive Recon",
            )
            await self._macro_phase_passive(progress)
            progress.advance(main_task)

            # ── Macro-Phase 2: ACTIVE PROBING ─────────────────────────
            if not self.passive_only:
                progress.update(
                    main_task,
                    description="[bold yellow]Phase 2: Active Probing",
                )
                await self._macro_phase_active(progress)
            else:
                console.print("  [dim]Skipping active probing (--passive-only)[/]")
            progress.advance(main_task)

            # ── Macro-Phase 3: LLM ANALYSIS ──────────────────────────
            if not self.skip_analysis:
                progress.update(
                    main_task,
                    description="[bold yellow]Phase 3: LLM Analysis",
                )
                await self._macro_phase_analysis(progress)
            else:
                console.print("  [dim]Skipping analysis (--no-analysis)[/]")
            progress.advance(main_task)

            progress.update(main_task, description="[bold green]Complete")

        self.result.mark_complete()
        return self.result

    # ── helpers ────────────────────────────────────────────────────────

    async def _run_modules_concurrent(
        self,
        modules: list[DiscoveryModule],
        progress: Progress,
        phase_task: Any,
    ) -> None:
        """Run a list of discovery modules concurrently with progress tracking."""

        async def run_one(module: DiscoveryModule) -> None:
            task = progress.add_task(f"  [dim]{module.name}[/]", total=1)
            success = await module.safe_discover(self.domain, self.result)
            progress.advance(task)
            status = "[green]done[/]" if success else "[red]failed[/]"
            progress.update(
                task, description=f"  [dim]{module.name}[/] {status}"
            )

        await asyncio.gather(*[run_one(m) for m in modules])

    # ── Phase 0: LLM BRAINSTORM ──────────────────────────────────────

    async def _phase_brainstorm(self, progress: Progress) -> None:
        """Phase 0: Deep LLM brainstorming to seed the entire pipeline.

        Uses two focused LLM calls to avoid truncation:
        1. Domains, subsidiaries, acquisitions, geography
        2. Infrastructure, tech stack, services, cloud, socials
        """
        if not self.config.has_llm:
            console.print("  [dim]Skipping brainstorm (no LLM key configured)[/]")
            return

        task = progress.add_task("  [dim]LLM Brainstorm[/]", total=2)

        try:
            brain = LLMBrain()

            # Call 1: Domains & subsidiaries (most critical)
            intel_domains = brain.brainstorm_domains_and_subsidiaries(
                self.target, self.domain
            )
            progress.advance(task)

            # Call 2: Infrastructure & tech (supplementary)
            intel_infra = brain.brainstorm_infrastructure(
                self.target, self.domain
            )
            progress.advance(task)

            # Merge both results
            intel: dict[str, Any] = {}
            if isinstance(intel_domains, dict):
                intel.update(intel_domains)
            if isinstance(intel_infra, dict):
                intel.update(intel_infra)

            if not intel:
                progress.update(task, description="  [dim]LLM Brainstorm[/] [red]no data[/]")
                return

            # ── Seed domains ──
            for d in intel.get("domains", []):
                domain_val = d.get("domain", "")
                confidence = d.get("confidence", "unknown").lower()
                # Only seed high/medium confidence domains to reduce false positives
                if domain_val and domain_val != self.domain and confidence in ("high", "medium"):
                    self.result.add_asset(Asset(
                        value=domain_val,
                        type=AssetType.DOMAIN,
                        source="llm-brainstorm",
                        metadata={
                            "confidence": confidence,
                            "purpose": d.get("purpose", ""),
                        },
                    ))

            # ── Seed subsidiaries ──
            for s in intel.get("subsidiaries", []):
                name = s.get("name", "")
                if name:
                    self.result.add_asset(Asset(
                        value=name,
                        type=AssetType.SUBSIDIARY,
                        source="llm-brainstorm",
                        metadata={
                            "domain": s.get("domain", ""),
                            "relationship": s.get("relationship", ""),
                            "confidence": s.get("confidence", "unknown"),
                        },
                    ))
                    sub_domain = s.get("domain", "")
                    if sub_domain:
                        self.result.add_asset(Asset(
                            value=sub_domain,
                            type=AssetType.DOMAIN,
                            source="llm-subsidiary",
                            parent=name,
                        ))

            # ── Seed acquisition domains ──
            for acq in intel.get("acquisition_history", []):
                acq_domain = acq.get("domain", "")
                if acq_domain:
                    self.result.add_asset(Asset(
                        value=acq_domain,
                        type=AssetType.DOMAIN,
                        source="llm-acquisition",
                        metadata={
                            "company": acq.get("company", ""),
                            "year": acq.get("year", ""),
                            "status": acq.get("status", ""),
                        },
                    ))

            # Note: cloud_infrastructure from brainstorm is NOT seeded as assets.
            # LLM-guessed bucket names are unverified — CloudDiscoveryModule
            # will check real buckets via HTTP HEAD requests.

            # ── Seed known IP ranges ──
            for ip_info in intel.get("known_ip_ranges", []):
                ip_range = ip_info.get("range", "")
                if ip_range:
                    self.result.add_asset(Asset(
                        value=ip_range,
                        type=AssetType.IP_RANGE,
                        source="llm-brainstorm",
                        metadata={
                            "purpose": ip_info.get("purpose", ""),
                            "source_info": ip_info.get("source", ""),
                        },
                    ))

            # ── Seed social profiles ──
            for profile in intel.get("social_profiles", []):
                url = profile.get("url", "")
                if url:
                    self.result.add_asset(Asset(
                        value=url,
                        type=AssetType.SOCIAL_MEDIA,
                        source="llm-brainstorm",
                        metadata={
                            "platform": profile.get("platform", ""),
                            "handle": profile.get("handle", ""),
                        },
                    ))

            # ── Seed technology stack ──
            for tech in intel.get("technology_stack", []):
                tech_name = tech.get("technology", "")
                if tech_name:
                    self.result.add_asset(Asset(
                        value=tech_name,
                        type=AssetType.TECHNOLOGY,
                        source="llm-brainstorm",
                        metadata={
                            "category": tech.get("category", ""),
                            "confidence": tech.get("confidence", ""),
                        },
                    ))

            # ── Seed known services as likely subdomains ──
            for svc in intel.get("known_services", []):
                for sub in svc.get("likely_subdomains", []):
                    fqdn = f"{sub}.{self.domain}"
                    self.result.add_asset(Asset(
                        value=fqdn,
                        type=AssetType.SUBDOMAIN,
                        source="llm-brainstorm",
                        metadata={"service": svc.get("service", "")},
                    ))

            # ── Seed geographic domains ──
            for geo in intel.get("geographic_presence", []):
                for geo_domain in geo.get("likely_domains", []):
                    if geo_domain:
                        self.result.add_asset(Asset(
                            value=geo_domain,
                            type=AssetType.SUBDOMAIN if "." in geo_domain and geo_domain.endswith(self.domain) else AssetType.DOMAIN,
                            source="llm-brainstorm",
                            metadata={"region": geo.get("region", "")},
                        ))

            # ── Seed email patterns ──
            for ep in intel.get("email_patterns", []):
                pattern = ep.get("pattern", "")
                if pattern:
                    self.result.add_asset(Asset(
                        value=pattern,
                        type=AssetType.EMAIL,
                        source="llm-brainstorm",
                        metadata={"type": "pattern", "confidence": ep.get("confidence", "")},
                    ))

            brainstorm_count = len(self.result.assets) - 1  # minus root domain
            logger.info("[Brainstorm] Seeded %d assets from LLM intelligence", brainstorm_count)

            progress.advance(task)
            progress.update(
                task,
                description=f"  [dim]LLM Brainstorm[/] [green]{brainstorm_count} assets seeded[/]",
            )

        except Exception as e:
            logger.warning("LLM brainstorm failed: %s", e)
            progress.advance(task)
            progress.update(task, description="  [dim]LLM Brainstorm[/] [red]failed[/]")

    # ── Macro-Phase 1: PASSIVE RECON ──────────────────────────────────

    async def _macro_phase_passive(self, progress: Progress) -> None:
        """Run all passive recon modules concurrently, then post-passive steps."""
        phase_task = progress.add_task(
            "  [dim]Passive Recon[/]", total=1
        )

        # Build the list of passive modules
        passive_modules: list[DiscoveryModule] = [
            DNSModule(),
            SubdomainModule(),
            CertTransparencyModule(),
            WaybackModule(),
            SecurityTrailsModule(),
            WHOISModule(),
            DNSZoneTransferModule(),
            EmailSecurityModule(),
            EmailHarvestModule(),
            HackerTargetModule(),
            URLScanModule(),
            RapidDNSModule(),
            CommonCrawlModule(),
            AnubisDBModule(),
            CertSpotterModule(),
            SubdomainCenterModule(),
            AlienVaultURLModule(),
        ]

        # Conditionally add enrichment modules (require API keys + --enrich flag)
        if self.enrich:
            if self.config.has_virustotal:
                passive_modules.append(VirusTotalModule())
            if self.config.has_github:
                passive_modules.append(GitHubDorkModule())
            if self.config.has_censys:
                passive_modules.append(CensysModule())
            if self.config.has_binaryedge:
                passive_modules.append(BinaryEdgeModule())
            if self.config.has_fullhunt:
                passive_modules.append(FullHuntModule())
            if self.config.has_passivetotal:
                passive_modules.append(PassiveTotalModule())
            if self.config.has_onyphe:
                passive_modules.append(ONYPHEModule())
            if self.config.has_fofa:
                passive_modules.append(FOFAModule())
            if self.config.has_leakix:
                passive_modules.append(LeakIXModule())
            if self.config.has_intelx:
                passive_modules.append(IntelXModule())
            if self.config.has_pulsedive:
                passive_modules.append(PulsediveModule())
            if self.config.has_zoomeye:
                passive_modules.append(ZoomEyeModule())

        from surfacemap.plugins.loader import load_plugins
        from surfacemap.plugins.registry import get_registry
        if self.config.enable_plugins:
            load_plugins()
            passive_modules.extend(get_registry().get_modules("passive"))

        # Run all passive modules concurrently
        # (LLM brainstorm already ran in Phase 0 and seeded domains/subsidiaries)
        await self._run_modules_concurrent(passive_modules, progress, phase_task)

        # ── Post-passive: deep recon on every subsidiary/extra domain ──

        extra_domains = [
            a for a in self.result.get_by_type(AssetType.DOMAIN)
            if a.value != self.domain
            and a.source in ("llm-intel", "llm-subsidiary", "llm-brainstorm", "llm-acquisition")
        ]

        if extra_domains:
            # Run DNS on each subsidiary concurrently (fast, lightweight)
            async def _recon_one(domain_val: str) -> None:
                task = progress.add_task(
                    f"  [dim]Recon ({domain_val})[/]", total=1
                )
                # Run DNS + subdomain + cert transparency concurrently per domain
                await asyncio.gather(
                    DNSModule().safe_discover(domain_val, self.result),
                    SubdomainModule().safe_discover(domain_val, self.result),
                    CertTransparencyModule().safe_discover(domain_val, self.result),
                )
                progress.advance(task)
                progress.update(
                    task,
                    description=f"  [dim]Recon ({domain_val})[/] [green]done[/]",
                )

            await asyncio.gather(*[
                _recon_one(a.value)
                for a in extra_domains[: self.config.max_extra_domains]
            ])

        # SubdomainPermutationModule and ASNModule need Phase 1 results
        post_passive_modules: list[DiscoveryModule] = [
            SubdomainPermutationModule(),
            ASNModule(),
        ]
        await self._run_modules_concurrent(
            post_passive_modules, progress, phase_task
        )

        progress.advance(phase_task)
        progress.update(
            phase_task, description="  [dim]Passive Recon[/] [green]done[/]"
        )

    # ── Macro-Phase 2: ACTIVE PROBING ─────────────────────────────────

    async def _macro_phase_active(self, progress: Progress) -> None:
        """Run all active probing modules concurrently."""
        phase_task = progress.add_task(
            "  [dim]Active Probing[/]", total=1
        )

        # Sub-phase 2a: probing, enumeration (these populate live hosts)
        active_modules: list[DiscoveryModule] = [
            HTTPProbeModule(),
            PortScanModule(),
            ReverseDNSModule(),
            SSLAnalysisModule(),
            SensitivePathModule(),
            JSAnalysisModule(),
            CORSCheckModule(),
            CookieSecurityModule(),
            CloudDiscoveryModule(),
            SubdomainTakeoverModule(),
            WebTechModule(),
            ReverseIPModule(),
            ShodanInternetDBModule(),
            IPInfoModule(),
        ]

        # Conditionally add Shodan if API key is configured and --enrich flag set
        if self.enrich and self.config.has_shodan:
            active_modules.append(ShodanModule())

        if self.config.enable_plugins:
            from surfacemap.plugins.loader import load_plugins
            from surfacemap.plugins.registry import get_registry
            load_plugins()
            active_modules.extend(get_registry().get_modules("active"))

        await self._run_modules_concurrent(
            active_modules, progress, phase_task
        )

        # Sub-phase 2b: these depend on live hosts from HTTP probe above
        post_probe_modules: list[DiscoveryModule] = [
            WebCrawlerModule(),
            NucleiModule(),
            ScreenshotModule(),
        ]
        if self.enrich and self.config.has_vulners:
            post_probe_modules.append(VulnersModule())
        if self.enrich and self.config.has_greynoise:
            post_probe_modules.append(GreyNoiseModule())
        await self._run_modules_concurrent(
            post_probe_modules, progress, phase_task
        )

        progress.advance(phase_task)
        progress.update(
            phase_task, description="  [dim]Active Probing[/] [green]done[/]"
        )

    # ── Macro-Phase 3: LLM ANALYSIS ──────────────────────────────────

    async def _macro_phase_analysis(self, progress: Progress) -> None:
        """Run LLM-powered analysis sequentially (each step depends on prior)."""
        if not self.config.has_llm:
            console.print(
                "  [dim]Skipping analysis phase (no API key configured)[/]"
            )
            return

        phase_task = progress.add_task(
            "  [dim]LLM Analysis[/]", total=5
        )

        # 1. False Positive Filter
        task_fp = progress.add_task(
            "  [dim]False Positive Filter[/]", total=1
        )
        try:
            await FalsePositiveFilter().filter(self.result)
            progress.advance(task_fp)
            progress.update(
                task_fp,
                description="  [dim]False Positive Filter[/] [green]done[/]",
            )
        except Exception as e:
            logger.warning("False positive filter failed: %s", e)
            progress.advance(task_fp)
            progress.update(
                task_fp,
                description="  [dim]False Positive Filter[/] [red]failed[/]",
            )
        progress.advance(phase_task)

        # 2. Risk Scorer
        task_rs = progress.add_task("  [dim]Risk Scorer[/]", total=1)
        try:
            await RiskScorer().score(self.result)
            progress.advance(task_rs)
            progress.update(
                task_rs,
                description="  [dim]Risk Scorer[/] [green]done[/]",
            )
        except Exception as e:
            logger.warning("Risk scoring failed: %s", e)
            progress.advance(task_rs)
            progress.update(
                task_rs,
                description="  [dim]Risk Scorer[/] [red]failed[/]",
            )
        progress.advance(phase_task)

        # 3. Attack Path Analysis
        task_ap = progress.add_task(
            "  [dim]Attack Path Analysis[/]", total=1
        )
        try:
            await AttackPathAnalysis().analyze(self.result)
            progress.advance(task_ap)
            progress.update(
                task_ap,
                description="  [dim]Attack Path Analysis[/] [green]done[/]",
            )
        except Exception as e:
            logger.warning("Attack path analysis failed: %s", e)
            progress.advance(task_ap)
            progress.update(
                task_ap,
                description="  [dim]Attack Path Analysis[/] [red]failed[/]",
            )
        progress.advance(phase_task)

        # 4. Executive Summary
        task_es = progress.add_task(
            "  [dim]Executive Summary[/]", total=1
        )
        try:
            await ExecutiveSummary().generate(self.result)
            progress.advance(task_es)
            progress.update(
                task_es,
                description="  [dim]Executive Summary[/] [green]done[/]",
            )
        except Exception as e:
            logger.warning("Executive summary failed: %s", e)
            progress.advance(task_es)
            progress.update(
                task_es,
                description="  [dim]Executive Summary[/] [red]failed[/]",
            )
        progress.advance(phase_task)

        # 5. Google Dorks
        task_dork = progress.add_task("  [dim]Google Dorks[/]", total=1)
        try:
            brain = LLMBrain()
            dorks = brain.generate_google_dorks(self.target, self.domain)
            for dork in dorks:
                query = dork.get("query", "")
                if query:
                    self.result.add_asset(Asset(
                        value=query,
                        type=AssetType.URL,
                        source="google-dork",
                        metadata={
                            "purpose": dork.get("purpose", ""),
                            "category": dork.get("category", ""),
                            "is_dork": True,
                        },
                    ))
            progress.advance(task_dork)
            progress.update(
                task_dork,
                description="  [dim]Google Dorks[/] [green]done[/]",
            )
        except Exception as e:
            logger.warning("Google dorks phase failed: %s", e)
            progress.advance(task_dork)
            progress.update(
                task_dork,
                description="  [dim]Google Dorks[/] [red]failed[/]",
            )
        progress.advance(phase_task)

        progress.update(
            phase_task, description="  [dim]LLM Analysis[/] [green]done[/]"
        )
