"""Discovery engine — orchestrates all modules in 6 phases.

Phase 1: Company Intel (LLM) — discover domains, subsidiaries, dorks
Phase 2: DNS + Subdomains — DNS records, subdomain enumeration
Phase 3: HTTP Probe — probe all discovered hosts
Phase 4: Port Scan — nmap on discovered IPs
Phase 5: Cloud + Takeover — bucket enum, dangling CNAME check
Phase 6: Google Dorks — generate targeted search queries
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
    SubdomainTakeoverModule,
)
from surfacemap.discovery.http import HTTPProbeModule, PortScanModule

logger = logging.getLogger(__name__)
console = Console()


class DiscoveryEngine:
    """Orchestrates all discovery modules in a phased pipeline."""

    def __init__(self, target: str, domain: str | None = None) -> None:
        self.target = target
        self.domain = domain or target
        self.config = get_config()
        self.result = ScanResult(target=target)

    async def run(self) -> ScanResult:
        """Execute the full 6-phase discovery pipeline."""
        console.print(
            f"\n[bold cyan]SurfaceMap v1.0.0[/] — Attack Surface Discovery",
        )
        console.print(f"[dim]Target:[/] [bold]{self.target}[/]")
        console.print(f"[dim]Domain:[/] [bold]{self.domain}[/]")
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
                "[bold green]Discovery Pipeline", total=6
            )

            # Phase 1: Company Intel (LLM)
            progress.update(main_task, description="[bold yellow]Phase 1: Company Intel (LLM)")
            await self._phase_company_intel(progress)
            progress.advance(main_task)

            # Phase 2: DNS + Subdomains
            progress.update(main_task, description="[bold yellow]Phase 2: DNS + Subdomains")
            await self._phase_dns(progress)
            progress.advance(main_task)

            # Phase 3: HTTP Probe
            progress.update(main_task, description="[bold yellow]Phase 3: HTTP Probe")
            await self._phase_http(progress)
            progress.advance(main_task)

            # Phase 4: Port Scan
            progress.update(main_task, description="[bold yellow]Phase 4: Port Scan")
            await self._phase_portscan(progress)
            progress.advance(main_task)

            # Phase 5: Cloud + Takeover
            progress.update(main_task, description="[bold yellow]Phase 5: Cloud + Takeover")
            await self._phase_cloud_takeover(progress)
            progress.advance(main_task)

            # Phase 6: Google Dorks
            progress.update(main_task, description="[bold yellow]Phase 6: Google Dorks")
            await self._phase_dorks(progress)
            progress.advance(main_task)

            progress.update(main_task, description="[bold green]Complete")

        self.result.mark_complete()
        return self.result

    async def _run_module(
        self, module: DiscoveryModule, progress: Progress
    ) -> bool:
        """Run a single discovery module with progress tracking."""
        task = progress.add_task(
            f"  [dim]{module.name}[/]", total=1
        )
        success = await module.safe_discover(self.domain, self.result)
        progress.advance(task)
        status = "[green]done[/]" if success else "[red]failed[/]"
        progress.update(task, description=f"  [dim]{module.name}[/] {status}")
        return success

    async def _phase_company_intel(self, progress: Progress) -> None:
        """Phase 1: Use LLM to gather company intelligence."""
        if not self.config.has_llm:
            console.print("  [dim]Skipping LLM phase (no API key configured)[/]")
            return

        task = progress.add_task("  [dim]LLM Company Intel[/]", total=3)

        try:
            brain = LLMBrain()

            # Discover additional domains
            domains = brain.discover_company_domains(self.target)
            for d in domains:
                domain_val = d.get("domain", "")
                if domain_val and domain_val != self.domain:
                    self.result.add_asset(Asset(
                        value=domain_val,
                        type=AssetType.DOMAIN,
                        source="llm-intel",
                        metadata={
                            "confidence": d.get("confidence", "unknown"),
                            "purpose": d.get("purpose", ""),
                        },
                    ))
            progress.advance(task)

            # Discover subsidiaries
            subsidiaries = brain.discover_subsidiaries(self.target)
            for s in subsidiaries:
                name = s.get("name", "")
                if name:
                    self.result.add_asset(Asset(
                        value=name,
                        type=AssetType.SUBSIDIARY,
                        source="llm-intel",
                        metadata={
                            "domain": s.get("domain", ""),
                            "relationship": s.get("relationship", ""),
                            "confidence": s.get("confidence", "unknown"),
                        },
                    ))
                    # Also add the subsidiary's domain if known
                    sub_domain = s.get("domain", "")
                    if sub_domain:
                        self.result.add_asset(Asset(
                            value=sub_domain,
                            type=AssetType.DOMAIN,
                            source="llm-subsidiary",
                            parent=name,
                        ))
            progress.advance(task)

            progress.advance(task)
            progress.update(task, description="  [dim]LLM Company Intel[/] [green]done[/]")

        except Exception as e:
            logger.warning("LLM company intel phase failed: %s", e)
            progress.update(task, description="  [dim]LLM Company Intel[/] [red]failed[/]")

    async def _phase_dns(self, progress: Progress) -> None:
        """Phase 2: DNS enumeration and subdomain discovery."""
        # Run DNS on primary domain
        await self._run_module(DNSModule(), progress)

        # Run subdomain discovery on primary domain
        await self._run_module(SubdomainModule(), progress)

        # Also enumerate DNS for any LLM-discovered domains
        extra_domains = [
            a for a in self.result.get_by_type(AssetType.DOMAIN)
            if a.value != self.domain and a.source in ("llm-intel", "llm-subsidiary")
        ]
        for domain_asset in extra_domains[:5]:  # Limit to prevent runaway
            original_domain = self.domain
            self.domain = domain_asset.value
            await self._run_module(DNSModule(), progress)
            self.domain = original_domain

    async def _phase_http(self, progress: Progress) -> None:
        """Phase 3: HTTP probing of all discovered hosts."""
        await self._run_module(HTTPProbeModule(), progress)

    async def _phase_portscan(self, progress: Progress) -> None:
        """Phase 4: Port scanning of discovered IPs."""
        await self._run_module(PortScanModule(), progress)

    async def _phase_cloud_takeover(self, progress: Progress) -> None:
        """Phase 5: Cloud bucket enumeration and subdomain takeover checks."""
        await self._run_module(CloudDiscoveryModule(), progress)
        await self._run_module(SubdomainTakeoverModule(), progress)

    async def _phase_dorks(self, progress: Progress) -> None:
        """Phase 6: Generate Google dork queries."""
        if not self.config.has_llm:
            console.print("  [dim]Skipping dorks phase (no API key configured)[/]")
            return

        task = progress.add_task("  [dim]Google Dorks[/]", total=1)
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
            progress.advance(task)
            progress.update(task, description="  [dim]Google Dorks[/] [green]done[/]")
        except Exception as e:
            logger.warning("Google dorks phase failed: %s", e)
            progress.update(task, description="  [dim]Google Dorks[/] [red]failed[/]")
