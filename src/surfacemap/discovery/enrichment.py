"""OSINT enrichment discovery modules.

Modules that query external APIs (VirusTotal, Shodan, GitHub, Hunter.io)
to enrich the attack surface with additional intelligence. Each module
gracefully skips if its API key is not configured.
"""

from __future__ import annotations

import asyncio
import logging
import re

import httpx

from surfacemap.core.config import get_config
from surfacemap.core.models import (
    Asset,
    AssetStatus,
    AssetType,
    ScanResult,
    Severity,
)
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. VirusTotal
# ---------------------------------------------------------------------------

class VirusTotalModule(DiscoveryModule):
    """Discover subdomains and IP resolution history via the VirusTotal API."""

    @property
    def name(self) -> str:
        return "VirusTotal"

    @property
    def description(self) -> str:
        return "Subdomain enumeration and IP resolution history via VirusTotal"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.virustotal_api_key:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"x-apikey": cfg.virustotal_api_key}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
            await self._fetch_subdomains(client, target, result, cfg)
            await asyncio.sleep(cfg.vt_rate_delay)
            await self._fetch_resolutions(client, target, result, cfg)

    async def _fetch_subdomains(
        self,
        client: httpx.AsyncClient,
        domain: str,
        result: ScanResult,
        cfg: object,
    ) -> None:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "[%s] Subdomain request failed (HTTP %d): %s",
                self.name, exc.response.status_code, exc,
            )
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Subdomain request error: %s", self.name, exc)
            return

        for item in data.get("data", []):
            subdomain = item.get("id", "")
            if subdomain:
                result.add_asset(Asset(
                    value=subdomain,
                    type=AssetType.SUBDOMAIN,
                    source=self.name,
                    parent=domain,
                ))

        logger.info(
            "[%s] Discovered %d subdomains for %s",
            self.name, len(data.get("data", [])), domain,
        )

    async def _fetch_resolutions(
        self,
        client: httpx.AsyncClient,
        domain: str,
        result: ScanResult,
        cfg: object,
    ) -> None:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions"
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "[%s] Resolutions request failed (HTTP %d): %s",
                self.name, exc.response.status_code, exc,
            )
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Resolutions request error: %s", self.name, exc)
            return

        seen_ips: set[str] = set()
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            ip = attrs.get("ip_address", "")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                result.add_asset(Asset(
                    value=ip,
                    type=AssetType.IP,
                    source=self.name,
                    parent=domain,
                    metadata={
                        "resolved_date": attrs.get("date", ""),
                        "host_name": attrs.get("host_name", domain),
                    },
                ))

        logger.info(
            "[%s] Discovered %d unique IPs from resolution history for %s",
            self.name, len(seen_ips), domain,
        )


# ---------------------------------------------------------------------------
# 2. Shodan
# ---------------------------------------------------------------------------

class ShodanModule(DiscoveryModule):
    """Enrich IP assets with open ports, services, and vulnerabilities via Shodan."""

    @property
    def name(self) -> str:
        return "Shodan"

    @property
    def description(self) -> str:
        return "Port/service enumeration and vulnerability data via Shodan"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.shodan_api_key:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        ip_assets = result.get_by_type(AssetType.IP)
        if not ip_assets:
            logger.info("[%s] No IP assets to enrich — skipping.", self.name)
            return

        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        async with httpx.AsyncClient(timeout=timeout) as client:
            for ip_asset in ip_assets:
                await self._enrich_ip(client, ip_asset, target, result, cfg)

    async def _enrich_ip(
        self,
        client: httpx.AsyncClient,
        ip_asset: Asset,
        target: str,
        result: ScanResult,
        cfg: object,
    ) -> None:
        ip = ip_asset.value
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": cfg.shodan_api_key}

        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "[%s] Host lookup failed for %s (HTTP %d): %s",
                self.name, ip, exc.response.status_code, exc,
            )
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Host lookup error for %s: %s", self.name, ip, exc)
            return

        # Enrich the existing IP asset with Shodan metadata
        ip_asset.metadata.update({
            "shodan_os": data.get("os"),
            "shodan_isp": data.get("isp"),
            "shodan_org": data.get("org"),
            "shodan_asn": data.get("asn"),
            "shodan_country": data.get("country_code"),
            "shodan_hostnames": data.get("hostnames", []),
            "shodan_vulns": data.get("vulns", []),
        })

        # Set severity based on known vulnerabilities
        vulns = data.get("vulns", [])
        if vulns:
            ip_asset.severity = Severity.HIGH
            ip_asset.notes = f"Shodan reports {len(vulns)} known CVE(s)"

        ports = data.get("ports", [])
        ip_asset.ports = list(set(ip_asset.ports + ports))

        # Add individual PORT and SERVICE assets from banner data
        for service_data in data.get("data", []):
            port = service_data.get("port")
            transport = service_data.get("transport", "tcp")
            product = service_data.get("product", "")
            version = service_data.get("version", "")
            banner = service_data.get("data", "")

            if port is not None:
                port_value = f"{ip}:{port}/{transport}"
                result.add_asset(Asset(
                    value=port_value,
                    type=AssetType.PORT,
                    source=self.name,
                    parent=ip,
                    metadata={
                        "port": port,
                        "transport": transport,
                        "product": product,
                        "version": version,
                        "banner": banner[:512] if banner else "",
                        "cpe": service_data.get("cpe", []),
                    },
                ))

                if product:
                    service_label = f"{product} {version}".strip()
                    result.add_asset(Asset(
                        value=service_label,
                        type=AssetType.SERVICE,
                        source=self.name,
                        parent=port_value,
                        metadata={
                            "ip": ip,
                            "port": port,
                            "transport": transport,
                            "banner": banner[:512] if banner else "",
                        },
                    ))

        logger.info(
            "[%s] Enriched %s — %d ports, %d vulns",
            self.name, ip, len(ports), len(vulns),
        )


# ---------------------------------------------------------------------------
# 3. GitHub Dork
# ---------------------------------------------------------------------------

class GitHubDorkModule(DiscoveryModule):
    """Search GitHub for leaked secrets, credentials, and repos mentioning the target."""

    DORK_TEMPLATES: tuple[str, ...] = (
        '"{domain}" filename:.env',
        '"{domain}" password',
        '"{domain}" api_key',
        '"{domain}" secret',
        '"{domain}" AWS_SECRET',
    )

    @property
    def name(self) -> str:
        return "GitHubDork"

    @property
    def description(self) -> str:
        return "GitHub code search for leaked secrets and related repositories"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.github_token:
            logger.info("[%s] No GitHub token configured — skipping.", self.name)
            return

        headers = {
            "Authorization": f"Bearer {cfg.github_token}",
            "Accept": "application/vnd.github.v3+json",
        }
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)
        seen_repos: set[str] = set()

        async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
            for template in self.DORK_TEMPLATES:
                query = template.format(domain=target)
                await self._run_search(client, query, target, result, seen_repos)
                await asyncio.sleep(1.0)  # GitHub search rate limit: 10 req/min

    async def _run_search(
        self,
        client: httpx.AsyncClient,
        query: str,
        target: str,
        result: ScanResult,
        seen_repos: set[str],
    ) -> None:
        url = "https://api.github.com/search/code"
        params = {"q": query}

        try:
            resp = await client.get(url, params=params)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "[%s] Search failed for query '%s' (HTTP %d): %s",
                self.name, query, exc.response.status_code, exc,
            )
            return
        except httpx.HTTPError as exc:
            logger.warning(
                "[%s] Search error for query '%s': %s", self.name, query, exc,
            )
            return

        items = data.get("items", [])
        logger.info(
            "[%s] Query '%s' returned %d results",
            self.name, query, len(items),
        )

        for item in items:
            html_url = item.get("html_url", "")
            file_path = item.get("path", "")
            repo_info = item.get("repository", {})
            repo_full_name = repo_info.get("full_name", "")

            if html_url:
                result.add_asset(Asset(
                    value=html_url,
                    type=AssetType.SECRET_LEAK,
                    source=self.name,
                    parent=target,
                    severity=Severity.HIGH,
                    metadata={
                        "github_url": html_url,
                        "file_path": file_path,
                        "repository": repo_full_name,
                        "matched_query": query,
                    },
                ))

            if repo_full_name and repo_full_name not in seen_repos:
                seen_repos.add(repo_full_name)
                repo_url = repo_info.get("html_url", "")
                result.add_asset(Asset(
                    value=repo_full_name,
                    type=AssetType.GITHUB_REPO,
                    source=self.name,
                    parent=target,
                    metadata={
                        "html_url": repo_url,
                        "description": repo_info.get("description", ""),
                        "private": repo_info.get("private", False),
                    },
                ))


# ---------------------------------------------------------------------------
# 4. Email Harvest
# ---------------------------------------------------------------------------

class EmailHarvestModule(DiscoveryModule):
    """Discover email addresses via Hunter.io or regex fallback on collected content."""

    @property
    def name(self) -> str:
        return "EmailHarvest"

    @property
    def description(self) -> str:
        return "Email address discovery via Hunter.io API and content scraping"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if cfg.hunter_api_key:
            await self._hunter_search(target, result, cfg)
        else:
            logger.info(
                "[%s] No Hunter API key — falling back to regex extraction.",
                self.name,
            )
            self._regex_fallback(target, result)

    async def _hunter_search(
        self,
        domain: str,
        result: ScanResult,
        cfg: object,
    ) -> None:
        url = "https://api.hunter.io/v2/domain-search"
        params = {"domain": domain, "api_key": cfg.hunter_api_key}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "[%s] Hunter.io request failed (HTTP %d): %s",
                self.name, exc.response.status_code, exc,
            )
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Hunter.io request error: %s", self.name, exc)
            return

        hunter_data = data.get("data", {})

        # Extract pattern information
        pattern = hunter_data.get("pattern")
        if pattern:
            logger.info("[%s] Email pattern for %s: %s", self.name, domain, pattern)

        # Extract individual emails
        emails = hunter_data.get("emails", [])
        for entry in emails:
            email_value = entry.get("value", "")
            if not email_value:
                continue

            confidence = entry.get("confidence", 0)
            first_name = entry.get("first_name", "")
            last_name = entry.get("last_name", "")

            result.add_asset(Asset(
                value=email_value,
                type=AssetType.EMAIL,
                source=self.name,
                parent=domain,
                metadata={
                    "confidence": confidence,
                    "first_name": first_name,
                    "last_name": last_name,
                    "position": entry.get("position", ""),
                    "department": entry.get("department", ""),
                    "pattern": pattern or "",
                    "hunter_type": entry.get("type", ""),
                },
            ))

        logger.info(
            "[%s] Hunter.io found %d emails for %s",
            self.name, len(emails), domain,
        )

    def _regex_fallback(self, domain: str, result: ScanResult) -> None:
        """Extract emails from URL asset metadata/response content using regex."""
        # Escape dots in domain for regex
        domain_pattern = re.escape(domain)
        email_re = re.compile(
            rf"[a-zA-Z0-9._%+-]+@{domain_pattern}",
            re.IGNORECASE,
        )

        url_assets = result.get_by_type(AssetType.URL)
        discovered: set[str] = set()

        for asset in url_assets:
            # Search in metadata fields that may contain response body text
            for key in ("response_body", "content", "body", "text"):
                content = asset.metadata.get(key, "")
                if not content or not isinstance(content, str):
                    continue
                matches = email_re.findall(content)
                for email in matches:
                    email_lower = email.lower()
                    if email_lower not in discovered:
                        discovered.add(email_lower)
                        result.add_asset(Asset(
                            value=email_lower,
                            type=AssetType.EMAIL,
                            source=self.name,
                            parent=domain,
                            metadata={
                                "found_in": asset.value,
                                "extraction_method": "regex",
                            },
                        ))

        logger.info(
            "[%s] Regex extraction found %d emails across %d URL assets",
            self.name, len(discovered), len(url_assets),
        )
