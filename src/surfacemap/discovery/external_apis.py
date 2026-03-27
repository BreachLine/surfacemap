"""External API discovery modules.

Modules that query external threat intelligence APIs (Censys, BinaryEdge,
FullHunt, PassiveTotal) to enrich the attack surface with additional
subdomains, IPs, ports, and services. Each module gracefully skips if
its API key is not configured.
"""

from __future__ import annotations

import logging

import httpx

from surfacemap.core.config import get_config
from surfacemap.core.models import (
    Asset,
    AssetType,
    ScanResult,
)
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Censys
# ---------------------------------------------------------------------------

class CensysModule(DiscoveryModule):
    """Discover IPs, ports, services, and certificates via the Censys search API."""

    @property
    def name(self) -> str:
        return "Censys"

    @property
    def description(self) -> str:
        return "IP, port, service, and certificate discovery via Censys"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.has_censys:
            logger.info("[%s] No API keys configured — skipping.", self.name)
            return

        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)
        auth = (cfg.censys_api_id, cfg.censys_api_secret)

        url = "https://search.censys.io/api/v2/hosts/search"
        params = {
            "q": f'services.tls.certificates.leaf_data.names: "{target}"',
        }

        try:
            async with httpx.AsyncClient(timeout=timeout, auth=auth) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning(
                "[%s] Search request failed (HTTP %d): %s",
                self.name, exc.response.status_code, exc,
            )
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Search request error: %s", self.name, exc)
            return

        hits = data.get("result", {}).get("hits", [])

        for hit in hits:
            ip = hit.get("ip", "")
            if not ip:
                continue

            # Add IP asset
            result.add_asset(Asset(
                value=ip,
                type=AssetType.IP,
                source=self.name,
                parent=target,
                metadata={
                    "autonomous_system": hit.get("autonomous_system", {}),
                    "location": hit.get("location", {}),
                },
            ))

            # Add PORT and SERVICE assets from services
            for service in hit.get("services", []):
                port = service.get("port")
                transport = service.get("transport_protocol", "tcp")
                service_name = service.get("service_name", "")

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
                            "service_name": service_name,
                        },
                    ))

                    if service_name:
                        result.add_asset(Asset(
                            value=f"{service_name} ({ip}:{port})",
                            type=AssetType.SERVICE,
                            source=self.name,
                            parent=port_value,
                            metadata={
                                "ip": ip,
                                "port": port,
                                "transport": transport,
                            },
                        ))

                # Add CERTIFICATE assets from TLS data
                tls = service.get("tls", {})
                certs = tls.get("certificates", {})
                leaf = certs.get("leaf_data", {})
                subject_dn = leaf.get("subject_dn", "")
                if subject_dn:
                    result.add_asset(Asset(
                        value=subject_dn,
                        type=AssetType.CERTIFICATE,
                        source=self.name,
                        parent=ip,
                        metadata={
                            "issuer_dn": leaf.get("issuer_dn", ""),
                            "fingerprint": leaf.get("fingerprint", ""),
                            "names": leaf.get("names", []),
                        },
                    ))

        logger.info(
            "[%s] Discovered %d hosts for %s",
            self.name, len(hits), target,
        )


# ---------------------------------------------------------------------------
# 2. BinaryEdge
# ---------------------------------------------------------------------------

class BinaryEdgeModule(DiscoveryModule):
    """Discover subdomains via the BinaryEdge API."""

    @property
    def name(self) -> str:
        return "BinaryEdge"

    @property
    def description(self) -> str:
        return "Subdomain enumeration via BinaryEdge"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.has_binaryedge:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"X-Key": cfg.binaryedge_api_key}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        url = f"https://api.binaryedge.io/v2/query/domains/subdomain/{target}"

        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
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

        events = data.get("events", [])
        count = 0

        for subdomain in events:
            if subdomain and isinstance(subdomain, str):
                result.add_asset(Asset(
                    value=subdomain,
                    type=AssetType.SUBDOMAIN,
                    source=self.name,
                    parent=target,
                ))
                count += 1

        logger.info(
            "[%s] Discovered %d subdomains for %s",
            self.name, count, target,
        )


# ---------------------------------------------------------------------------
# 3. FullHunt
# ---------------------------------------------------------------------------

class FullHuntModule(DiscoveryModule):
    """Discover subdomains and host metadata via the FullHunt API."""

    @property
    def name(self) -> str:
        return "FullHunt"

    @property
    def description(self) -> str:
        return "Subdomain enumeration and host metadata via FullHunt"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.has_fullhunt:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"X-API-KEY": cfg.fullhunt_api_key}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        url = f"https://fullhunt.io/api/v1/domain/{target}/subdomains"

        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
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

        hosts = data.get("hosts", [])
        count = 0

        for host in hosts:
            if isinstance(host, dict):
                subdomain = host.get("host", "")
                if subdomain:
                    result.add_asset(Asset(
                        value=subdomain,
                        type=AssetType.SUBDOMAIN,
                        source=self.name,
                        parent=target,
                        metadata={
                            "ip": host.get("ip_address", ""),
                            "status": host.get("status_code", ""),
                            "technology": host.get("technology", []),
                        },
                    ))
                    count += 1
            elif isinstance(host, str) and host:
                result.add_asset(Asset(
                    value=host,
                    type=AssetType.SUBDOMAIN,
                    source=self.name,
                    parent=target,
                ))
                count += 1

        logger.info(
            "[%s] Discovered %d subdomains for %s",
            self.name, count, target,
        )


# ---------------------------------------------------------------------------
# 4. PassiveTotal
# ---------------------------------------------------------------------------

class PassiveTotalModule(DiscoveryModule):
    """Discover subdomains via the PassiveTotal (RiskIQ) API."""

    @property
    def name(self) -> str:
        return "PassiveTotal"

    @property
    def description(self) -> str:
        return "Subdomain enumeration via PassiveTotal (RiskIQ)"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()

        if not cfg.has_passivetotal:
            logger.info("[%s] No API keys configured — skipping.", self.name)
            return

        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)
        auth = (cfg.passivetotal_username, cfg.passivetotal_api_key)

        url = "https://api.passivetotal.org/v2/enrichment/subdomains"
        body = {"query": f"*.{target}"}

        try:
            async with httpx.AsyncClient(timeout=timeout, auth=auth) as client:
                resp = await client.get(url, params=body)
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

        subdomains = data.get("subdomains", [])
        count = 0

        for sub in subdomains:
            if sub and isinstance(sub, str):
                fqdn = f"{sub}.{target}"
                result.add_asset(Asset(
                    value=fqdn,
                    type=AssetType.SUBDOMAIN,
                    source=self.name,
                    parent=target,
                ))
                count += 1

        logger.info(
            "[%s] Discovered %d subdomains for %s",
            self.name, count, target,
        )
