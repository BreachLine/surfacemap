"""External API discovery modules (12 modules).

Modules that query external threat intelligence and search APIs to enrich
the attack surface with subdomains, IPs, ports, services, certificates,
vulnerabilities, reputation data, data leaks, and email addresses. Each
module gracefully skips if its API key is not configured.
"""

from __future__ import annotations

import asyncio
import base64
import logging

import httpx

from surfacemap.core.config import get_config
from surfacemap.core.models import (
    Asset,
    AssetType,
    Severity,
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


# ---------------------------------------------------------------------------
# 5. ONYPHE
# ---------------------------------------------------------------------------

class ONYPHEModule(DiscoveryModule):
    """Discover IPs, ports, and services via the ONYPHE API."""

    @property
    def name(self) -> str:
        return "ONYPHE"

    @property
    def description(self) -> str:
        return "IP, port, and service discovery via ONYPHE"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_onyphe:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"Authorization": f"bearer {cfg.onyphe_api_key}"}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
                resp = await client.get(f"https://www.onyphe.io/api/v2/simple/datascan/{target}")
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("[%s] Request failed (HTTP %d): %s", self.name, exc.response.status_code, exc)
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Request error: %s", self.name, exc)
            return
        except ValueError as exc:
            logger.warning("[%s] Invalid JSON response: %s", self.name, exc)
            return

        count = 0
        for entry in data.get("results", []):
            ip = entry.get("ip", "")
            port = entry.get("port")
            protocol = entry.get("protocol", "")
            if ip:
                result.add_asset(Asset(value=ip, type=AssetType.IP, source=self.name, parent=target))
            if ip and port is not None:
                result.add_asset(Asset(value=f"{ip}:{port}", type=AssetType.PORT, source=self.name, parent=ip))
                count += 1
            if protocol and ip and port is not None:
                result.add_asset(Asset(
                    value=f"{protocol} ({ip}:{port})", type=AssetType.SERVICE, source=self.name, parent=ip,
                ))
        logger.info("[%s] Discovered %d port/service entries for %s", self.name, count, target)


# ---------------------------------------------------------------------------
# 6. GreyNoise
# ---------------------------------------------------------------------------

class GreyNoiseModule(DiscoveryModule):
    """Enrich discovered IPs with GreyNoise reputation data."""

    @property
    def name(self) -> str:
        return "GreyNoise"

    @property
    def description(self) -> str:
        return "IP reputation and noise classification via GreyNoise"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_greynoise:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        ips = [a for a in result.get_by_type(AssetType.IP) if ":" not in a.value]
        if not ips:
            logger.info("[%s] No IPs to enrich — skipping.", self.name)
            return

        headers = {"key": cfg.greynoise_api_key, "Accept": "application/json"}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        count = 0
        async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
            for asset in ips[:50]:
                try:
                    resp = await client.get(f"https://api.greynoise.io/v3/community/{asset.value}")
                    if resp.status_code in (401, 403):
                        logger.warning("[%s] Authentication failed (HTTP %d) — check API key", self.name, resp.status_code)
                        break
                    if resp.status_code == 429:
                        logger.warning("[%s] Rate limited — stopping enrichment", self.name)
                        break
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    asset.metadata["greynoise_noise"] = data.get("noise", False)
                    asset.metadata["greynoise_riot"] = data.get("riot", False)
                    asset.metadata["greynoise_classification"] = data.get("classification", "")
                    asset.metadata["greynoise_name"] = data.get("name", "")
                    count += 1
                except (httpx.HTTPError, ValueError) as exc:
                    logger.warning("[%s] Error for %s: %s", self.name, asset.value, exc)
                    continue
        logger.info("[%s] Enriched %d IPs with reputation data", self.name, count)


# ---------------------------------------------------------------------------
# 7. FOFA
# ---------------------------------------------------------------------------

class FOFAModule(DiscoveryModule):
    """Discover subdomains, IPs, and ports via the FOFA search engine."""

    @property
    def name(self) -> str:
        return "FOFA"

    @property
    def description(self) -> str:
        return "Subdomain, IP, and port discovery via FOFA"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_fofa:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        query = f'domain="{target}"'
        qbase64 = base64.b64encode(query.encode()).decode()
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)
        params = {
            "email": cfg.fofa_email, "key": cfg.fofa_api_key,
            "qbase64": qbase64, "fields": "host,ip,port,protocol", "size": "100",
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get("https://fofa.info/api/v1/search/all", params=params)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("[%s] Request failed (HTTP %d): %s", self.name, exc.response.status_code, exc)
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Request error: %s", self.name, exc)
            return
        except ValueError as exc:
            logger.warning("[%s] Invalid JSON response: %s", self.name, exc)
            return

        count = 0
        for row in data.get("results", []):
            if not isinstance(row, list) or len(row) < 3:
                continue
            host, ip, port = row[0], row[1], row[2]
            if host and target in host:
                result.add_asset(Asset(value=host, type=AssetType.SUBDOMAIN, source=self.name, parent=target))
                count += 1
            if ip:
                result.add_asset(Asset(value=ip, type=AssetType.IP, source=self.name, parent=target))
            if ip and port:
                result.add_asset(Asset(value=f"{ip}:{port}", type=AssetType.PORT, source=self.name, parent=ip))
        logger.info("[%s] Discovered %d hosts for %s", self.name, count, target)


# ---------------------------------------------------------------------------
# 8. LeakIX
# ---------------------------------------------------------------------------

class LeakIXModule(DiscoveryModule):
    """Discover exposed services and leaked data via LeakIX."""

    @property
    def name(self) -> str:
        return "LeakIX"

    @property
    def description(self) -> str:
        return "Exposed services and data leak detection via LeakIX"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_leakix:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"api-key": cfg.leakix_api_key, "Accept": "application/json"}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
                resp = await client.get(f"https://leakix.net/domain/{target}")
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("[%s] Request failed (HTTP %d): %s", self.name, exc.response.status_code, exc)
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Request error: %s", self.name, exc)
            return
        except ValueError as exc:
            logger.warning("[%s] Invalid JSON response: %s", self.name, exc)
            return

        # LeakIX returns {"Services": [...], "Leaks": [...]}
        if isinstance(data, dict):
            entries = (data.get("Services") or []) + (data.get("Leaks") or [])
        elif isinstance(data, list):
            entries = data
        else:
            logger.warning("[%s] Unexpected response type %s", self.name, type(data).__name__)
            return

        svc_count = 0
        leak_count = 0
        for entry in entries:
            ip = entry.get("ip", "")
            host = entry.get("host", "")
            port = entry.get("port", "")
            if host and target in host:
                result.add_asset(Asset(value=host, type=AssetType.SUBDOMAIN, source=self.name, parent=target))
            if ip:
                result.add_asset(Asset(value=ip, type=AssetType.IP, source=self.name, parent=target))
            if ip and port:
                result.add_asset(Asset(value=f"{ip}:{port}", type=AssetType.PORT, source=self.name, parent=ip))
                svc_count += 1

            # Leaks have event_source and severity
            event_source = entry.get("event_source", "")
            severity_str = entry.get("severity", "")
            if severity_str in ("high", "critical") and (host or ip):
                result.add_asset(Asset(
                    value=f"{event_source} on {host or ip}:{port}",
                    type=AssetType.SECRET_LEAK, severity=Severity.HIGH,
                    source=self.name, parent=host or ip,
                    metadata={"event_source": event_source, "host": host, "port": port},
                ))
                leak_count += 1
        logger.info("[%s] Discovered %d services, %d leaks for %s", self.name, svc_count, leak_count, target)


# ---------------------------------------------------------------------------
# 9. IntelX (Intelligence X)
# ---------------------------------------------------------------------------

class IntelXModule(DiscoveryModule):
    """Discover subdomains and emails via IntelX phonebook search."""

    @property
    def name(self) -> str:
        return "IntelX"

    @property
    def description(self) -> str:
        return "Subdomain and email discovery via Intelligence X phonebook"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_intelx:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"x-key": cfg.intelx_api_key, "Content-Type": "application/json"}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)
        base_url = "https://2.intelx.io"

        count = 0
        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
                resp = await client.post(f"{base_url}/phonebook/search", json={
                    "term": target, "maxresults": 1000, "target": 1, "timeout": 20,
                })
                resp.raise_for_status()
                search_id = resp.json().get("id", "")
                if not search_id:
                    logger.warning("[%s] Search returned no ID — API may be unavailable", self.name)
                    return

                for attempt in range(5):
                    await asyncio.sleep(2)
                    try:
                        resp = await client.get(
                            f"{base_url}/phonebook/search/result",
                            params={"id": search_id, "limit": 1000},
                        )
                    except httpx.HTTPError as exc:
                        logger.warning("[%s] Polling attempt %d failed: %s", self.name, attempt + 1, exc)
                        continue
                    if resp.status_code != 200:
                        continue
                    try:
                        data = resp.json()
                    except ValueError:
                        logger.warning("[%s] Polling returned invalid JSON", self.name)
                        continue
                    for sel in data.get("selectors", []):
                        value = sel.get("selectorvalue", "")
                        stype = sel.get("selectortype", 0)
                        if stype == 2 and value and target in value:
                            result.add_asset(Asset(
                                value=value, type=AssetType.SUBDOMAIN, source=self.name, parent=target,
                            ))
                            count += 1
                        elif stype == 0 and "@" in value and target in value:
                            result.add_asset(Asset(
                                value=value, type=AssetType.EMAIL, source=self.name, parent=target,
                            ))
                    if data.get("status", 0) == 2:
                        break
        except httpx.HTTPStatusError as exc:
            logger.warning("[%s] Request failed (HTTP %d): %s", self.name, exc.response.status_code, exc)
        except httpx.HTTPError as exc:
            logger.warning("[%s] Request error: %s", self.name, exc)

        logger.info("[%s] Discovered %d subdomains for %s", self.name, count, target)


# ---------------------------------------------------------------------------
# 10. Vulners
# ---------------------------------------------------------------------------

class VulnersModule(DiscoveryModule):
    """Enrich discovered technologies with known CVEs from Vulners."""

    @property
    def name(self) -> str:
        return "Vulners"

    @property
    def description(self) -> str:
        return "CVE/vulnerability lookup for discovered technologies via Vulners"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_vulners:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        techs = result.get_by_type(AssetType.TECHNOLOGY)
        if not techs:
            logger.info("[%s] No technologies to look up — skipping.", self.name)
            return

        headers = {"X-Api-Key": cfg.vulners_api_key, "Content-Type": "application/json"}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        count = 0
        async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
            for tech in techs[:20]:
                name = tech.value.split("(")[0].strip()
                if not name or len(name) < 3:
                    continue
                try:
                    resp = await client.post(
                        "https://vulners.com/api/v3/search/lucene",
                        json={"query": f'affectedSoftware.name:"{name}"', "size": 5},
                    )
                    if resp.status_code in (401, 403):
                        logger.warning("[%s] Authentication failed (HTTP %d) — check API key", self.name, resp.status_code)
                        break
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    documents = (data.get("data") or {}).get("documents") or []
                    for doc in documents:
                        cve_id = doc.get("id", "")
                        cvss_raw = doc.get("cvss")
                        cvss = cvss_raw.get("score", 0) if isinstance(cvss_raw, dict) else (cvss_raw if isinstance(cvss_raw, (int, float)) else 0)
                        title = doc.get("title", "")
                        severity = Severity.INFO
                        if cvss >= 9.0:
                            severity = Severity.CRITICAL
                        elif cvss >= 7.0:
                            severity = Severity.HIGH
                        elif cvss >= 4.0:
                            severity = Severity.MEDIUM
                        elif cvss > 0:
                            severity = Severity.LOW
                        result.add_asset(Asset(
                            value=f"{cve_id}: {title[:100]}",
                            type=AssetType.VULNERABILITY, severity=severity,
                            source=self.name, parent=name,
                            metadata={"cve": cve_id, "cvss": cvss, "software": name},
                        ))
                        count += 1
                except (httpx.HTTPError, ValueError) as exc:
                    logger.warning("[%s] Error looking up %s: %s", self.name, name, exc)
                    continue
        logger.info("[%s] Found %d vulnerabilities for %s", self.name, count, target)


# ---------------------------------------------------------------------------
# 11. Pulsedive
# ---------------------------------------------------------------------------

class PulsediveModule(DiscoveryModule):
    """Enrich target with threat intelligence from Pulsedive."""

    @property
    def name(self) -> str:
        return "Pulsedive"

    @property
    def description(self) -> str:
        return "Threat intelligence and risk scoring via Pulsedive"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_pulsedive:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(
                    "https://pulsedive.com/api/info.php",
                    params={"indicator": target, "key": cfg.pulsedive_api_key},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("[%s] Request failed (HTTP %d): %s", self.name, exc.response.status_code, exc)
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Request error: %s", self.name, exc)
            return
        except ValueError as exc:
            logger.warning("[%s] Invalid JSON response: %s", self.name, exc)
            return

        risk = data.get("risk", "none")
        threats = data.get("threats", [])
        properties = data.get("properties", {})

        for asset in result.get_by_type(AssetType.DOMAIN):
            if asset.value == target:
                asset.metadata["pulsedive_risk"] = risk
                asset.metadata["pulsedive_threats"] = [t.get("name", "") for t in threats] if threats else []
                break

        for tech in properties.get("technology", []):
            result.add_asset(Asset(value=tech, type=AssetType.TECHNOLOGY, source=self.name, parent=target))

        count = 0
        for port_str in properties.get("port", []):
            result.add_asset(Asset(value=f"{target}:{port_str}", type=AssetType.PORT, source=self.name, parent=target))
            count += 1
        logger.info("[%s] Risk=%s, %d ports for %s", self.name, risk, count, target)


# ---------------------------------------------------------------------------
# 12. ZoomEye
# ---------------------------------------------------------------------------

class ZoomEyeModule(DiscoveryModule):
    """Discover IPs, ports, and services via the ZoomEye search engine."""

    @property
    def name(self) -> str:
        return "ZoomEye"

    @property
    def description(self) -> str:
        return "IP, port, and service discovery via ZoomEye"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.has_zoomeye:
            logger.info("[%s] No API key configured — skipping.", self.name)
            return

        headers = {"API-KEY": cfg.zoomeye_api_key}
        timeout = httpx.Timeout(cfg.osint_timeout, connect=cfg.osint_connect_timeout)

        try:
            async with httpx.AsyncClient(headers=headers, timeout=timeout) as client:
                resp = await client.get(
                    "https://api.zoomeye.org/host/search",
                    params={"query": f"hostname:{target}", "page": "1"},
                )
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as exc:
            logger.warning("[%s] Request failed (HTTP %d): %s", self.name, exc.response.status_code, exc)
            return
        except httpx.HTTPError as exc:
            logger.warning("[%s] Request error: %s", self.name, exc)
            return
        except ValueError as exc:
            logger.warning("[%s] Invalid JSON response: %s", self.name, exc)
            return

        count = 0
        for match in data.get("matches", []):
            ip = match.get("ip", "")
            port_info = match.get("portinfo", {})
            port = port_info.get("port", "")
            service = port_info.get("service", "")
            os_name = port_info.get("os", "")
            if ip:
                result.add_asset(Asset(
                    value=ip, type=AssetType.IP, source=self.name, parent=target,
                    metadata={"os": os_name} if os_name else {},
                ))
            if ip and port is not None:
                result.add_asset(Asset(value=f"{ip}:{port}", type=AssetType.PORT, source=self.name, parent=ip))
                count += 1
            if service and ip and port is not None:
                result.add_asset(Asset(
                    value=f"{service} ({ip}:{port})", type=AssetType.SERVICE, source=self.name, parent=ip,
                ))
        logger.info("[%s] Discovered %d ports for %s", self.name, count, target)
