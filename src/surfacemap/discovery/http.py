"""HTTP-based discovery modules.

Probes discovered subdomains via HTTP/HTTPS to detect technologies,
CDNs, WAFs, and missing security headers.
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

# Technology detection patterns from HTTP headers
HEADER_TECH_PATTERNS: dict[str, list[tuple[str, str]]] = {
    "server": [
        (r"nginx", "Nginx"),
        (r"apache", "Apache"),
        (r"cloudflare", "Cloudflare"),
        (r"microsoft-iis", "IIS"),
        (r"gunicorn", "Gunicorn"),
        (r"uvicorn", "Uvicorn"),
        (r"openresty", "OpenResty"),
        (r"lighttpd", "Lighttpd"),
        (r"caddy", "Caddy"),
        (r"litespeed", "LiteSpeed"),
        (r"envoy", "Envoy"),
        (r"traefik", "Traefik"),
    ],
    "x-powered-by": [
        (r"php", "PHP"),
        (r"asp\.net", "ASP.NET"),
        (r"express", "Express.js"),
        (r"next\.js", "Next.js"),
        (r"nuxt", "Nuxt.js"),
        (r"django", "Django"),
        (r"flask", "Flask"),
        (r"ruby", "Ruby"),
        (r"java", "Java"),
    ],
    "x-generator": [
        (r"wordpress", "WordPress"),
        (r"drupal", "Drupal"),
        (r"joomla", "Joomla"),
        (r"hugo", "Hugo"),
        (r"gatsby", "Gatsby"),
    ],
}

# CDN detection from headers
CDN_PATTERNS: dict[str, str] = {
    "cf-ray": "Cloudflare",
    "x-cdn": "Generic CDN",
    "x-cache": "CDN Cache",
    "x-amz-cf-id": "CloudFront",
    "x-fastly-request-id": "Fastly",
    "x-akamai-transformed": "Akamai",
    "x-vercel-id": "Vercel",
    "x-netlify-request-id": "Netlify",
    "fly-request-id": "Fly.io",
}

# WAF detection patterns
WAF_PATTERNS: dict[str, str] = {
    "cf-ray": "Cloudflare WAF",
    "x-sucuri-id": "Sucuri WAF",
    "x-cdn": "Imperva/Incapsula",
    "server: awselb": "AWS WAF/ELB",
    "x-kong-proxy-latency": "Kong",
}

# Security headers to check
SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
]


class HTTPProbeModule(DiscoveryModule):
    """Probe all discovered subdomains via HTTP/HTTPS."""

    name = "HTTP Probe"
    description = "Probe subdomains for HTTP services, detect technologies and security headers"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        subdomains = result.get_by_type(AssetType.SUBDOMAIN)

        # Probe ALL discovered hosts with a shared client for connection pooling
        all_targets = [target] + [a.value for a in subdomains]
        seen: set[str] = set()
        hosts_to_probe: list[str] = []

        for host in all_targets:
            if host in seen:
                continue
            seen.add(host)
            hosts_to_probe.append(host)

        logger.info("[HTTP Probe] Probing %d hosts with %d concurrency",
                    len(hosts_to_probe), config.max_concurrent_probes)

        sem = asyncio.Semaphore(config.max_concurrent_probes)
        # Use short connect timeout (5s) — if host doesn't respond quickly, skip
        probe_timeout = httpx.Timeout(connect=5, read=config.http_timeout, write=10, pool=10)

        async with httpx.AsyncClient(
            timeout=probe_timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": config.user_agent},
            limits=httpx.Limits(max_connections=config.max_concurrent_probes),
        ) as shared_client:
            tasks = [
                self._probe_host(host, target, result, sem, config, shared_client)
                for host in hosts_to_probe
            ]
            await asyncio.gather(*tasks)

    async def _probe_host(
        self,
        host: str,
        parent: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: object,
        client: httpx.AsyncClient,
    ) -> None:
        """Probe a single host via HTTPS then HTTP."""
        cfg = config  # type: ignore[assignment]
        async with sem:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{host}"
                try:
                    resp = await client.get(url)

                    # Determine status
                    if 300 <= resp.status_code < 400:
                        status = AssetStatus.REDIRECT
                    elif resp.status_code < 400:
                        status = AssetStatus.LIVE
                    else:
                        status = AssetStatus.DOWN

                    # Detect technologies
                    technologies = self._detect_technologies(resp.headers)

                    # Detect CDN
                    cdn = self._detect_cdn(resp.headers)
                    if cdn:
                        result.add_asset(Asset(
                            value=cdn, type=AssetType.CDN,
                            parent=host, source="http-cdn",
                        ))

                    # Detect WAF
                    waf = self._detect_waf(resp.headers)
                    if waf:
                        result.add_asset(Asset(
                            value=waf, type=AssetType.WAF,
                            parent=host, source="http-waf",
                        ))

                    # Check security headers
                    missing_headers = self._check_security_headers(resp.headers)
                    security_severity = Severity.INFO
                    if len(missing_headers) > 5:
                        security_severity = Severity.MEDIUM
                    elif len(missing_headers) > 3:
                        security_severity = Severity.LOW

                    # Extract title from HTML
                    title = ""
                    title_match = re.search(
                        r"<title[^>]*>(.*?)</title>",
                        resp.text[:4096],
                        re.IGNORECASE | re.DOTALL,
                    )
                    if title_match:
                        title = title_match.group(1).strip()[:100]

                    # Update subdomain asset or create URL asset
                    result.add_asset(Asset(
                        value=url,
                        type=AssetType.URL,
                        status=status,
                        parent=host,
                        source="http-probe",
                        technologies=technologies,
                        severity=security_severity,
                        metadata={
                            "status_code": resp.status_code,
                            "title": title,
                            "content_length": len(resp.content),
                            "scheme": scheme,
                            "missing_security_headers": missing_headers,
                            "response_headers": dict(resp.headers),
                        },
                    ))

                    # Add detected technologies as separate assets
                    for tech in technologies:
                        result.add_asset(Asset(
                            value=tech,
                            type=AssetType.TECHNOLOGY,
                            parent=host,
                            source="http-tech-detect",
                        ))

                    # If HTTPS worked, skip HTTP
                    if scheme == "https" and status == AssetStatus.LIVE:
                        break

                except httpx.ConnectError:
                    continue
                except httpx.TimeoutException:
                    continue
                except Exception as e:
                    logger.debug("HTTP probe failed for %s: %s", url, e)
                    continue

    def _detect_technologies(self, headers: httpx.Headers) -> list[str]:
        """Detect technologies from HTTP response headers."""
        detected: list[str] = []
        for header_name, patterns in HEADER_TECH_PATTERNS.items():
            header_value = headers.get(header_name, "").lower()
            if not header_value:
                continue
            for pattern, tech_name in patterns:
                if re.search(pattern, header_value, re.IGNORECASE):
                    if tech_name not in detected:
                        detected.append(tech_name)
        return detected

    def _detect_cdn(self, headers: httpx.Headers) -> str | None:
        """Detect CDN from HTTP headers."""
        for header, cdn_name in CDN_PATTERNS.items():
            if header.lower() in [h.lower() for h in headers]:
                return cdn_name
        return None

    def _detect_waf(self, headers: httpx.Headers) -> str | None:
        """Detect WAF from HTTP headers."""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for pattern, waf_name in WAF_PATTERNS.items():
            if ":" in pattern:
                key, val = pattern.split(": ", 1)
                if key.lower() in headers_lower and val in headers_lower.get(key.lower(), ""):
                    return waf_name
            elif pattern.lower() in headers_lower:
                return waf_name
        return None

    def _check_security_headers(self, headers: httpx.Headers) -> list[str]:
        """Check for missing security headers."""
        headers_lower = {h.lower() for h in headers}
        missing = []
        for header in SECURITY_HEADERS:
            if header not in headers_lower:
                missing.append(header)
        return missing


class PortScanModule(DiscoveryModule):
    """Run nmap port scans on discovered IP addresses."""

    name = "Port Scan"
    description = "Scan discovered IPs for open ports and services using nmap"

    async def discover(self, target: str, result: ScanResult) -> None:
        ip_assets = result.get_by_type(AssetType.IP)
        if not ip_assets:
            logger.info("No IPs discovered — skipping port scan")
            return

        config = get_config()

        # Deduplicate IPs and sanitize
        unique_ips = list({
            re.sub(r'[^a-fA-F0-9.:]', '', a.value)
            for a in ip_assets
        })

        for ip in unique_ips[: config.max_ips_to_scan]:
            await self._scan_ip(ip, target, result, config)

    async def _scan_ip(
        self, ip: str, target: str, result: ScanResult, config: object
    ) -> None:
        """Run nmap on a single IP address."""
        cfg = config  # type: ignore[assignment]
        try:
            nmap_args = cfg.nmap_args.split()
            cmd = ["nmap"] + nmap_args + ["-oG", "-", ip]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.scan_timeout
            )
            output = stdout.decode()

            # Parse greppable nmap output
            for line in output.split("\n"):
                if "/open/" not in line:
                    continue

                # Extract ports from greppable format
                ports_section = line.split("Ports: ")
                if len(ports_section) < 2:
                    continue

                port_entries = ports_section[1].split(",")
                for entry in port_entries:
                    entry = entry.strip()
                    parts = entry.split("/")
                    if len(parts) >= 5 and parts[1] == "open":
                        port_num = int(parts[0])
                        protocol = parts[2]
                        service_name = parts[4] if parts[4] else "unknown"
                        version = parts[6] if len(parts) > 6 else ""

                        # Add port asset
                        result.add_asset(Asset(
                            value=f"{ip}:{port_num}",
                            type=AssetType.PORT,
                            status=AssetStatus.LIVE,
                            parent=ip,
                            source="nmap",
                            metadata={
                                "port": port_num,
                                "protocol": protocol,
                                "service": service_name,
                                "version": version.strip(),
                            },
                        ))

                        # Add service asset
                        if service_name and service_name != "unknown":
                            result.add_asset(Asset(
                                value=f"{service_name}/{version.strip()}" if version.strip() else service_name,
                                type=AssetType.SERVICE,
                                status=AssetStatus.LIVE,
                                parent=f"{ip}:{port_num}",
                                source="nmap",
                                metadata={
                                    "ip": ip,
                                    "port": port_num,
                                    "protocol": protocol,
                                },
                            ))

        except FileNotFoundError:
            logger.warning("nmap not installed — skipping port scan")
        except asyncio.TimeoutError:
            logger.warning("nmap timed out for %s", ip)
        except Exception as e:
            logger.warning("Port scan failed for %s: %s", ip, e)
