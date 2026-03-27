"""Web-based OSINT discovery -- fetches data from public APIs and web sources."""

import asyncio
import json
import logging
import re
import time
from typing import List, Optional

import httpx

from surfacemap.core.config import SurfaceMapConfig, get_config
from surfacemap.core.models import Asset, AssetType, AssetStatus, ScanResult, Severity
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple async rate limiter — enforces minimum delay between calls."""

    def __init__(self, min_interval: float) -> None:
        self._min_interval = min_interval
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = asyncio.get_event_loop().time()
            elapsed = now - self._last_call
            if elapsed < self._min_interval:
                await asyncio.sleep(self._min_interval - elapsed)
            self._last_call = asyncio.get_event_loop().time()


# Shared rate limiters for APIs with known limits
_hackertarget_limiter = RateLimiter(1.0)    # 1 req/sec (100/day free)
_alienvault_limiter = RateLimiter(2.0)      # conservative for free tier
_certspotter_limiter = RateLimiter(1.0)     # 100/hour free


def _osint_timeout(config: SurfaceMapConfig) -> httpx.Timeout:
    """Build an httpx Timeout with a short connect timeout and longer read timeout."""
    return httpx.Timeout(
        connect=config.osint_connect_timeout,
        read=config.osint_timeout,
        write=config.osint_timeout,
        pool=config.osint_timeout,
    )


async def _fetch_with_retry(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_retries: int,
    retry_delay: float,
    method: str = "GET",
    **kwargs,
) -> httpx.Response | None:
    """Fetch a URL with retry on transient errors (429, 503, 502, timeout)."""
    for attempt in range(max_retries + 1):
        try:
            resp = await client.request(method, url, **kwargs)
            if resp.status_code in (429, 502, 503):
                if attempt < max_retries:
                    wait = retry_delay * (2 ** attempt)
                    logger.info(
                        "[OSINT] %s returned %d, retrying in %.0fs (attempt %d/%d)",
                        url.split("?")[0], resp.status_code,
                        wait, attempt + 1, max_retries,
                    )
                    await asyncio.sleep(wait)
                    continue
            return resp
        except (httpx.TimeoutException, httpx.ConnectError) as exc:
            if attempt < max_retries:
                wait = retry_delay * (2 ** attempt)
                logger.info(
                    "[OSINT] %s timed out, retrying in %.0fs (attempt %d/%d)",
                    url.split("?")[0], wait, attempt + 1, max_retries,
                )
                await asyncio.sleep(wait)
                continue
            logger.warning("[OSINT] %s failed after %d attempts: %s", url.split("?")[0], max_retries + 1, exc)
            return None
    return None


class CertTransparencyModule(DiscoveryModule):
    """Certificate Transparency log search via crt.sh API."""
    name = "cert_transparency"
    description = "Certificate Transparency logs (crt.sh)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://crt.sh/?q=%.{domain}&output=json",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[CertTransparency] crt.sh returned no data")
                    return

                seen = set()
                for entry in resp.json():
                    name = entry.get("name_value", "")
                    issuer = entry.get("issuer_name", "")
                    not_after = entry.get("not_after", "")

                    for subdomain in name.split("\n"):
                        subdomain = subdomain.strip().lower().lstrip("*.")
                        if subdomain and subdomain.endswith(domain) and subdomain not in seen:
                            seen.add(subdomain)
                            result.add_asset(Asset(
                                value=subdomain,
                                type=AssetType.SUBDOMAIN if subdomain != domain else AssetType.DOMAIN,
                                parent=domain,
                                source=self.name,
                                metadata={"issuer": issuer[:100], "expires": not_after},
                            ))
        except Exception as exc:
            logger.warning("[CertTransparency] crt.sh failed: %s", exc)

        ct_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[CertTransparency] Found %d entries for %s", ct_count, domain)


class WaybackModule(DiscoveryModule):
    """Wayback Machine URL discovery.

    Uses text output format (faster than JSON) and streams the response
    to handle large datasets without timeout.
    """
    name = "wayback"
    description = "Historical URLs from Wayback Machine"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()
        seen: set[str] = set()
        total_wanted = config.max_wayback_results

        # Use text format (much lighter than JSON) and stream the response
        url = (
            f"https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original"
            f"&collapse=urlkey&limit={total_wanted}"
        )

        # Try wildcard subdomain query first, fall back to base domain only
        urls_to_try = [
            url,
            (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url={domain}/*&output=text&fl=original"
                f"&collapse=urlkey&limit={total_wanted}"
            ),
        ]

        wayback_timeout = httpx.Timeout(
            connect=config.osint_connect_timeout,
            read=config.osint_connect_timeout,
            write=config.osint_connect_timeout,
            pool=config.osint_connect_timeout,
        )

        for attempt_url in urls_to_try:
            try:
                async with httpx.AsyncClient(timeout=wayback_timeout) as client:
                    async with client.stream("GET", attempt_url) as resp:
                        if resp.status_code != 200:
                            continue

                        async for line in resp.aiter_lines():
                            line = line.strip()
                            if not line:
                                continue
                            if line not in seen:
                                seen.add(line)
                                result.add_asset(Asset(
                                    value=line[:500],
                                    type=AssetType.URL,
                                    parent=domain,
                                    source=self.name,
                                ))
                                if len(seen) >= total_wanted:
                                    break

                if seen:
                    break  # Got results, no need to try fallback

            except httpx.TimeoutException:
                if seen:
                    logger.info("[Wayback] Partial: %d URLs for %s", len(seen), domain)
                    break
                continue
            except Exception:
                continue

        if not seen:
            logger.warning("[Wayback] No data from any endpoint for %s", domain)

        wb_count = len([a for a in result.assets if a.source == self.name])
        if wb_count:
            logger.info("[Wayback] Found %d URLs for %s", wb_count, domain)


class AlienVaultModule(DiscoveryModule):
    """AlienVault OTX passive DNS."""
    name = "alienvault"
    description = "AlienVault OTX passive DNS records"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[AlienVault] No data (status=%s)", resp.status_code if resp else "timeout")
                    return

                data = resp.json()
                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "")
                    address = record.get("address", "")

                    if hostname and hostname.endswith(domain) and hostname != domain:
                        result.add_asset(Asset(
                            value=hostname,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                            ip_addresses=[address] if address else [],
                        ))

                    if address:
                        result.add_asset(Asset(
                            value=address,
                            type=AssetType.IP,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[AlienVault] Failed: %s", exc)

        av_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[AlienVault] Found %d records for %s", av_count, domain)


class SecurityTrailsModule(DiscoveryModule):
    """SecurityTrails API for subdomain history."""
    name = "securitytrails"
    description = "SecurityTrails subdomain enumeration (requires API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        import os
        api_key = os.environ.get("SECURITYTRAILS_API_KEY", "")
        if not api_key:
            return

        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                    headers={"APIKEY": api_key},
                )
                if resp is not None and resp.status_code == 200:
                    data = resp.json()
                    for sub in data.get("subdomains", []):
                        fqdn = f"{sub}.{domain}"
                        result.add_asset(Asset(
                            value=fqdn,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[SecurityTrails] Failed: %s", exc)


class WebTechModule(DiscoveryModule):
    """Technology detection from HTTP response headers and body."""
    name = "webtech"
    description = "Technology fingerprinting from HTTP responses"

    FINGERPRINTS = {
        # Header-based
        "x-powered-by: php": "PHP",
        "x-powered-by: express": "Express.js",
        "x-powered-by: asp.net": "ASP.NET",
        "server: nginx": "Nginx",
        "server: apache": "Apache",
        "server: cloudflare": "Cloudflare",
        "server: iis": "IIS",
        "server: gunicorn": "Gunicorn",
        "server: openresty": "OpenResty",
        "x-amz-cf-id": "CloudFront",
        "x-cache": "CDN",
        # Body-based
        "wp-content": "WordPress",
        "wp-json": "WordPress",
        "drupal": "Drupal",
        "joomla": "Joomla",
        "shopify": "Shopify",
        "squarespace": "Squarespace",
        "wix.com": "Wix",
        "react": "React",
        "angular": "Angular",
        "vue.js": "Vue.js",
        "next.js": "Next.js",
        "nuxt": "Nuxt.js",
        "gatsby": "Gatsby",
        "laravel": "Laravel",
        "django": "Django",
        "flask": "Flask",
        "spring": "Spring",
        "rails": "Ruby on Rails",
        "bootstrap": "Bootstrap",
        "tailwind": "Tailwind CSS",
        "jquery": "jQuery",
        "recaptcha": "reCAPTCHA",
        "google-analytics": "Google Analytics",
        "gtag": "Google Tag Manager",
        "stripe": "Stripe",
        "intercom": "Intercom",
        "zendesk": "Zendesk",
        "hubspot": "HubSpot",
        "cloudflare": "Cloudflare",
    }

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        live_assets = [a for a in result.assets
                      if a.status == AssetStatus.LIVE
                      and a.type in (AssetType.DOMAIN, AssetType.SUBDOMAIN)]

        async def detect_tech(asset: Asset) -> None:
            try:
                async with httpx.AsyncClient(
                    timeout=config.http_timeout, verify=False, follow_redirects=True
                ) as client:
                    resp = await client.get(f"https://{asset.value}")
                    content = (str(resp.headers) + resp.text[:10000]).lower()

                    techs = []
                    for pattern, tech in self.FINGERPRINTS.items():
                        if pattern in content and tech not in techs:
                            techs.append(tech)

                    if techs:
                        asset.technologies.extend([t for t in techs if t not in asset.technologies])
                        for tech in techs:
                            result.add_asset(Asset(
                                value=tech,
                                type=AssetType.TECHNOLOGY,
                                parent=asset.value,
                                source=self.name,
                            ))
            except Exception:
                pass

        # Batch probe
        for i in range(0, len(live_assets), config.webtech_batch_size):
            batch = live_assets[i : i + config.webtech_batch_size]
            await asyncio.gather(*[detect_tech(a) for a in batch])
            await asyncio.sleep(config.webtech_batch_delay)


class HackerTargetModule(DiscoveryModule):
    """HackerTarget free host search API."""
    name = "hackertarget"
    description = "HackerTarget host search (free, no API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            await _hackertarget_limiter.acquire()
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://api.hackertarget.com/hostsearch/?q={domain}",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[HackerTarget] No data (status=%s)", resp.status_code if resp else "timeout")
                    return

                text = resp.text.strip()
                if not text or "error" in text.lower():
                    logger.warning("[HackerTarget] Empty or error response for %s", domain)
                    return

                for line in text.splitlines():
                    line = line.strip()
                    if not line or "," not in line:
                        continue
                    parts = line.split(",", 1)
                    subdomain = parts[0].strip().lower()
                    ip_addr = parts[1].strip() if len(parts) > 1 else ""

                    if subdomain and subdomain.endswith(domain):
                        result.add_asset(Asset(
                            value=subdomain,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                            ip_addresses=[ip_addr] if ip_addr else [],
                        ))

                    if ip_addr:
                        result.add_asset(Asset(
                            value=ip_addr,
                            type=AssetType.IP,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[HackerTarget] Failed: %s", exc)

        ht_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[HackerTarget] Found %d assets for %s", ht_count, domain)


class URLScanModule(DiscoveryModule):
    """URLScan.io search API for subdomains, URLs, and IPs."""
    name = "urlscan"
    description = "URLScan.io domain search (free, no API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=100",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[URLScan] No data (status=%s)", resp.status_code if resp else "timeout")
                    return

                data = resp.json()
                seen_subdomains: set[str] = set()
                seen_urls: set[str] = set()
                seen_ips: set[str] = set()

                for entry in data.get("results", []):
                    page = entry.get("page", {})
                    page_domain = (page.get("domain") or "").strip().lower()
                    page_url = (page.get("url") or "").strip()
                    page_ip = (page.get("ip") or "").strip()

                    if page_domain and page_domain.endswith(domain) and page_domain not in seen_subdomains:
                        seen_subdomains.add(page_domain)
                        result.add_asset(Asset(
                            value=page_domain,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                        ))

                    # Only add URLs that are ON the target domain
                    if page_url and domain in page_url and page_url not in seen_urls:
                        seen_urls.add(page_url)
                        result.add_asset(Asset(
                            value=page_url[:500],
                            type=AssetType.URL,
                            parent=domain,
                            source=self.name,
                        ))

                    # Only add IPs if the page domain belongs to target
                    if page_ip and page_domain.endswith(domain) and page_ip not in seen_ips:
                        seen_ips.add(page_ip)
                        result.add_asset(Asset(
                            value=page_ip,
                            type=AssetType.IP,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[URLScan] Failed: %s", exc)

        us_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[URLScan] Found %d assets for %s", us_count, domain)


class RapidDNSModule(DiscoveryModule):
    """RapidDNS subdomain enumeration via HTML scraping."""
    name = "rapiddns"
    description = "RapidDNS subdomain lookup (free, no API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://rapiddns.io/subdomain/{domain}?full=1#result",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[RapidDNS] No data (status=%s)", resp.status_code if resp else "timeout")
                    return

                escaped_domain = re.escape(domain)
                pattern = re.compile(
                    r"<td>([a-zA-Z0-9._-]+\." + escaped_domain + r")</td>"
                )

                seen: set[str] = set()
                for match in pattern.finditer(resp.text):
                    subdomain = match.group(1).strip().lower()
                    if subdomain and subdomain not in seen:
                        seen.add(subdomain)
                        result.add_asset(Asset(
                            value=subdomain,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[RapidDNS] Failed: %s", exc)

        rd_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[RapidDNS] Found %d subdomains for %s", rd_count, domain)


class CommonCrawlModule(DiscoveryModule):
    """CommonCrawl index search for URLs."""
    name = "commoncrawl"
    description = "CommonCrawl URL discovery (free, no API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        # Use a fast-fail timeout since CommonCrawl can be slow
        cc_timeout = httpx.Timeout(
            connect=config.osint_connect_timeout,
            read=config.osint_timeout,
            write=config.osint_timeout,
            pool=config.osint_timeout,
        )

        try:
            async with httpx.AsyncClient(timeout=cc_timeout) as client:
                # Step 1: Get latest index
                index_resp = await _fetch_with_retry(
                    client,
                    "https://index.commoncrawl.org/collinfo.json",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if index_resp is None or index_resp.status_code != 200:
                    logger.warning("[CommonCrawl] Could not fetch index list")
                    return

                indexes = index_resp.json()
                if not indexes:
                    logger.warning("[CommonCrawl] Empty index list")
                    return

                cdx_api_url = indexes[0].get("cdx-api")
                if not cdx_api_url:
                    logger.warning("[CommonCrawl] No cdx-api URL in latest index")
                    return

                # Step 2: Query the CDX API
                resp = await _fetch_with_retry(
                    client,
                    f"{cdx_api_url}?url=*.{domain}&output=json&fl=url&limit={config.max_wayback_results}",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[CommonCrawl] CDX query returned no data")
                    return

                seen: set[str] = set()
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        url = obj.get("url", "").strip()
                        if url and url not in seen:
                            seen.add(url)
                            result.add_asset(Asset(
                                value=url[:500],
                                type=AssetType.URL,
                                parent=domain,
                                source=self.name,
                            ))
                    except json.JSONDecodeError:
                        continue
        except Exception as exc:
            logger.warning("[CommonCrawl] Failed: %s", exc)

        cc_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[CommonCrawl] Found %d URLs for %s", cc_count, domain)


class ReverseIPModule(DiscoveryModule):
    """Reverse IP lookup via HackerTarget to find co-hosted domains."""
    name = "reverse_ip"
    description = "Reverse IP lookup via HackerTarget (free, no API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        # Collect unique IPs already discovered
        unique_ips = list({a.value for a in result.get_by_type(AssetType.IP)})
        if not unique_ips:
            logger.info("[ReverseIP] No IPs to look up for %s", domain)
            return

        semaphore = asyncio.Semaphore(config.max_concurrent_probes)

        async def lookup_ip(ip: str) -> None:
            async with semaphore:
                try:
                    async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                        resp = await _fetch_with_retry(
                            client,
                            f"https://api.hackertarget.com/reverseiplookup/?q={ip}",
                            max_retries=config.osint_max_retries,
                            retry_delay=config.osint_retry_delay,
                        )
                        if resp is None or resp.status_code != 200:
                            return

                        text = resp.text.strip()
                        # HackerTarget returns error messages as plain text
                        if not text or "error" in text.lower() or "api count" in text.lower():
                            return

                        for line in text.splitlines():
                            hostname = line.strip().lower()
                            if not hostname or " " in hostname or "error" in hostname:
                                continue
                            # Only add hostnames belonging to the target domain
                            if hostname.endswith(domain):
                                result.add_asset(Asset(
                                    value=hostname,
                                    type=AssetType.SUBDOMAIN,
                                    parent=domain,
                                    source=self.name,
                                    ip_addresses=[ip],
                                ))
                except Exception as exc:
                    logger.warning("[ReverseIP] Lookup failed for %s: %s", ip, exc)

                # Rate limit: HackerTarget free tier
                await asyncio.sleep(1)

        await asyncio.gather(*[lookup_ip(ip) for ip in unique_ips])

        rip_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[ReverseIP] Found %d hostnames for %s", rip_count, domain)


class ThreatMinerModule(DiscoveryModule):
    """ThreatMiner subdomain enumeration API."""
    name = "threatminer"
    description = "ThreatMiner subdomain lookup (free, no API key)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    logger.warning("[ThreatMiner] No data (status=%s)", resp.status_code if resp else "timeout")
                    return

                data = resp.json()
                subdomains = data.get("results", [])
                if not isinstance(subdomains, list):
                    logger.warning("[ThreatMiner] Unexpected response format for %s", domain)
                    return

                seen: set[str] = set()
                for sub in subdomains:
                    if not isinstance(sub, str):
                        continue
                    sub = sub.strip().lower()
                    if sub and sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
                        result.add_asset(Asset(
                            value=sub,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[ThreatMiner] Failed: %s", exc)

        tm_count = len([a for a in result.assets if a.source == self.name])
        logger.info("[ThreatMiner] Found %d subdomains for %s", tm_count, domain)


class AnubisDBModule(DiscoveryModule):
    """Anubis DB — massive subdomain database. Free, no API key."""
    name = "anubis_db"
    description = "Anubis DB subdomain database (jldc.me)"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(
                timeout=_osint_timeout(config), follow_redirects=True
            ) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://jldc.me/anubis/subdomains/{domain}",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    return

                subdomains = resp.json()
                if not isinstance(subdomains, list):
                    return

                seen: set[str] = set()
                for sub in subdomains:
                    sub = str(sub).strip().lower()
                    if sub and sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
                        result.add_asset(Asset(
                            value=sub,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[AnubisDB] Failed: %s", exc)

        count = len([a for a in result.assets if a.source == self.name])
        logger.info("[AnubisDB] Found %d subdomains for %s", count, domain)


class CertSpotterModule(DiscoveryModule):
    """CertSpotter — certificate transparency with SAN extraction. Free tier."""
    name = "certspotter"
    description = "CertSpotter certificate transparency API"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            await _certspotter_limiter.acquire()
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://api.certspotter.com/v1/issuances"
                    f"?domain={domain}&include_subdomains=true&expand=dns_names",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    return

                certs = resp.json()
                if not isinstance(certs, list):
                    return

                seen: set[str] = set()
                for cert in certs:
                    for name in cert.get("dns_names", []):
                        name = name.strip().lower().lstrip("*.")
                        if name and name.endswith(domain) and name not in seen:
                            seen.add(name)
                            result.add_asset(Asset(
                                value=name,
                                type=AssetType.SUBDOMAIN if name != domain else AssetType.DOMAIN,
                                parent=domain,
                                source=self.name,
                                metadata={
                                    "not_after": cert.get("not_after", ""),
                                },
                            ))
        except Exception as exc:
            logger.warning("[CertSpotter] Failed: %s", exc)

        count = len([a for a in result.assets if a.source == self.name])
        logger.info("[CertSpotter] Found %d names for %s", count, domain)


class ShodanInternetDBModule(DiscoveryModule):
    """Shodan InternetDB — FREE, no API key. Ports, vulns, hostnames per IP."""
    name = "shodan_internetdb"
    description = "Shodan InternetDB for open ports, vulns, and hostnames (free)"

    async def discover(self, target: str, result: ScanResult) -> None:
        # Only query IPs from DNS resolution — not random IPs from URLScan etc.
        dns_sources = {"dns-a", "dns-aaaa", "hackertarget"}
        ip_assets = [a for a in result.get_by_type(AssetType.IP) if a.source in dns_sources]
        if not ip_assets:
            return

        config = get_config()
        unique_ips = list({a.value for a in ip_assets if ":" not in a.value})
        sem = asyncio.Semaphore(config.max_concurrent_probes)

        async def _query_ip(ip: str) -> None:
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=config.http_timeout) as client:
                        resp = await client.get(f"https://internetdb.shodan.io/{ip}")
                        if resp.status_code != 200:
                            return

                        data = resp.json()

                        # Add ports
                        for port in data.get("ports", []):
                            result.add_asset(Asset(
                                value=f"{ip}:{port}",
                                type=AssetType.PORT,
                                status=AssetStatus.LIVE,
                                parent=ip,
                                source=self.name,
                            ))

                        # Only add hostnames that belong to the target domain
                        for hostname in data.get("hostnames", []):
                            hostname = hostname.strip().lower()
                            if hostname and hostname.endswith(target):
                                result.add_asset(Asset(
                                    value=hostname,
                                    type=AssetType.SUBDOMAIN,
                                    parent=ip,
                                    source=self.name,
                                ))

                        # Add vulnerabilities to IP metadata
                        vulns = data.get("vulns", [])
                        if vulns:
                            # Find the IP asset and enrich it
                            for asset in ip_assets:
                                if asset.value == ip:
                                    asset.metadata["vulns"] = vulns
                                    asset.metadata["cpes"] = data.get("cpes", [])
                                    if len(vulns) > 5:
                                        asset.severity = Severity.HIGH
                                    elif vulns:
                                        asset.severity = Severity.MEDIUM
                                    break

                except Exception:
                    pass

        await asyncio.gather(*[_query_ip(ip) for ip in unique_ips])

        count = len([a for a in result.assets if a.source == self.name])
        logger.info("[ShodanInternetDB] Found %d assets across %d IPs", count, len(unique_ips))


class SubdomainCenterModule(DiscoveryModule):
    """SubdomainCenter — large subdomain database. Free, no key."""
    name = "subdomain_center"
    description = "SubdomainCenter subdomain database"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://api.subdomain.center/?domain={domain}",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    return

                subdomains = resp.json()
                if not isinstance(subdomains, list):
                    return

                seen: set[str] = set()
                for sub in subdomains:
                    sub = str(sub).strip().lower()
                    if sub and sub.endswith(domain) and sub not in seen:
                        seen.add(sub)
                        result.add_asset(Asset(
                            value=sub,
                            type=AssetType.SUBDOMAIN,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[SubdomainCenter] Failed: %s", exc)

        count = len([a for a in result.assets if a.source == self.name])
        logger.info("[SubdomainCenter] Found %d subdomains for %s", count, domain)


class IPInfoModule(DiscoveryModule):
    """IPInfo.io — IP geolocation, ASN, org enrichment. Free 50k/month."""
    name = "ipinfo"
    description = "IPInfo.io IP geolocation and ASN enrichment (free)"

    async def discover(self, target: str, result: ScanResult) -> None:
        ip_assets = result.get_by_type(AssetType.IP)
        if not ip_assets:
            return

        config = get_config()
        unique_ips = list({a.value for a in ip_assets})
        sem = asyncio.Semaphore(config.max_concurrent_probes)

        async def _enrich_ip(ip: str) -> None:
            async with sem:
                try:
                    async with httpx.AsyncClient(timeout=config.http_timeout) as client:
                        resp = await client.get(f"https://ipinfo.io/{ip}/json")
                        if resp.status_code != 200:
                            return

                        data = resp.json()

                        # Enrich existing IP asset with geo/org data
                        for asset in ip_assets:
                            if asset.value == ip:
                                asset.metadata["hostname"] = data.get("hostname", "")
                                asset.metadata["org"] = data.get("org", "")
                                asset.metadata["city"] = data.get("city", "")
                                asset.metadata["region"] = data.get("region", "")
                                asset.metadata["country"] = data.get("country", "")
                                asset.metadata["loc"] = data.get("loc", "")
                                break

                        # Add hostname as subdomain if it belongs to target
                        hostname = data.get("hostname", "")
                        if hostname and hostname.endswith(target):
                            result.add_asset(Asset(
                                value=hostname,
                                type=AssetType.SUBDOMAIN,
                                parent=ip,
                                source=self.name,
                            ))

                except Exception:
                    pass

        await asyncio.gather(*[_enrich_ip(ip) for ip in unique_ips])

        count = len([a for a in result.assets if a.source == self.name])
        logger.info("[IPInfo] Enriched %d IPs for %s", len(unique_ips), target)


class AlienVaultURLModule(DiscoveryModule):
    """AlienVault OTX URL list — separate from passive DNS. Free."""
    name = "alienvault_urls"
    description = "AlienVault OTX URL history"

    async def discover(self, target: str, result: ScanResult) -> None:
        domain = re.sub(r'[^a-zA-Z0-9.\-]', '', target)
        config = get_config()

        try:
            async with httpx.AsyncClient(timeout=_osint_timeout(config)) as client:
                resp = await _fetch_with_retry(
                    client,
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=200&page=1",
                    max_retries=config.osint_max_retries,
                    retry_delay=config.osint_retry_delay,
                )
                if resp is None or resp.status_code != 200:
                    return

                data = resp.json()
                seen: set[str] = set()
                for entry in data.get("url_list", []):
                    url = entry.get("url", "")
                    if url and url not in seen:
                        seen.add(url)
                        result.add_asset(Asset(
                            value=url[:500],
                            type=AssetType.URL,
                            parent=domain,
                            source=self.name,
                        ))
        except Exception as exc:
            logger.warning("[AlienVaultURLs] Failed: %s", exc)

        count = len([a for a in result.assets if a.source == self.name])
        if count:
            logger.info("[AlienVaultURLs] Found %d URLs for %s", count, domain)
