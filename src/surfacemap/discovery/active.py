"""Active discovery modules for attack surface analysis.

Performs active probing against live hosts to discover sensitive files,
JavaScript-embedded secrets, CORS misconfigurations, and cookie security issues.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

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

# Severity mapping for sensitive paths — keys are normalized lowercase path fragments.
_SENSITIVE_PATH_SEVERITY: dict[str, Severity] = {
    ".git/head": Severity.HIGH,
    ".git/config": Severity.HIGH,
    ".env": Severity.CRITICAL,
    ".env.local": Severity.CRITICAL,
    ".env.production": Severity.CRITICAL,
    "robots.txt": Severity.INFO,
    "sitemap.xml": Severity.INFO,
    "actuator/env": Severity.CRITICAL,
    "actuator/configprops": Severity.CRITICAL,
    "backup.sql": Severity.CRITICAL,
    "dump.sql": Severity.CRITICAL,
    "database.sql": Severity.CRITICAL,
    "db.sql": Severity.CRITICAL,
    "phpinfo.php": Severity.HIGH,
    "info.php": Severity.HIGH,
    "swagger.json": Severity.MEDIUM,
    "swagger/index.html": Severity.MEDIUM,
    "openapi.json": Severity.MEDIUM,
    "api-docs": Severity.MEDIUM,
    "admin": Severity.MEDIUM,
    "wp-admin": Severity.MEDIUM,
    "wp-login.php": Severity.MEDIUM,
    "administrator": Severity.MEDIUM,
    "_admin": Severity.MEDIUM,
    "login": Severity.MEDIUM,
    ".htpasswd": Severity.CRITICAL,
    ".aws/credentials": Severity.CRITICAL,
    "config/database.yml": Severity.CRITICAL,
    "wp-config.php.bak": Severity.CRITICAL,
    "config.php.bak": Severity.CRITICAL,
    ".dockerenv": Severity.MEDIUM,
    "docker-compose.yml": Severity.MEDIUM,
    "server-status": Severity.MEDIUM,
    "server-info": Severity.MEDIUM,
    "debug": Severity.MEDIUM,
    "elmah.axd": Severity.MEDIUM,
    "graphql": Severity.MEDIUM,
    "graphiql": Severity.MEDIUM,
    "backup.zip": Severity.CRITICAL,
    "backup.tar.gz": Severity.CRITICAL,
    "site.tar.gz": Severity.CRITICAL,
    "phpmyadmin": Severity.HIGH,
    "adminer": Severity.HIGH,
}

# Default severity when a path is not in the explicit mapping
_DEFAULT_PATH_SEVERITY = Severity.LOW


def _severity_for_path(path: str) -> Severity:
    """Look up the severity for a sensitive path, falling back to default."""
    normalized = path.strip("/").lower()
    if normalized in _SENSITIVE_PATH_SEVERITY:
        return _SENSITIVE_PATH_SEVERITY[normalized]
    # Check partial matches for admin-style paths
    for key, severity in _SENSITIVE_PATH_SEVERITY.items():
        if normalized.endswith(key) or normalized.startswith(key):
            return severity
    return _DEFAULT_PATH_SEVERITY


# ---------------------------------------------------------------------------
# 1. SensitivePathModule
# ---------------------------------------------------------------------------


class SensitivePathModule(DiscoveryModule):
    """Probe live hosts for sensitive files and paths."""

    name = "Sensitive Path Probe"
    description = "Probe live hosts for exposed sensitive files, admin panels, and configuration endpoints"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        live_hosts = result.get_live_hosts()
        if not live_hosts:
            logger.info("No live hosts — skipping sensitive path probing")
            return

        sem = asyncio.Semaphore(config.max_concurrent_paths)
        tasks: list[asyncio.Task[None]] = []

        for host in live_hosts:
            for path in config.sensitive_paths:
                path = path.strip()
                if not path:
                    continue
                tasks.append(
                    asyncio.ensure_future(
                        self._probe_path(host, path, target, result, sem, config)
                    )
                )

        await asyncio.gather(*tasks)

    async def _probe_path(
        self,
        host: str,
        path: str,
        parent: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: Any,
    ) -> None:
        """Probe a single path on a host, trying HTTPS then HTTP."""
        async with sem:
            for scheme in ("https", "http"):
                url = f"{scheme}://{host}/{path.lstrip('/')}"
                try:
                    async with httpx.AsyncClient(
                        timeout=config.active_probe_timeout,
                        follow_redirects=True,
                        verify=False,
                        headers={"User-Agent": config.user_agent},
                    ) as client:
                        resp = await client.get(url)

                    if resp.status_code == 200 and len(resp.content) > 0:
                        severity = _severity_for_path(path)
                        result.add_asset(Asset(
                            value=url,
                            type=AssetType.SENSITIVE_FILE,
                            status=AssetStatus.LIVE,
                            parent=host,
                            source="sensitive-path-probe",
                            severity=severity,
                            metadata={
                                "path": path,
                                "status_code": resp.status_code,
                                "content_length": len(resp.content),
                                "content_type": resp.headers.get("content-type", ""),
                                "scheme": scheme,
                            },
                            notes=f"Sensitive path '{path}' accessible on {host}",
                        ))
                        logger.info(
                            "Found sensitive path %s on %s [%s]",
                            path,
                            host,
                            severity.value,
                        )
                        # Found on this scheme — no need to try the other
                        break

                except (httpx.ConnectError, httpx.ConnectTimeout):
                    continue
                except httpx.TimeoutException:
                    logger.debug("Timeout probing %s", url)
                    continue
                except Exception as exc:
                    logger.debug("Error probing %s: %s", url, exc)
                    continue


# ---------------------------------------------------------------------------
# 2. JSAnalysisModule
# ---------------------------------------------------------------------------

# Regex to extract <script src="..."> URLs from HTML
_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+src\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# Patterns applied to JS content
_API_ENDPOINT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*["'`](\/[^"'`\s]+)["'`]"""),
    re.compile(r"""["'`](\/api\/v[0-9]+\/[^"'`\s]*)["'`]"""),
    re.compile(r"""["'`](\/api\/[^"'`\s]+)["'`]"""),
    re.compile(r"""["'`](\/graphql[^"'`\s]*)["'`]"""),
    re.compile(r"""["'`](\/v[0-9]+\/[^"'`\s]+)["'`]"""),
]

_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""(?:apiKey|api_key|apikey|API_KEY)\s*[:=]\s*["'`]([^"'`]{8,})["'`]"""), "API Key"),
    (re.compile(r"""(?:AKIA[0-9A-Z]{16})"""), "AWS Access Key"),
    (re.compile(r"""eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"""), "JWT Token"),
    (re.compile(r"""-----BEGIN\s(?:RSA\s)?PRIVATE\sKEY-----"""), "Private Key"),
    (re.compile(r"""(?:secret_key|SECRET_KEY|secretKey)\s*[:=]\s*["'`]([^"'`]{8,})["'`]"""), "Secret Key"),
    (re.compile(r"""(?:password|passwd|PASSWD|PASSWORD)\s*[:=]\s*["'`]([^"'`]{4,})["'`]"""), "Hardcoded Password"),
    (re.compile(r"""(?:client_secret|CLIENT_SECRET|clientSecret)\s*[:=]\s*["'`]([^"'`]{8,})["'`]"""), "Client Secret"),
    (re.compile(r"""(?:token|TOKEN|auth_token|AUTH_TOKEN)\s*[:=]\s*["'`]([A-Za-z0-9_\-]{20,})["'`]"""), "Auth Token"),
]

_CLOUD_URL_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"""[a-z0-9][a-z0-9\-]*\.s3\.amazonaws\.com"""), "AWS S3"),
    (re.compile(r"""s3\.amazonaws\.com/[a-z0-9][a-z0-9\-]*"""), "AWS S3"),
    (re.compile(r"""[a-z0-9][a-z0-9\-]*\.blob\.core\.windows\.net"""), "Azure Blob"),
    (re.compile(r"""storage\.googleapis\.com/[a-z0-9][a-z0-9\-]*"""), "Google Cloud Storage"),
    (re.compile(r"""[a-z0-9][a-z0-9\-]*\.storage\.googleapis\.com"""), "Google Cloud Storage"),
]


class JSAnalysisModule(DiscoveryModule):
    """Analyze JavaScript files for embedded secrets, API endpoints, and subdomains."""

    name = "JavaScript Analysis"
    description = "Extract API endpoints, subdomains, secrets, and cloud URLs from JavaScript files"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        live_hosts = result.get_live_hosts()
        if not live_hosts:
            logger.info("No live hosts — skipping JS analysis")
            return

        sem = asyncio.Semaphore(config.max_concurrent_js)
        tasks = [
            asyncio.ensure_future(
                self._analyze_host(host, target, result, sem, config)
            )
            for host in live_hosts
        ]
        await asyncio.gather(*tasks)

    async def _analyze_host(
        self,
        host: str,
        target: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: Any,
    ) -> None:
        """Fetch the homepage and analyze all linked JS files."""
        async with sem:
            html = await self._fetch_homepage(host, config)
            if not html:
                return

            script_urls = self._extract_script_urls(html, host)
            if not script_urls:
                logger.debug("No script URLs found on %s", host)
                return

            for js_url in script_urls:
                await self._analyze_js_file(js_url, host, target, result, config)

    async def _fetch_homepage(self, host: str, config: Any) -> str | None:
        """Fetch the homepage HTML from a host."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                async with httpx.AsyncClient(
                    timeout=config.js_analysis_timeout,
                    follow_redirects=True,
                    verify=False,
                    headers={"User-Agent": config.user_agent},
                ) as client:
                    resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text
            except (httpx.ConnectError, httpx.ConnectTimeout):
                continue
            except httpx.TimeoutException:
                continue
            except Exception as exc:
                logger.debug("Error fetching homepage %s: %s", url, exc)
                continue
        return None

    def _extract_script_urls(self, html: str, host: str) -> list[str]:
        """Extract all <script src="..."> URLs from HTML."""
        raw_urls = _SCRIPT_SRC_RE.findall(html)
        resolved: list[str] = []
        seen: set[str] = set()

        for raw in raw_urls:
            url = raw.strip()
            if url.startswith("//"):
                url = f"https:{url}"
            elif url.startswith("/"):
                url = f"https://{host}{url}"
            elif not url.startswith(("http://", "https://")):
                url = f"https://{host}/{url}"

            if url not in seen:
                seen.add(url)
                resolved.append(url)

        return resolved

    async def _analyze_js_file(
        self,
        js_url: str,
        host: str,
        target: str,
        result: ScanResult,
        config: Any,
    ) -> None:
        """Fetch and analyze a single JS file for secrets and endpoints."""
        try:
            async with httpx.AsyncClient(
                timeout=config.js_analysis_timeout,
                follow_redirects=True,
                verify=False,
                headers={"User-Agent": config.user_agent},
            ) as client:
                resp = await client.get(js_url)
            if resp.status_code != 200:
                return
            js_content = resp.text
        except (httpx.ConnectError, httpx.ConnectTimeout):
            return
        except httpx.TimeoutException:
            return
        except Exception as exc:
            logger.debug("Error fetching JS %s: %s", js_url, exc)
            return

        # Extract API endpoints
        self._extract_api_endpoints(js_content, js_url, host, result)

        # Extract subdomains for the target domain
        self._extract_subdomains(js_content, js_url, host, target, result)

        # Extract secrets
        self._extract_secrets(js_content, js_url, host, result)

        # Extract cloud URLs
        self._extract_cloud_urls(js_content, js_url, host, result)

    def _extract_api_endpoints(
        self,
        js_content: str,
        js_url: str,
        host: str,
        result: ScanResult,
    ) -> None:
        """Find API endpoint patterns in JS content."""
        seen: set[str] = set()
        for pattern in _API_ENDPOINT_PATTERNS:
            for match in pattern.finditer(js_content):
                endpoint = match.group(1) if match.lastindex else match.group(0)
                if endpoint in seen:
                    continue
                seen.add(endpoint)
                result.add_asset(Asset(
                    value=endpoint,
                    type=AssetType.API_ENDPOINT,
                    status=AssetStatus.UNKNOWN,
                    parent=host,
                    source="js-analysis",
                    severity=Severity.INFO,
                    metadata={
                        "found_in": js_url,
                        "host": host,
                    },
                    notes=f"API endpoint found in {js_url}",
                ))

    def _extract_subdomains(
        self,
        js_content: str,
        js_url: str,
        host: str,
        target: str,
        result: ScanResult,
    ) -> None:
        """Find subdomains of the target domain in JS content."""
        # Escape dots in domain for regex
        escaped_domain = re.escape(target)
        subdomain_pattern = re.compile(
            rf"""[a-z0-9](?:[a-z0-9\-]{{0,61}}[a-z0-9])?\.{escaped_domain}""",
            re.IGNORECASE,
        )
        seen: set[str] = set()
        for match in subdomain_pattern.finditer(js_content):
            subdomain = match.group(0).lower()
            if subdomain == target or subdomain in seen:
                continue
            seen.add(subdomain)
            result.add_asset(Asset(
                value=subdomain,
                type=AssetType.SUBDOMAIN,
                status=AssetStatus.UNKNOWN,
                parent=target,
                source="js-analysis",
                severity=Severity.INFO,
                metadata={
                    "found_in": js_url,
                    "host": host,
                },
                notes=f"Subdomain found in {js_url}",
            ))

    def _extract_secrets(
        self,
        js_content: str,
        js_url: str,
        host: str,
        result: ScanResult,
    ) -> None:
        """Find potential secret values in JS content."""
        seen: set[str] = set()
        for pattern, secret_type in _SECRET_PATTERNS:
            for match in pattern.finditer(js_content):
                secret_value = match.group(0)
                if secret_value in seen:
                    continue
                seen.add(secret_value)

                # Determine severity by type
                severity = Severity.HIGH
                if secret_type in ("AWS Access Key", "Private Key"):
                    severity = Severity.CRITICAL
                elif secret_type == "JWT Token":
                    severity = Severity.HIGH
                elif secret_type == "API Key":
                    severity = Severity.HIGH

                # Redact the secret value for storage
                redacted = secret_value[:8] + "..." + secret_value[-4:] if len(secret_value) > 16 else secret_value[:4] + "..."

                result.add_asset(Asset(
                    value=f"{secret_type} in {js_url}",
                    type=AssetType.SECRET_LEAK,
                    status=AssetStatus.VULNERABLE,
                    parent=host,
                    source="js-analysis",
                    severity=severity,
                    metadata={
                        "secret_type": secret_type,
                        "found_in": js_url,
                        "host": host,
                        "redacted_value": redacted,
                    },
                    notes=f"{secret_type} found in {js_url}",
                ))

    def _extract_cloud_urls(
        self,
        js_content: str,
        js_url: str,
        host: str,
        result: ScanResult,
    ) -> None:
        """Find cloud storage URLs in JS content."""
        seen: set[str] = set()
        for pattern, cloud_provider in _CLOUD_URL_PATTERNS:
            for match in pattern.finditer(js_content):
                cloud_url = match.group(0)
                if cloud_url in seen:
                    continue
                seen.add(cloud_url)
                result.add_asset(Asset(
                    value=cloud_url,
                    type=AssetType.CLOUD_BUCKET,
                    status=AssetStatus.UNKNOWN,
                    parent=host,
                    source="js-analysis",
                    severity=Severity.MEDIUM,
                    metadata={
                        "provider": cloud_provider,
                        "found_in": js_url,
                        "host": host,
                    },
                    notes=f"{cloud_provider} URL found in {js_url}",
                ))


# ---------------------------------------------------------------------------
# 3. CORSCheckModule
# ---------------------------------------------------------------------------


class CORSCheckModule(DiscoveryModule):
    """Check live hosts for CORS misconfigurations."""

    name = "CORS Check"
    description = "Detect CORS misconfigurations that could allow cross-origin data theft"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        live_hosts = result.get_live_hosts()
        if not live_hosts:
            logger.info("No live hosts — skipping CORS check")
            return

        sem = asyncio.Semaphore(config.max_concurrent_probes)
        tasks = [
            asyncio.ensure_future(
                self._check_host(host, target, result, sem, config)
            )
            for host in live_hosts
        ]
        await asyncio.gather(*tasks)

    async def _check_host(
        self,
        host: str,
        target: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: Any,
    ) -> None:
        """Test CORS on a single host with multiple origins."""
        async with sem:
            # Test with evil.com origin
            await self._test_origin(
                host, "https://evil.com", target, result, config
            )
            # Test with null origin
            await self._test_origin(
                host, "null", target, result, config
            )

    async def _test_origin(
        self,
        host: str,
        origin: str,
        target: str,
        result: ScanResult,
        config: Any,
    ) -> None:
        """Send a request with a specific Origin header and analyze the response."""
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/"
            try:
                async with httpx.AsyncClient(
                    timeout=config.http_timeout,
                    follow_redirects=True,
                    verify=False,
                    headers={
                        "User-Agent": config.user_agent,
                        "Origin": origin,
                    },
                ) as client:
                    resp = await client.get(url)

                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "").lower()
                has_credentials = acac == "true"

                if not acao:
                    # No CORS header — nothing to flag on this scheme
                    if scheme == "https":
                        continue
                    break

                severity: Severity | None = None
                description = ""

                if acao == "*":
                    severity = Severity.MEDIUM
                    description = "Wildcard Access-Control-Allow-Origin (*)"
                elif acao == origin and origin != "null":
                    # Reflects arbitrary origin
                    if has_credentials:
                        severity = Severity.CRITICAL
                        description = (
                            f"Reflects arbitrary origin '{origin}' "
                            f"with Access-Control-Allow-Credentials: true"
                        )
                    else:
                        severity = Severity.HIGH
                        description = f"Reflects arbitrary origin '{origin}'"
                elif acao == "null" and origin == "null":
                    if has_credentials:
                        severity = Severity.HIGH
                        description = (
                            "Allows null origin with "
                            "Access-Control-Allow-Credentials: true"
                        )
                    else:
                        severity = Severity.MEDIUM
                        description = "Allows null origin"

                if severity is not None:
                    result.add_asset(Asset(
                        value=f"CORS misconfiguration on {url}",
                        type=AssetType.CORS_MISCONFIGURATION,
                        status=AssetStatus.MISCONFIGURED,
                        parent=host,
                        source="cors-check",
                        severity=severity,
                        metadata={
                            "url": url,
                            "tested_origin": origin,
                            "acao_header": acao,
                            "acac_header": acac,
                            "has_credentials": has_credentials,
                            "scheme": scheme,
                        },
                        notes=description,
                    ))
                    logger.info(
                        "CORS issue on %s: %s [%s]",
                        host,
                        description,
                        severity.value,
                    )
                    # Found an issue on this scheme — no need to test the other
                    break

            except (httpx.ConnectError, httpx.ConnectTimeout):
                continue
            except httpx.TimeoutException:
                logger.debug("Timeout during CORS check on %s", url)
                continue
            except Exception as exc:
                logger.debug("Error during CORS check on %s: %s", url, exc)
                continue


# ---------------------------------------------------------------------------
# 4. CookieSecurityModule
# ---------------------------------------------------------------------------


class CookieSecurityModule(DiscoveryModule):
    """Analyze cookies from existing scan results for security issues."""

    name = "Cookie Security"
    description = "Check cookies for missing Secure, HttpOnly, and SameSite attributes"

    async def discover(self, target: str, result: ScanResult) -> None:
        url_assets = result.get_by_type(AssetType.URL)
        if not url_assets:
            logger.info("No URL assets — skipping cookie security check")
            return

        for asset in url_assets:
            response_headers = asset.metadata.get("response_headers", {})
            if not response_headers:
                continue

            host = asset.parent or asset.value.split("://", 1)[-1].split("/", 1)[0]
            scheme = asset.metadata.get("scheme", "")
            is_https = scheme == "https" or asset.value.startswith("https://")

            # Collect all Set-Cookie values (headers may be multi-valued)
            set_cookie_values = self._get_set_cookie_values(response_headers)
            if not set_cookie_values:
                continue

            for cookie_header in set_cookie_values:
                self._analyze_cookie(
                    cookie_header, host, is_https, asset.value, result
                )

    def _get_set_cookie_values(
        self, headers: dict[str, Any]
    ) -> list[str]:
        """Extract all Set-Cookie header values from response headers.

        Headers may be stored as a dict with string values, or the value
        may be a list if multiple Set-Cookie headers were present.
        """
        values: list[str] = []
        for key, val in headers.items():
            if key.lower() == "set-cookie":
                if isinstance(val, list):
                    values.extend(val)
                elif isinstance(val, str):
                    # httpx collapses multi-valued headers with ', ' but
                    # cookies may contain commas in expires; split on newlines
                    # if present, otherwise treat as single.
                    values.append(val)
        return values

    def _analyze_cookie(
        self,
        cookie_header: str,
        host: str,
        is_https: bool,
        source_url: str,
        result: ScanResult,
    ) -> None:
        """Analyze a single Set-Cookie header for security issues."""
        parts = cookie_header.split(";")
        if not parts:
            return

        # Cookie name is before the first '='
        cookie_name_val = parts[0].strip()
        cookie_name = cookie_name_val.split("=", 1)[0].strip() if "=" in cookie_name_val else cookie_name_val

        # Parse attributes (case-insensitive)
        attrs_lower = [p.strip().lower() for p in parts[1:]]
        attrs_set = set(attrs_lower)

        has_secure = any(a == "secure" for a in attrs_set)
        has_httponly = any(a == "httponly" for a in attrs_set)
        samesite_value = self._get_samesite_value(attrs_lower)

        issues: list[tuple[str, Severity]] = []

        # Missing Secure on HTTPS
        if is_https and not has_secure:
            issues.append(
                (f"Cookie '{cookie_name}' missing Secure flag on HTTPS", Severity.MEDIUM)
            )

        # Missing HttpOnly
        if not has_httponly:
            issues.append(
                (f"Cookie '{cookie_name}' missing HttpOnly flag", Severity.LOW)
            )

        # SameSite=None without Secure
        if samesite_value == "none" and not has_secure:
            issues.append(
                (f"Cookie '{cookie_name}' has SameSite=None without Secure flag", Severity.MEDIUM)
            )

        for description, severity in issues:
            result.add_asset(Asset(
                value=description,
                type=AssetType.COOKIE_ISSUE,
                status=AssetStatus.MISCONFIGURED,
                parent=host,
                source="cookie-security",
                severity=severity,
                metadata={
                    "cookie_name": cookie_name,
                    "has_secure": has_secure,
                    "has_httponly": has_httponly,
                    "samesite": samesite_value,
                    "source_url": source_url,
                    "is_https": is_https,
                    "raw_header": cookie_header,
                },
                notes=description,
            ))
            logger.info(
                "Cookie issue on %s: %s [%s]",
                host,
                description,
                severity.value,
            )

    @staticmethod
    def _get_samesite_value(attrs_lower: list[str]) -> str | None:
        """Extract the SameSite attribute value from cookie attributes."""
        for attr in attrs_lower:
            if attr.startswith("samesite="):
                return attr.split("=", 1)[1].strip()
            if attr == "samesite":
                # SameSite without value defaults to Lax in modern browsers
                return "lax"
        return None
