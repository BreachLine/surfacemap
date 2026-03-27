"""Web crawler/spider module for attack surface discovery.

Crawls live hosts to discover URLs, forms, parameters, and API endpoints.
Supports two modes: katana CLI (if available) or built-in BFS crawler using httpx.
"""

from __future__ import annotations

import asyncio
import collections
import json
import logging
import os
import re
from typing import Any
from urllib.parse import urljoin, urlparse

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

# Patterns that hint at API endpoints
_API_PATTERNS = re.compile(
    r"(/api/|/v[0-9]+/|/graphql|/rest/|/rpc/|/ws/|/webhook)",
    re.IGNORECASE,
)

# File extensions to skip during crawling (binary / static assets)
_SKIP_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv",
    ".pdf", ".zip", ".tar", ".gz", ".rar",
    ".exe", ".dmg", ".deb", ".rpm",
})


class WebCrawlerModule(DiscoveryModule):
    """Crawl live hosts to discover URLs, forms, parameters, and API endpoints."""

    name = "Web Crawler"
    description = "Spider live hosts to discover URLs, forms, input parameters, and API endpoints"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        hosts = result.get_live_hosts()

        if not hosts:
            logger.info("[Web Crawler] No live hosts — skipping crawl")
            return

        # Prioritize the target domain and its subdomains first
        priority = [h for h in hosts if h == target or h.endswith("." + target)]
        others = [h for h in hosts if h not in priority]
        hosts = priority + others

        logger.info(
            "[Web Crawler] Crawling %d live hosts (max_depth=%d, max_pages=%d)",
            min(len(hosts), 10),
            config.crawl_max_depth,
            config.crawl_max_pages,
        )

        # Try katana first, fall back to built-in crawler
        used_katana = await self._crawl_katana(hosts, target, result, config)
        if not used_katana:
            logger.info("[Web Crawler] katana not found — using built-in crawler")
            await self._crawl_builtin(hosts, target, result, config)

    # ------------------------------------------------------------------
    # Katana mode
    # ------------------------------------------------------------------

    async def _crawl_katana(
        self,
        hosts: list[str],
        target: str,
        result: ScanResult,
        cfg: Any,
    ) -> bool:
        """Use katana CLI for crawling. Returns False if katana is not installed."""
        import shutil
        import tempfile

        katana_path = shutil.which("katana")
        if not katana_path:
            return False

        logger.info("[Web Crawler] Using katana at %s", katana_path)

        targets_file = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False
            ) as f:
                for host in hosts[:10]:
                    f.write(f"https://{host}\n")
                targets_file = f.name

            cmd = [
                katana_path,
                "-list", targets_file,
                "-d", str(cfg.crawl_max_depth),
                "-jc",          # JavaScript crawling
                "-kf", "all",   # known file discovery
                "-silent",
                "-jsonl",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.crawl_timeout
            )

            for line in stdout.decode(errors="replace").strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    url = data.get("request", {}).get("endpoint", "")
                    parsed_url = urlparse(url) if url else None
                    url_host = parsed_url.netloc.split(":")[0] if parsed_url else ""
                    if url and (url_host == target or url_host.endswith("." + target)):
                        result.add_asset(Asset(
                            value=url,
                            type=AssetType.URL,
                            source="katana",
                        ))
                        # Detect API endpoints
                        if _API_PATTERNS.search(url):
                            result.add_asset(Asset(
                                value=url,
                                type=AssetType.API_ENDPOINT,
                                source="katana",
                            ))
                except json.JSONDecodeError:
                    # Katana may emit plain URLs in some modes
                    stripped = line.strip()
                    if stripped and target in stripped:
                        result.add_asset(Asset(
                            value=stripped,
                            type=AssetType.URL,
                            source="katana",
                        ))

        except asyncio.TimeoutError:
            logger.warning("[Web Crawler] katana timed out after %ds", cfg.crawl_timeout)
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.warning("[Web Crawler] katana failed: %s", e)
            return False
        finally:
            if targets_file:
                try:
                    os.unlink(targets_file)
                except OSError:
                    pass

        return True

    # ------------------------------------------------------------------
    # Built-in BFS crawler
    # ------------------------------------------------------------------

    async def _crawl_builtin(
        self,
        hosts: list[str],
        target: str,
        result: ScanResult,
        cfg: Any,
    ) -> None:
        """BFS crawl using httpx."""
        visited: set[str] = set()
        queue: collections.deque[tuple[str, int]] = collections.deque()

        for host in hosts[:10]:  # cap hosts to crawl
            for scheme in ("https", "http"):
                queue.append((f"{scheme}://{host}/", 0))

        sem = asyncio.Semaphore(cfg.max_concurrent_probes)
        probe_timeout = httpx.Timeout(connect=5, read=cfg.http_timeout, write=10, pool=10)

        async with httpx.AsyncClient(
            timeout=probe_timeout,
            follow_redirects=True,
            verify=False,
            headers={"User-Agent": cfg.user_agent},
            limits=httpx.Limits(max_connections=cfg.max_concurrent_probes),
        ) as client:
            while queue and len(visited) < cfg.crawl_max_pages:
                url, depth = queue.popleft()
                if url in visited or depth > cfg.crawl_max_depth:
                    continue
                visited.add(url)

                # Skip binary / static asset URLs
                parsed_path = urlparse(url).path.lower()
                if any(parsed_path.endswith(ext) for ext in _SKIP_EXTENSIONS):
                    continue

                async with sem:
                    try:
                        resp = await client.get(url)
                    except httpx.ConnectError:
                        continue
                    except httpx.TimeoutException:
                        continue
                    except Exception:
                        continue

                content_type = resp.headers.get("content-type", "")
                if "text/html" not in content_type:
                    continue

                body = resp.text

                # ----- Extract links -----
                for match in re.finditer(
                    r'(?:href|src|action)=["\']([^"\']+)["\']', body
                ):
                    link = match.group(1)
                    abs_url = urljoin(url, link)
                    parsed = urlparse(abs_url)

                    # Stay in scope (exact match or subdomain)
                    netloc = parsed.netloc.split(":")[0]
                    if netloc != target and not netloc.endswith("." + target):
                        continue

                    # Normalize: strip fragment
                    clean_url = abs_url.split("#")[0]

                    if clean_url not in visited:
                        queue.append((clean_url, depth + 1))
                        result.add_asset(Asset(
                            value=clean_url,
                            type=AssetType.URL,
                            source="web-crawler",
                        ))

                    # Detect API endpoints
                    if _API_PATTERNS.search(clean_url):
                        result.add_asset(Asset(
                            value=clean_url,
                            type=AssetType.API_ENDPOINT,
                            source="web-crawler",
                        ))

                    # Extract query parameters
                    if parsed.query:
                        for param in parsed.query.split("&"):
                            param_name = param.split("=")[0]
                            if param_name:
                                result.add_asset(Asset(
                                    value=f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{param_name}",
                                    type=AssetType.PARAMETER,
                                    source="web-crawler",
                                    metadata={"parameter": param_name, "page": url},
                                ))

                # ----- Extract forms -----
                for form_match in re.finditer(
                    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
                    body,
                    re.DOTALL | re.IGNORECASE,
                ):
                    action = urljoin(url, form_match.group(1))
                    form_full = form_match.group(0)
                    form_body = form_match.group(2)

                    # Extract method
                    method = "GET"
                    method_match = re.search(
                        r'method=["\'](\w+)["\']', form_full, re.IGNORECASE
                    )
                    if method_match:
                        method = method_match.group(1).upper()

                    # Extract input names
                    params = re.findall(
                        r'name=["\']([^"\']+)["\']', form_body, re.IGNORECASE
                    )

                    result.add_asset(Asset(
                        value=action,
                        type=AssetType.FORM,
                        source="web-crawler",
                        metadata={
                            "method": method,
                            "parameters": params,
                            "page": url,
                        },
                    ))

                    for param in params:
                        result.add_asset(Asset(
                            value=f"{action}?{param}",
                            type=AssetType.PARAMETER,
                            source="web-crawler",
                            metadata={"parameter": param, "form_action": action},
                        ))

                # ----- Extract script sources -----
                for script_match in re.finditer(
                    r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE
                ):
                    script_url = urljoin(url, script_match.group(1))
                    parsed_script = urlparse(script_url)
                    script_netloc = parsed_script.netloc.split(":")[0]
                    if script_netloc == target or script_netloc.endswith("." + target):
                        result.add_asset(Asset(
                            value=script_url,
                            type=AssetType.URL,
                            source="web-crawler",
                            metadata={"type": "script", "page": url},
                        ))
