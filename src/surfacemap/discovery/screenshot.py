"""Screenshot capture for discovered live hosts.

Attempts to capture screenshots using playwright (preferred) with a
fallback to headless Chrome/Chromium CLI. If neither is available,
the module silently skips.
"""

from __future__ import annotations

import asyncio
import re
import logging
import shutil
from pathlib import Path

from surfacemap.core.config import get_config
from surfacemap.core.models import Asset, AssetType, ScanResult
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)


class ScreenshotModule(DiscoveryModule):
    """Capture screenshots of live web hosts."""

    name = "Screenshots"
    description = "Capture screenshots of live web hosts"

    async def discover(self, target: str, result: ScanResult) -> None:
        cfg = get_config()
        if not cfg.screenshot_enabled:
            logger.info(
                "[%s] Screenshots disabled (set SURFACEMAP_SCREENSHOTS=true).",
                self.name,
            )
            return

        hosts = result.get_live_hosts()
        if not hosts:
            logger.info("[%s] No live hosts to screenshot.", self.name)
            return

        screenshot_dir = cfg.output_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)

        # Try playwright first, then fall back to headless Chrome
        if await self._try_playwright(hosts, target, result, cfg, screenshot_dir):
            return

        if await self._try_chrome(hosts, target, result, cfg, screenshot_dir):
            return

        logger.info(
            "[%s] No screenshot tool available (install playwright or chrome).",
            self.name,
        )

    # ------------------------------------------------------------------
    # Strategy 1: Playwright (async API)
    # ------------------------------------------------------------------

    async def _try_playwright(
        self,
        hosts: list[str],
        target: str,
        result: ScanResult,
        cfg: object,
        screenshot_dir: Path,
    ) -> bool:
        try:
            from playwright.async_api import async_playwright  # noqa: WPS433
        except ImportError:
            return False

        sem = asyncio.Semaphore(5)
        count = 0

        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--ignore-certificate-errors", "--no-sandbox"],
            )

            async def capture(host: str) -> None:
                nonlocal count
                async with sem:
                    page = None
                    try:
                        for scheme in ("https", "http"):
                            page = await browser.new_page(
                                viewport={
                                    "width": cfg.screenshot_width,  # type: ignore[attr-defined]
                                    "height": cfg.screenshot_height,  # type: ignore[attr-defined]
                                },
                                ignore_https_errors=True,
                            )
                            try:
                                # Short timeout for HTTPS probe (3s), full timeout for HTTP
                                probe_timeout = 3000 if scheme == "https" else cfg.screenshot_timeout * 1000  # type: ignore[attr-defined]
                                await page.goto(
                                    f"{scheme}://{host}",
                                    timeout=probe_timeout,
                                    wait_until="domcontentloaded",
                                )
                                break
                            except Exception:
                                await page.close()
                                page = None
                                continue
                        else:
                            return

                        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', host)
                        path = screenshot_dir / f"{safe_name}.png"
                        await page.screenshot(path=str(path))

                        result.add_asset(Asset(
                            value=str(path),
                            type=AssetType.URL,
                            source="screenshot",
                            parent=host,
                            metadata={
                                "screenshot_path": str(path),
                                "host": host,
                            },
                        ))
                        count += 1
                    except Exception as e:
                        logger.debug(
                            "[%s] Failed to screenshot %s: %s",
                            self.name, host, e,
                        )
                    finally:
                        if page:
                            await page.close()

            # Cap at 20 hosts to avoid extremely long runtimes
            await asyncio.gather(*[capture(h) for h in hosts[:20]])
            await browser.close()

        logger.info("[%s] Captured %d screenshots.", self.name, count)
        return True

    # ------------------------------------------------------------------
    # Strategy 2: Headless Chrome / Chromium CLI
    # ------------------------------------------------------------------

    async def _try_chrome(
        self,
        hosts: list[str],
        target: str,
        result: ScanResult,
        cfg: object,
        screenshot_dir: Path,
    ) -> bool:
        chrome_path = None
        for name in (
            "google-chrome",
            "chromium",
            "chromium-browser",
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        ):
            found = shutil.which(name)
            if found:
                chrome_path = found
                break

        if not chrome_path:
            return False

        count = 0
        sem = asyncio.Semaphore(3)

        async def capture(host: str) -> None:
            nonlocal count
            async with sem:
                safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', host)
                path = screenshot_dir / f"{safe_name}.png"
                for scheme in ("https", "http"):
                    cmd = [
                        chrome_path,
                        "--headless=new",
                        "--disable-gpu",
                        "--no-sandbox",
                        "--ignore-certificate-errors",
                        f"--screenshot={path}",
                        f"--window-size={cfg.screenshot_width},{cfg.screenshot_height}",
                        f"{scheme}://{host}",
                    ]
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            *cmd,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        await asyncio.wait_for(
                            proc.communicate(),
                            timeout=cfg.screenshot_timeout if scheme == "http" else 5,
                        )
                        if path.exists() and path.stat().st_size > 1000:
                            break
                    except (asyncio.TimeoutError, Exception):
                        continue

                if path.exists() and path.stat().st_size > 1000:
                    result.add_asset(Asset(
                        value=str(path),
                        type=AssetType.URL,
                        source="screenshot",
                        parent=host,
                        metadata={
                            "screenshot_path": str(path),
                            "host": host,
                        },
                    ))
                    count += 1

        await asyncio.gather(*[capture(h) for h in hosts[:20]])
        logger.info("[%s] Captured %d screenshots via Chrome.", self.name, count)
        return count > 0
