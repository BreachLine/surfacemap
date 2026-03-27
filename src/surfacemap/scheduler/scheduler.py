"""Scheduled scan execution with diff-based alerting."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from surfacemap.core.config import get_config
from surfacemap.discovery.engine import DiscoveryEngine
from surfacemap.scheduler.differ import compute_diff, format_diff_summary
from surfacemap.storage.db import ScanDatabase

logger = logging.getLogger(__name__)


def _parse_interval(interval: str) -> int:
    """Parse interval string like '24h', '30m', '1d' to seconds."""
    interval = interval.strip().lower()
    try:
        if interval.endswith("d"):
            seconds = int(interval[:-1]) * 86400
        elif interval.endswith("h"):
            seconds = int(interval[:-1]) * 3600
        elif interval.endswith("m"):
            seconds = int(interval[:-1]) * 60
        else:
            seconds = int(interval)
    except ValueError:
        raise ValueError(f"Invalid interval format: {interval!r}. Use e.g. '24h', '30m', '1d'")
    if seconds <= 0:
        raise ValueError(f"Interval must be positive, got {seconds}s")
    return seconds


async def run_scheduled_scan(
    target: str,
    domain: str | None = None,
    interval: str = "24h",
    enrich: bool = False,
    passive_only: bool = False,
) -> None:
    """Run scans on a schedule, diffing results and alerting on changes."""
    cfg = get_config()
    db = ScanDatabase()
    await db.initialize()

    interval_seconds = _parse_interval(interval)
    logger.info("Starting scheduled monitoring for %s every %s", target, interval)

    previous_result = None

    while True:
        logger.info("[Scheduler] Starting scan for %s at %s",
                     target, datetime.now(timezone.utc).isoformat())

        try:
            engine = DiscoveryEngine(
                target=target,
                domain=domain or target,
                enrich=enrich,
                passive_only=passive_only,
            )
            result = await engine.run()
            await db.save_scan(result)

            if previous_result:
                diff = compute_diff(previous_result, result)
                summary = format_diff_summary(diff)
                logger.info("[Scheduler] Diff:\n%s", summary)

                if diff["added_count"] > 0 or diff["removed_count"] > 0:
                    if cfg.has_slack:
                        try:
                            from surfacemap.notifications.slack import send_slack_notification
                            await send_slack_notification(
                                f"*SurfaceMap Monitor Alert*\n```{summary}```"
                            )
                        except Exception as e:
                            logger.warning("Slack notification failed: %s", e)

            previous_result = result

        except Exception as e:
            logger.error("[Scheduler] Scan failed: %s", e)

        logger.info("[Scheduler] Next scan in %s", interval)
        await asyncio.sleep(interval_seconds)
