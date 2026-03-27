"""Slack notifications for scan results.

Sends rich Block Kit formatted messages when scans complete.
Supports both webhook and Bot Token authentication.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from surfacemap import __version__
from surfacemap.core.config import get_config
from surfacemap.core.models import ScanResult

logger = logging.getLogger(__name__)


async def send_slack_notification(
    message: str,
    blocks: list[dict[str, Any]] | None = None,
) -> bool:
    """Send a Slack notification via webhook or Bot API.

    Args:
        message: Fallback text for the notification.
        blocks: Optional Block Kit blocks for rich formatting.

    Returns:
        True if the notification was sent successfully.
    """
    config = get_config()

    if not config.has_slack:
        logger.debug("Slack not configured — skipping notification")
        return False

    try:
        if config.slack_webhook_url:
            return await _send_via_webhook(
                config.slack_webhook_url, message, blocks
            )
        elif config.slack_bot_token:
            return await _send_via_bot(
                config.slack_bot_token, config.slack_channel, message, blocks
            )
    except Exception as e:
        logger.error("Failed to send Slack notification: %s", e)

    return False


async def _send_via_webhook(
    webhook_url: str,
    message: str,
    blocks: list[dict[str, Any]] | None,
) -> bool:
    """Send via Slack incoming webhook."""
    config = get_config()
    payload: dict[str, Any] = {"text": message}
    if blocks:
        payload["blocks"] = blocks

    async with httpx.AsyncClient(timeout=config.slack_timeout) as client:
        resp = await client.post(webhook_url, json=payload)
        if resp.status_code == 200:
            logger.info("Slack webhook notification sent")
            return True
        else:
            logger.error(
                "Slack webhook failed: %d %s", resp.status_code, resp.text
            )
            return False


async def _send_via_bot(
    token: str,
    channel: str,
    message: str,
    blocks: list[dict[str, Any]] | None,
) -> bool:
    """Send via Slack Bot Token (chat.postMessage)."""
    config = get_config()
    payload: dict[str, Any] = {
        "channel": channel,
        "text": message,
    }
    if blocks:
        payload["blocks"] = blocks

    async with httpx.AsyncClient(timeout=config.slack_timeout) as client:
        resp = await client.post(
            "https://slack.com/api/chat.postMessage",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        if data.get("ok"):
            logger.info("Slack bot notification sent to %s", channel)
            return True
        else:
            logger.error("Slack bot failed: %s", data.get("error"))
            return False


async def notify_scan_complete(result: ScanResult) -> bool:
    """Send a rich scan completion notification to Slack.

    Formats the scan results as a Block Kit message with sections
    for summary, findings by severity, and key assets.
    """
    stats = result.compute_stats()

    # Build severity line
    severity_parts = []
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = stats["by_severity"].get(sev, 0)
        if count > 0:
            emoji = {
                "critical": ":red_circle:",
                "high": ":large_orange_circle:",
                "medium": ":large_yellow_circle:",
                "low": ":large_blue_circle:",
                "info": ":white_circle:",
            }.get(sev, ":white_circle:")
            severity_parts.append(f"{emoji} {sev.upper()}: {count}")

    severity_line = " | ".join(severity_parts) if severity_parts else "No findings"

    # Build type breakdown
    type_lines = []
    for type_name, count in sorted(
        stats["by_type"].items(), key=lambda x: x[1], reverse=True
    )[:8]:
        type_lines.append(f"  {type_name}: {count}")
    type_breakdown = "\n".join(type_lines)

    # Build technologies line
    tech_line = ", ".join(stats["unique_technologies"][:10]) or "None detected"

    # Takeover warnings
    takeover_assets = [
        a for a in result.assets
        if a.status.value == "takeover_possible"
    ]
    takeover_section = ""
    if takeover_assets:
        takeover_lines = [f":warning: *{a.value}* — {a.notes}" for a in takeover_assets[:5]]
        takeover_section = "\n".join(takeover_lines)

    # Build Block Kit blocks
    blocks: list[dict[str, Any]] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"SurfaceMap Scan Complete: {result.target}",
            },
        },
        {
            "type": "section",
            "fields": [
                {
                    "type": "mrkdwn",
                    "text": f"*Target:*\n{result.target}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Scan ID:*\n`{result.scan_id}`",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Total Assets:*\n{stats['total_assets']}",
                },
                {
                    "type": "mrkdwn",
                    "text": f"*Live Assets:*\n{stats['live_assets']}",
                },
            ],
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Severity Breakdown:*\n{severity_line}",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Asset Types:*\n```{type_breakdown}```",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Technologies:*\n{tech_line}",
            },
        },
    ]

    if takeover_section:
        blocks.append({"type": "divider"})
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*:rotating_light: Subdomain Takeover Candidates:*\n{takeover_section}",
            },
        })

    blocks.append({
        "type": "context",
        "elements": [
            {
                "type": "mrkdwn",
                "text": f"SurfaceMap v{__version__} | Started: {result.started_at} | Completed: {result.completed_at or 'N/A'}",
            },
        ],
    })

    fallback = (
        f"SurfaceMap scan complete for {result.target}: "
        f"{stats['total_assets']} assets discovered ({stats['live_assets']} live)"
    )

    return await send_slack_notification(fallback, blocks)
