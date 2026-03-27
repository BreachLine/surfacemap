"""Narrative analysis: attack paths and executive summaries.

Uses LLM capabilities to generate human-readable analysis artefacts
from raw scan results.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any

from surfacemap.core.config import get_config
from surfacemap.core.llm import LLMBrain
from surfacemap.core.models import ScanResult, Severity

logger = logging.getLogger(__name__)


class AttackPathAnalysis:
    """Constructs realistic attack paths from discovered findings."""

    async def analyze(self, result: ScanResult) -> None:
        """Populate result.attack_paths with LLM-generated attack chains.

        Only runs when an LLM provider is available.
        """
        config = get_config()
        if not config.has_llm:
            return

        # Group top findings by asset type for the LLM prompt
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        total_collected = 0
        max_findings = 50

        for sev in severity_order:
            for asset in result.get_by_severity(sev):
                if total_collected >= max_findings:
                    break
                grouped[asset.type.value].append(asset.to_dict())
                total_collected += 1
            if total_collected >= max_findings:
                break

        if not grouped:
            return

        prompt = (
            "You are an expert penetration tester analysing the results of an "
            "attack surface scan against the target "
            f'"{result.target}".\n\n'
            "Discovered assets and vulnerabilities grouped by type:\n"
            f"{json.dumps(grouped, indent=2)}\n\n"
            "Given these discovered assets and vulnerabilities, construct 3-5 "
            "realistic attack paths an attacker could follow. Chain findings "
            "together.\n\n"
            "Return a JSON array of objects, each with:\n"
            '  "name": a short descriptive name for the attack path\n'
            '  "steps": an ordered array of strings describing each step\n'
            '  "severity": overall severity ("critical", "high", "medium", or "low")\n'
            '  "assets_involved": array of asset value strings used in this path'
        )

        try:
            llm = LLMBrain()
            response = llm.ask_json(prompt)

            if isinstance(response, list):
                result.attack_paths = response
            elif isinstance(response, dict) and "attack_paths" in response:
                result.attack_paths = response["attack_paths"]

            logger.info(
                "Generated %d attack paths for %s",
                len(result.attack_paths),
                result.target,
            )

        except Exception as exc:
            logger.warning("LLM attack path analysis failed: %s", exc)


class ExecutiveSummary:
    """Generates a non-technical executive summary of the scan."""

    async def generate(self, result: ScanResult) -> None:
        """Populate result.executive_summary with LLM-generated prose.

        Only runs when an LLM provider is available.
        """
        config = get_config()
        if not config.has_llm:
            return

        stats = result.compute_stats()

        # Collect key findings for context
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
        ]
        key_findings: list[dict[str, Any]] = []
        for sev in severity_order:
            for asset in result.get_by_severity(sev):
                if len(key_findings) >= 20:
                    break
                key_findings.append(asset.to_dict())
            if len(key_findings) >= 20:
                break

        prompt = (
            "You are a cybersecurity consultant preparing a report for "
            "executive leadership.\n\n"
            f"Target: {result.target}\n\n"
            f"Scan statistics:\n{json.dumps(stats, indent=2)}\n\n"
            f"Key findings:\n{json.dumps(key_findings, indent=2)}\n\n"
            "Generate a 3-5 paragraph executive summary of this attack "
            "surface scan suitable for non-technical stakeholders. Include "
            "risk highlights and top recommendations."
        )

        try:
            llm = LLMBrain()
            summary = llm.ask(prompt)
            if summary:
                result.executive_summary = summary
                logger.info(
                    "Generated executive summary (%d chars) for %s",
                    len(summary),
                    result.target,
                )

        except Exception as exc:
            logger.warning("LLM executive summary generation failed: %s", exc)
