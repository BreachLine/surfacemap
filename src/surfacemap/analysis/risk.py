"""Risk scoring and false-positive filtering for scan results.

Combines algorithmic heuristics with optional LLM refinement to produce
a risk score, grade, and filtered finding set.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from surfacemap.core.config import get_config
from surfacemap.core.llm import LLMBrain
from surfacemap.core.models import ScanResult, Severity

logger = logging.getLogger(__name__)

# Points assigned per severity level for algorithmic scoring
_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 15,
    Severity.HIGH: 8,
    Severity.MEDIUM: 4,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

# Grade boundaries: (upper_bound_inclusive, grade_letter)
_GRADE_BOUNDARIES: list[tuple[int, str]] = [
    (20, "A"),
    (40, "B"),
    (60, "C"),
    (80, "D"),
    (100, "F"),
]


def _score_to_grade(score: int) -> str:
    """Map a 0-100 risk score to a letter grade."""
    for upper, grade in _GRADE_BOUNDARIES:
        if score <= upper:
            return grade
    return "F"


class RiskScorer:
    """Calculates a risk score and grade for a completed scan."""

    async def score(self, result: ScanResult) -> None:
        """Score the scan result in place, setting risk_score and risk_grade.

        Step 1: Compute an algorithmic base score from severity counts.
        Step 2: Optionally refine with LLM analysis.
        Step 3: Map final score to a letter grade.
        """
        config = get_config()

        # -- Step 1: algorithmic base score ----------------------------------
        raw_points = sum(
            _SEVERITY_WEIGHTS.get(asset.severity, 0) for asset in result.assets
        )

        # Normalise to 0-100.  Use the theoretical max for the current asset
        # count so the scale adapts to scan size.
        max_possible = len(result.assets) * _SEVERITY_WEIGHTS[Severity.CRITICAL]
        if max_possible > 0:
            base_score = int(round(raw_points / max_possible * 100))
        else:
            base_score = 0
        base_score = max(0, min(100, base_score))

        final_score = base_score

        # -- Step 2: LLM refinement (optional) ------------------------------
        if config.has_llm:
            final_score = await self._refine_with_llm(result, base_score)

        # -- Step 3: grade mapping -------------------------------------------
        result.risk_score = final_score
        result.risk_grade = _score_to_grade(final_score)

        logger.info(
            "Risk score: %d (%s) [base=%d, assets=%d]",
            result.risk_score,
            result.risk_grade,
            base_score,
            len(result.assets),
        )

    # --------------------------------------------------------------------- #

    @staticmethod
    async def _refine_with_llm(result: ScanResult, base_score: int) -> int:
        """Ask the LLM to refine the algorithmic score."""
        stats = result.compute_stats()

        # Collect top 20 findings (CRITICAL first, then HIGH, etc.)
        severity_order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]
        top_findings: list[dict[str, Any]] = []
        for sev in severity_order:
            for asset in result.get_by_severity(sev):
                if len(top_findings) >= 20:
                    break
                top_findings.append(asset.to_dict())
            if len(top_findings) >= 20:
                break

        prompt = (
            "You are a cybersecurity risk analyst. Given the following attack "
            "surface scan summary and top findings, produce a refined risk "
            "score from 0 (no risk) to 100 (critical risk).\n\n"
            f"Algorithmic base score: {base_score}\n\n"
            f"Scan statistics:\n{json.dumps(stats, indent=2)}\n\n"
            f"Top findings:\n{json.dumps(top_findings, indent=2)}\n\n"
            "Return a JSON object with exactly two keys:\n"
            '  "score": an integer 0-100\n'
            '  "factors": an array of short strings explaining key risk factors'
        )

        try:
            llm = LLMBrain()
            response = llm.ask_json(prompt)
            if isinstance(response, dict) and "score" in response:
                refined = int(response["score"])
                refined = max(0, min(100, refined))
                factors = response.get("factors", [])
                logger.info("LLM risk factors: %s", factors)
                return refined
        except Exception as exc:
            logger.warning("LLM risk refinement failed: %s", exc)

        return base_score


class FalsePositiveFilter:
    """Uses LLM analysis to demote likely false-positive findings."""

    async def filter(self, result: ScanResult) -> None:
        """Review top findings and demote likely false positives in place.

        Only runs when an LLM provider is available.
        """
        config = get_config()
        if not config.has_llm:
            return

        # Collect top 50 findings by severity (CRITICAL + HIGH + MEDIUM)
        candidates: list[dict[str, Any]] = []
        candidate_indices: list[int] = []
        target_severities = {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}

        for idx, asset in enumerate(result.assets):
            if asset.severity in target_severities:
                candidates.append(asset.to_dict())
                candidate_indices.append(idx)
                if len(candidates) >= 50:
                    break

        if not candidates:
            return

        prompt = (
            "You are a senior penetration tester reviewing security findings "
            "from an automated attack surface scan. Identify likely false "
            "positives.\n\n"
            f"Findings:\n{json.dumps(candidates, indent=2)}\n\n"
            "Review these security findings and identify likely false "
            "positives. Return a JSON array of the 'value' strings for "
            "findings that should be demoted (i.e., are likely false positives)."
        )

        try:
            llm = LLMBrain()
            response = llm.ask_json(prompt)
            if not isinstance(response, list):
                return

            demote_values = {str(v) for v in response}
            demoted_count = 0

            # Severity demotion mapping
            demotion_map: dict[Severity, Severity] = {
                Severity.CRITICAL: Severity.HIGH,
                Severity.HIGH: Severity.MEDIUM,
                Severity.MEDIUM: Severity.LOW,
            }

            for idx in candidate_indices:
                asset = result.assets[idx]
                if asset.value in demote_values:
                    new_severity = demotion_map.get(asset.severity)
                    if new_severity is not None:
                        asset.severity = new_severity
                        asset.metadata["fp_review"] = "likely_false_positive"
                        demoted_count += 1

            logger.info(
                "False-positive filter demoted %d of %d reviewed findings",
                demoted_count,
                len(candidates),
            )

        except Exception as exc:
            logger.warning("LLM false-positive filtering failed: %s", exc)
