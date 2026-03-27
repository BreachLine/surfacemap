"""SARIF 2.1.0 output for CI/CD integration (GitHub/GitLab Security tab)."""

from __future__ import annotations

from typing import Any

from surfacemap import __version__
from surfacemap.core.models import ScanResult, Severity

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

_SEVERITY_TO_SARIF = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def generate_sarif(result: ScanResult) -> dict[str, Any]:
    """Generate SARIF 2.1.0 report from scan results."""
    # Filter to security-relevant assets only (not INFO severity)
    findings = [a for a in result.assets if a.severity != Severity.INFO]

    # Build unique rules from (type, source) combinations
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for asset in findings:
        rule_id = f"surfacemap/{asset.type.value}/{asset.source}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"{asset.type.value}_{asset.source}".replace("-", "_"),
                "shortDescription": {"text": f"{asset.type.value} finding from {asset.source}"},
                "defaultConfiguration": {"level": _SEVERITY_TO_SARIF.get(asset.severity, "note")},
            }

        sarif_result = {
            "ruleId": rule_id,
            "level": _SEVERITY_TO_SARIF.get(asset.severity, "note"),
            "message": {"text": f"Discovered {asset.type.value}: {asset.value} (status: {asset.status.value}, severity: {asset.severity.value})"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": asset.value, "uriBaseId": "ROOTURI"},
                },
            }],
            "properties": {
                "asset_type": asset.type.value,
                "status": asset.status.value,
                "source": asset.source,
                "severity": asset.severity.value,
            },
        }
        if asset.notes:
            sarif_result["properties"]["notes"] = asset.notes
        results.append(sarif_result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "SurfaceMap",
                    "version": __version__,
                    "informationUri": "https://github.com/BreachLine/surfacemap",
                    "rules": list(rules.values()),
                },
            },
            "results": results,
            "invocations": [{
                "executionSuccessful": True,
                "properties": {
                    "target": result.target,
                    "scan_id": result.scan_id,
                    "total_assets": len(result.assets),
                    "findings": len(findings),
                    "risk_score": result.risk_score,
                    "risk_grade": result.risk_grade,
                },
            }],
        }],
    }
