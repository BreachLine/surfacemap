"""Scan diff computation for monitoring changes between scans."""

from __future__ import annotations

import logging
from typing import Any

from surfacemap.core.models import ScanResult, Severity

logger = logging.getLogger(__name__)


def compute_diff(old: ScanResult, new: ScanResult) -> dict[str, Any]:
    """Compute differences between two scan results."""
    old_fps = {a.fingerprint: a for a in old.assets}
    new_fps = {a.fingerprint: a for a in new.assets}

    added = [a.to_dict() for fp, a in new_fps.items() if fp not in old_fps]
    removed = [a.to_dict() for fp, a in old_fps.items() if fp not in new_fps]

    # Status changes
    changed = []
    for fp in old_fps:
        if fp in new_fps and old_fps[fp].status != new_fps[fp].status:
            changed.append({
                "asset": new_fps[fp].to_dict(),
                "old_status": old_fps[fp].status.value,
                "new_status": new_fps[fp].status.value,
            })

    # Severity summary
    new_critical = [a for a in added if a["severity"] in ("critical", "high")]

    return {
        "old_scan_id": old.scan_id,
        "new_scan_id": new.scan_id,
        "target": new.target,
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
        "new_critical_findings": new_critical,
        "old_total": len(old.assets),
        "new_total": len(new.assets),
    }


def format_diff_summary(diff: dict[str, Any]) -> str:
    """Format a diff result as a human-readable summary."""
    lines = [
        f"Scan Diff: {diff['target']}",
        f"  Previous: {diff['old_scan_id']} ({diff['old_total']} assets)",
        f"  Current:  {diff['new_scan_id']} ({diff['new_total']} assets)",
        f"  Added:    {diff['added_count']}",
        f"  Removed:  {diff['removed_count']}",
        f"  Changed:  {diff['changed_count']}",
    ]
    if diff["new_critical_findings"]:
        lines.append(f"  NEW CRITICAL/HIGH: {len(diff['new_critical_findings'])}")
        for f_item in diff["new_critical_findings"][:5]:
            lines.append(f"    - [{f_item['severity']}] {f_item['type']}: {f_item['value']}")
    return "\n".join(lines)
