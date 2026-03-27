"""Nuclei template-based vulnerability scanner integration.

Wraps the nuclei CLI tool to run template-based scans against discovered
live hosts. If nuclei is not installed, the module silently skips.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile

from surfacemap.core.config import get_config
from surfacemap.core.models import Asset, AssetType, ScanResult, Severity
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)

_NUCLEI_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


class NucleiModule(DiscoveryModule):
    """Run nuclei template scans against discovered live hosts."""

    name = "Nuclei"
    description = "Template-based vulnerability scanning via Nuclei"
    module_timeout = 600  # Nuclei runs 6000+ templates, needs more time

    async def discover(self, target: str, result: ScanResult) -> None:
        nuclei_path = shutil.which("nuclei")
        if not nuclei_path:
            logger.info("[%s] nuclei not found on PATH — skipping.", self.name)
            return

        cfg = get_config()
        hosts = result.get_live_hosts()
        if not hosts:
            logger.info("[%s] No live hosts to scan.", self.name)
            return

        # Write targets to a temp file (one URL per line)
        fd, targets_file = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                for host in hosts:
                    f.write(f"https://{host}\n")
                    f.write(f"http://{host}\n")

            cmd = [
                nuclei_path,
                "-l", targets_file,
                "-severity", cfg.nuclei_severity,
                "-jsonl",
                "-rate-limit", str(cfg.nuclei_rate_limit),
                "-c", str(cfg.nuclei_concurrency),
                "-timeout", str(cfg.nuclei_timeout),
                "-silent",
            ]
            if cfg.nuclei_templates:
                for t in cfg.nuclei_templates.split(","):
                    cmd.extend(["-t", t.strip()])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            count = 0
            for line in stdout.decode(errors="replace").strip().split("\n"):
                if not line.strip():
                    continue
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue

                template_id = finding.get("template-id", "unknown")
                matched_at = finding.get("matched-at", "")
                info = finding.get("info", {})
                sev_str = info.get("severity", "info").lower()
                severity = _NUCLEI_SEVERITY_MAP.get(sev_str, Severity.INFO)
                name = info.get("name", template_id)

                result.add_asset(Asset(
                    value=matched_at or target,
                    type=AssetType.VULNERABILITY,
                    source="nuclei",
                    severity=severity,
                    notes=name,
                    metadata={
                        "template_id": template_id,
                        "template_name": name,
                        "matched_at": matched_at,
                        "matcher_name": finding.get("matcher-name", ""),
                        "description": info.get("description", ""),
                        "tags": info.get("tags", []),
                        "reference": info.get("reference", []),
                        "extracted_results": finding.get("extracted-results", []),
                    },
                ))
                count += 1

            logger.info("[%s] Found %d vulnerabilities.", self.name, count)

        except Exception as e:
            logger.warning("[%s] Scan failed: %s", self.name, e)
        finally:
            try:
                os.unlink(targets_file)
            except OSError:
                pass
