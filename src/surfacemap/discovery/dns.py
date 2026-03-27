"""DNS-based discovery modules.

Includes DNS record enumeration, subdomain discovery (subfinder + crt.sh +
brute force + LLM suggestions), subdomain takeover detection, and cloud
storage bucket enumeration.
"""

from __future__ import annotations

import asyncio
import logging
import re

import httpx

from surfacemap.core.config import get_config
from surfacemap.core.llm import LLMBrain
from surfacemap.core.models import (
    Asset,
    AssetStatus,
    AssetType,
    ScanResult,
    Severity,
)
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)

# Common subdomain wordlist for brute forcing
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "imap", "remote", "blog", "webdisk", "cpanel", "whm",
    "autodiscover", "autoconfig", "m", "mobile", "api", "dev", "staging",
    "test", "admin", "portal", "vpn", "cdn", "cloud", "git", "gitlab",
    "jenkins", "ci", "jira", "confluence", "grafana", "kibana", "monitor",
    "status", "app", "apps", "beta", "demo", "docs", "help", "support",
    "shop", "store", "auth", "sso", "login", "oauth", "id", "accounts",
    "static", "assets", "media", "images", "img", "files", "download",
    "upload", "backup", "db", "database", "mysql", "postgres", "redis",
    "elastic", "search", "logs", "metrics", "prometheus", "uat", "qa",
    "sandbox", "internal", "intranet", "wiki", "crm", "erp", "hr",
    "finance", "billing", "pay", "payments", "gateway", "proxy", "edge",
    "lb", "load", "web", "www2", "secure", "ssl", "old", "new", "v2",
    "api-v2", "graphql", "ws", "wss", "socket", "relay", "mx", "mx1",
    "mx2", "email", "newsletter", "marketing", "analytics", "track",
    "events", "webhook", "hooks", "callback", "notify", "push",
]

# Subdomain takeover fingerprints: provider -> (CNAME pattern, response fingerprint)
TAKEOVER_FINGERPRINTS: dict[str, dict[str, str]] = {
    "github_pages": {
        "cname": r"\.github\.io$",
        "fingerprint": "There isn't a GitHub Pages site here",
    },
    "heroku": {
        "cname": r"\.herokuapp\.com$",
        "fingerprint": "No such app",
    },
    "aws_s3": {
        "cname": r"\.s3\.amazonaws\.com$",
        "fingerprint": "NoSuchBucket",
    },
    "aws_s3_website": {
        "cname": r"\.s3-website.*\.amazonaws\.com$",
        "fingerprint": "NoSuchBucket",
    },
    "shopify": {
        "cname": r"\.myshopify\.com$",
        "fingerprint": "Sorry, this shop is currently unavailable",
    },
    "tumblr": {
        "cname": r"\.tumblr\.com$",
        "fingerprint": "There's nothing here",
    },
    "wordpress": {
        "cname": r"\.wordpress\.com$",
        "fingerprint": "Do you want to register",
    },
    "pantheon": {
        "cname": r"\.pantheonsite\.io$",
        "fingerprint": "The gods are wise",
    },
    "teamwork": {
        "cname": r"\.teamwork\.com$",
        "fingerprint": "Oops - We didn't find your site",
    },
    "helpjuice": {
        "cname": r"\.helpjuice\.com$",
        "fingerprint": "We could not find what you're looking for",
    },
    "helpscout": {
        "cname": r"\.helpscoutdocs\.com$",
        "fingerprint": "No settings were found for this company",
    },
    "cargo": {
        "cname": r"\.cargocollective\.com$",
        "fingerprint": "If you're moving your domain away from Cargo",
    },
    "feedpress": {
        "cname": r"redirect\.feedpress\.me$",
        "fingerprint": "The feed has not been found",
    },
    "ghost": {
        "cname": r"\.ghost\.io$",
        "fingerprint": "The thing you were looking for is no longer here",
    },
    "bitbucket": {
        "cname": r"\.bitbucket\.io$",
        "fingerprint": "Repository not found",
    },
    "surge": {
        "cname": r"\.surge\.sh$",
        "fingerprint": "project not found",
    },
    "netlify": {
        "cname": r"\.netlify\.(app|com)$",
        "fingerprint": "Not Found - Request ID",
    },
}


class DNSModule(DiscoveryModule):
    """Enumerate DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA)."""

    name = "DNS Records"
    description = "Enumerate A, AAAA, MX, NS, TXT, CNAME, and SOA records"

    async def discover(self, target: str, result: ScanResult) -> None:
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        config = get_config()

        for rtype in record_types:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", target, rtype,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=config.dns_timeout
                )
                output = stdout.decode().strip()

                if not output:
                    continue

                for line in output.split("\n"):
                    line = line.strip().rstrip(".")
                    if not line:
                        continue

                    if rtype == "A":
                        result.add_asset(Asset(
                            value=line, type=AssetType.IP,
                            parent=target, source="dns-a",
                        ))
                    elif rtype == "AAAA":
                        result.add_asset(Asset(
                            value=line, type=AssetType.IP,
                            parent=target, source="dns-aaaa",
                        ))
                    elif rtype == "MX":
                        # MX records have priority prefix
                        parts = line.split()
                        mx_host = parts[-1] if parts else line
                        result.add_asset(Asset(
                            value=mx_host, type=AssetType.EMAIL_SERVER,
                            parent=target, source="dns-mx",
                            metadata={"priority": parts[0] if len(parts) > 1 else "10"},
                        ))
                    elif rtype == "NS":
                        result.add_asset(Asset(
                            value=line, type=AssetType.NAMESERVER,
                            parent=target, source="dns-ns",
                        ))
                    elif rtype == "CNAME":
                        result.add_asset(Asset(
                            value=line, type=AssetType.SUBDOMAIN,
                            parent=target, source="dns-cname",
                            metadata={"cname_target": line},
                        ))

            except asyncio.TimeoutError:
                logger.warning("DNS lookup timed out for %s %s", target, rtype)
            except FileNotFoundError:
                logger.warning("dig not found — skipping DNS record enumeration")
                return
            except Exception as e:
                logger.warning("DNS %s lookup failed for %s: %s", rtype, target, e)


class SubdomainModule(DiscoveryModule):
    """Discover subdomains via subfinder, crt.sh, DNS brute force, and LLM."""

    name = "Subdomain Discovery"
    description = "Enumerate subdomains via subfinder, crt.sh, brute force, and LLM"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        found_subdomains: set[str] = set()

        # Method 1: subfinder
        await self._subfinder(target, found_subdomains)

        # Method 2: crt.sh certificate transparency
        await self._crtsh(target, found_subdomains)

        # Method 3: DNS brute force
        await self._brute_force(target, found_subdomains, config)

        # Method 4: LLM-suggested subdomains
        if config.has_llm:
            await self._llm_suggestions(target, found_subdomains, config)

        # Add all discovered subdomains to result
        for sub in sorted(found_subdomains):
            if sub != target:
                result.add_asset(Asset(
                    value=sub, type=AssetType.SUBDOMAIN,
                    parent=target, source="subdomain-enum",
                ))

        logger.info("Discovered %d subdomains for %s", len(found_subdomains), target)

    async def _subfinder(self, target: str, found: set[str]) -> None:
        """Run subfinder for passive subdomain enumeration."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", target, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=60)
            for line in stdout.decode().strip().split("\n"):
                sub = line.strip().lower()
                if sub and (sub.endswith(f".{target}") or sub == target):
                    found.add(sub)
        except FileNotFoundError:
            logger.info("subfinder not installed — skipping")
        except asyncio.TimeoutError:
            logger.warning("subfinder timed out")
        except Exception as e:
            logger.warning("subfinder failed: %s", e)

    async def _crtsh(self, target: str, found: set[str]) -> None:
        """Query crt.sh certificate transparency logs."""
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                resp = await client.get(
                    f"https://crt.sh/?q=%.{target}&output=json"
                )
                if resp.status_code == 200:
                    entries = resp.json()
                    for entry in entries:
                        name_value = entry.get("name_value", "")
                        for name in name_value.split("\n"):
                            name = name.strip().lower().lstrip("*.")
                            if name.endswith(f".{target}") or name == target:
                                found.add(name)
        except Exception as e:
            logger.warning("crt.sh query failed: %s", e)

    async def _brute_force(self, target: str, found: set[str], config: object) -> None:
        """DNS brute force common subdomain names."""
        cfg = config  # type: ignore[assignment]
        sem = asyncio.Semaphore(cfg.max_concurrent_dns)

        async def check_subdomain(prefix: str) -> None:
            fqdn = f"{prefix}.{target}"
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "dig", "+short", fqdn, "A",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=cfg.dns_timeout
                    )
                    if stdout.decode().strip():
                        found.add(fqdn)
                except (asyncio.TimeoutError, FileNotFoundError):
                    pass
                except Exception:
                    pass

        tasks = [check_subdomain(prefix) for prefix in DEFAULT_SUBDOMAINS]
        await asyncio.gather(*tasks)

    async def _llm_suggestions(
        self, target: str, found: set[str], config: object
    ) -> None:
        """Use LLM to suggest additional subdomains."""
        cfg = config  # type: ignore[assignment]
        try:
            brain = LLMBrain()
            suggestions = brain.suggest_subdomains(target, list(found)[:30])
            sem = asyncio.Semaphore(cfg.max_concurrent_dns)

            async def check(prefix: str) -> None:
                fqdn = f"{prefix}.{target}"
                async with sem:
                    try:
                        proc = await asyncio.create_subprocess_exec(
                            "dig", "+short", fqdn, "A",
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout, _ = await asyncio.wait_for(
                            proc.communicate(), timeout=cfg.dns_timeout
                        )
                        if stdout.decode().strip():
                            found.add(fqdn)
                            logger.info("LLM suggestion confirmed: %s", fqdn)
                    except Exception:
                        pass

            tasks = [check(s) for s in suggestions if s not in found]
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.warning("LLM subdomain suggestions failed: %s", e)


class SubdomainTakeoverModule(DiscoveryModule):
    """Check discovered subdomains for potential takeover vulnerabilities."""

    name = "Subdomain Takeover"
    description = "Detect dangling CNAMEs vulnerable to subdomain takeover"

    async def discover(self, target: str, result: ScanResult) -> None:
        subdomains = result.get_by_type(AssetType.SUBDOMAIN)
        if not subdomains:
            return

        config = get_config()
        sem = asyncio.Semaphore(config.max_concurrent_probes)

        async def check_takeover(asset: Asset) -> None:
            async with sem:
                await self._check_cname(asset, result)

        tasks = [check_takeover(a) for a in subdomains]
        await asyncio.gather(*tasks)

    async def _check_cname(self, asset: Asset, result: ScanResult) -> None:
        """Check if a subdomain has a dangling CNAME."""
        config = get_config()
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", asset.value, "CNAME",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=config.dns_timeout
            )
            cname = stdout.decode().strip().rstrip(".")

            if not cname:
                return

            # Check against known takeover fingerprints
            for provider, patterns in TAKEOVER_FINGERPRINTS.items():
                if re.search(patterns["cname"], cname):
                    # Verify by checking HTTP response
                    is_vulnerable = await self._verify_takeover(
                        asset.value, patterns["fingerprint"]
                    )
                    if is_vulnerable:
                        asset.status = AssetStatus.TAKEOVER_POSSIBLE
                        asset.severity = Severity.HIGH
                        asset.notes = (
                            f"Possible subdomain takeover via {provider}. "
                            f"CNAME points to {cname}"
                        )
                        asset.metadata["takeover_provider"] = provider
                        asset.metadata["cname_target"] = cname
                        logger.warning(
                            "TAKEOVER: %s -> %s (%s)",
                            asset.value, cname, provider,
                        )
                        return

        except (asyncio.TimeoutError, FileNotFoundError):
            pass
        except Exception as e:
            logger.debug("Takeover check failed for %s: %s", asset.value, e)

    async def _verify_takeover(self, subdomain: str, fingerprint: str) -> bool:
        """Verify takeover by checking HTTP response content."""
        for scheme in ["https", "http"]:
            try:
                async with httpx.AsyncClient(
                    timeout=10, follow_redirects=True, verify=False
                ) as client:
                    resp = await client.get(f"{scheme}://{subdomain}")
                    if fingerprint.lower() in resp.text.lower():
                        return True
            except Exception:
                continue
        return False


class CloudDiscoveryModule(DiscoveryModule):
    """Enumerate cloud storage buckets (S3, Azure Blob, GCS)."""

    name = "Cloud Storage"
    description = "Enumerate S3 buckets, Azure Blob containers, and GCS buckets"

    # Common bucket naming patterns
    BUCKET_PATTERNS = [
        "{company}", "{company}-assets", "{company}-backup", "{company}-backups",
        "{company}-data", "{company}-dev", "{company}-development",
        "{company}-files", "{company}-images", "{company}-internal",
        "{company}-logs", "{company}-media", "{company}-private",
        "{company}-prod", "{company}-production", "{company}-public",
        "{company}-staging", "{company}-static", "{company}-storage",
        "{company}-test", "{company}-uploads", "{company}-web",
    ]

    async def discover(self, target: str, result: ScanResult) -> None:
        # Extract company name from domain
        company = target.split(".")[0].lower()
        config = get_config()

        sem = asyncio.Semaphore(config.max_concurrent_probes)
        tasks: list[asyncio.Task[None]] = []

        for pattern in self.BUCKET_PATTERNS:
            bucket_name = pattern.format(company=company)
            tasks.append(asyncio.ensure_future(
                self._check_s3(bucket_name, target, result, sem)
            ))
            tasks.append(asyncio.ensure_future(
                self._check_azure(bucket_name, target, result, sem)
            ))
            tasks.append(asyncio.ensure_future(
                self._check_gcs(bucket_name, target, result, sem)
            ))

        await asyncio.gather(*tasks)

    async def _check_s3(
        self, name: str, target: str, result: ScanResult,
        sem: asyncio.Semaphore,
    ) -> None:
        """Check if an S3 bucket exists and is publicly accessible."""
        async with sem:
            url = f"https://{name}.s3.amazonaws.com"
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.head(url)
                    if resp.status_code in (200, 403):
                        status = (
                            AssetStatus.LIVE if resp.status_code == 200
                            else AssetStatus.FILTERED
                        )
                        severity = (
                            Severity.HIGH if resp.status_code == 200
                            else Severity.MEDIUM
                        )
                        result.add_asset(Asset(
                            value=f"s3://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=status,
                            parent=target,
                            source="cloud-s3",
                            severity=severity,
                            metadata={
                                "provider": "aws",
                                "public": resp.status_code == 200,
                                "url": url,
                            },
                        ))
            except Exception:
                pass

    async def _check_azure(
        self, name: str, target: str, result: ScanResult,
        sem: asyncio.Semaphore,
    ) -> None:
        """Check if an Azure Blob container exists."""
        async with sem:
            url = f"https://{name}.blob.core.windows.net"
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.head(url)
                    if resp.status_code in (200, 400):
                        result.add_asset(Asset(
                            value=f"azure://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=AssetStatus.LIVE,
                            parent=target,
                            source="cloud-azure",
                            severity=Severity.MEDIUM,
                            metadata={"provider": "azure", "url": url},
                        ))
            except Exception:
                pass

    async def _check_gcs(
        self, name: str, target: str, result: ScanResult,
        sem: asyncio.Semaphore,
    ) -> None:
        """Check if a Google Cloud Storage bucket exists."""
        async with sem:
            url = f"https://storage.googleapis.com/{name}"
            try:
                async with httpx.AsyncClient(timeout=8) as client:
                    resp = await client.head(url)
                    if resp.status_code in (200, 403):
                        status = (
                            AssetStatus.LIVE if resp.status_code == 200
                            else AssetStatus.FILTERED
                        )
                        result.add_asset(Asset(
                            value=f"gcs://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=status,
                            parent=target,
                            source="cloud-gcs",
                            severity=Severity.MEDIUM,
                            metadata={"provider": "gcp", "url": url},
                        ))
            except Exception:
                pass
