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


def _sanitize_hostname(hostname: str) -> str:
    """Sanitize a hostname to prevent command injection via subprocess."""
    return re.sub(r'[^a-zA-Z0-9.\-:]', '', hostname.strip())


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
    "azure_trafficmanager": {
        "cname": r"\.trafficmanager\.net$",
        "fingerprint": "default host name",
    },
    "azure_websites": {
        "cname": r"\.azurewebsites\.net$",
        "fingerprint": "404 Web Site not found",
    },
    "azure_cloudapp": {
        "cname": r"\.cloudapp\.net$",
        "fingerprint": "not found",
    },
    "zendesk": {
        "cname": r"\.zendesk\.com$",
        "fingerprint": "Help Center Closed",
    },
    "readme": {
        "cname": r"\.readme\.io$",
        "fingerprint": "Project doesnt exist",
    },
    "statuspage": {
        "cname": r"\.statuspage\.io$",
        "fingerprint": "Status page",
    },
    "flyio": {
        "cname": r"\.fly\.dev$",
        "fingerprint": "404 Not Found",
    },
    "smartjobboard": {
        "cname": r"\.smartjobboard\.com$",
        "fingerprint": "This job board",
    },
    "strikingly": {
        "cname": r"\.strikingly\.com$",
        "fingerprint": "page not found",
    },
    "uptimerobot": {
        "cname": r"\.uptimerobot\.com$",
        "fingerprint": "page not found",
    },
    "vercel": {
        "cname": r"\.vercel\.app$",
        "fingerprint": "404: NOT_FOUND",
    },
    "webflow": {
        "cname": r"\.webflow\.io$",
        "fingerprint": "The page you are looking for",
    },
    "agilecrm": {
        "cname": r"\.agilecrm\.com$",
        "fingerprint": "Sorry, this page",
    },
    "aha": {
        "cname": r"\.ideas\.aha\.io$",
        "fingerprint": "There is no portal",
    },
    "tilda": {
        "cname": r"\.tilda\.ws$",
        "fingerprint": "Please renew your subscription",
    },
}


class DNSModule(DiscoveryModule):
    """Enumerate DNS records for a domain (A, AAAA, MX, NS, TXT, CNAME, SOA)."""

    name = "DNS Records"
    description = "Enumerate A, AAAA, MX, NS, TXT, CNAME, and SOA records"

    async def discover(self, target: str, result: ScanResult) -> None:
        target = _sanitize_hostname(target)
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
        target = _sanitize_hostname(target)
        config = get_config()
        found_subdomains: set[str] = set()

        # Method 1: subfinder
        await self._subfinder(target, found_subdomains, config)

        # Method 2: crt.sh certificate transparency
        await self._crtsh(target, found_subdomains, config)

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

    async def _subfinder(self, target: str, found: set[str], config: object) -> None:
        """Run subfinder for passive subdomain enumeration."""
        cfg = config  # type: ignore[assignment]
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", target, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.subfinder_timeout
            )
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

    async def _crtsh(self, target: str, found: set[str], config: object) -> None:
        """Query crt.sh certificate transparency logs."""
        cfg = config  # type: ignore[assignment]
        try:
            async with httpx.AsyncClient(timeout=cfg.osint_timeout) as client:
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
            suggestions = brain.suggest_subdomains(
                target, list(found)[: cfg.max_llm_known_subs]
            )
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

        config = get_config()
        # Use DNS concurrency (higher) since takeover checks are DNS-only
        sem = asyncio.Semaphore(config.max_concurrent_dns)

        tasks: list[asyncio.Task[None]] = []

        # CNAME takeover checks on ALL discovered subdomains
        if subdomains:
            async def check_takeover(asset: Asset) -> None:
                async with sem:
                    await self._check_cname(asset, result)

            tasks.extend(
                asyncio.ensure_future(check_takeover(a))
                for a in subdomains
            )

        # NS delegation takeover check on the target domain itself
        tasks.append(asyncio.ensure_future(
            self._check_ns_delegation(target, result)
        ))

        await asyncio.gather(*tasks)

    async def _check_cname(self, asset: Asset, result: ScanResult) -> None:
        asset_value = _sanitize_hostname(asset.value)
        """Check if a subdomain has a dangling CNAME."""
        config = get_config()
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", asset_value, "CNAME",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=config.dns_timeout
            )
            cname = _sanitize_hostname(stdout.decode().strip().rstrip("."))

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

            # NXDOMAIN check: resolve the CNAME target itself
            try:
                nxproc = await asyncio.create_subprocess_exec(
                    "dig", "+short", cname, "A",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                nx_stdout, _ = await asyncio.wait_for(
                    nxproc.communicate(), timeout=config.dns_timeout
                )
                cname_resolved = nx_stdout.decode().strip()

                if not cname_resolved:
                    # CNAME exists but target doesn't resolve — dangling CNAME
                    asset.status = AssetStatus.TAKEOVER_POSSIBLE
                    asset.severity = Severity.MEDIUM
                    asset.notes = (
                        f"Dangling CNAME detected. {asset.value} has CNAME "
                        f"pointing to {cname} which does not resolve "
                        f"(NXDOMAIN). This may be vulnerable to subdomain "
                        f"takeover if the target domain can be registered or "
                        f"claimed by an attacker."
                    )
                    asset.metadata["cname_target"] = cname
                    asset.metadata["dangling_cname"] = True
                    logger.warning(
                        "DANGLING CNAME: %s -> %s (NXDOMAIN)",
                        asset.value, cname,
                    )
            except (asyncio.TimeoutError, Exception):
                pass

        except (asyncio.TimeoutError, FileNotFoundError):
            pass
        except Exception as e:
            logger.debug("Takeover check failed for %s: %s", asset.value, e)

    async def _check_ns_delegation(self, target: str, result: ScanResult) -> None:
        """Check for NS delegation takeover.

        If any NS record for the target domain points to a hostname that
        does not resolve (NXDOMAIN), an attacker could register that
        hostname and take full control of DNS for the domain.
        """
        config = get_config()
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", target, "NS",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=config.dns_timeout
            )
            ns_output = stdout.decode().strip()

            if not ns_output:
                return

            ns_hosts = [
                line.strip().rstrip(".")
                for line in ns_output.split("\n")
                if line.strip()
            ]

            for ns_host in ns_hosts:
                try:
                    ns_proc = await asyncio.create_subprocess_exec(
                        "dig", "+short", ns_host, "A",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    ns_stdout, _ = await asyncio.wait_for(
                        ns_proc.communicate(), timeout=config.dns_timeout
                    )
                    ns_resolved = ns_stdout.decode().strip()

                    if not ns_resolved:
                        # NS hostname doesn't resolve — critical takeover risk
                        result.add_asset(Asset(
                            value=ns_host,
                            type=AssetType.DNS_ISSUE,
                            status=AssetStatus.TAKEOVER_POSSIBLE,
                            severity=Severity.CRITICAL,
                            parent=target,
                            source="ns-takeover-check",
                            notes=(
                                f"NS delegation takeover risk. The nameserver "
                                f"{ns_host} for {target} does not resolve "
                                f"(NXDOMAIN). An attacker who registers or "
                                f"claims this hostname can take full control "
                                f"of DNS resolution for {target}."
                            ),
                            metadata={
                                "ns_host": ns_host,
                                "target_domain": target,
                                "dangling_ns": True,
                            },
                        ))
                        logger.warning(
                            "NS TAKEOVER: %s has unresolvable NS %s",
                            target, ns_host,
                        )
                except (asyncio.TimeoutError, Exception):
                    pass

        except (asyncio.TimeoutError, FileNotFoundError):
            pass
        except Exception as e:
            logger.debug("NS delegation check failed for %s: %s", target, e)

    async def _verify_takeover(self, subdomain: str, fingerprint: str) -> bool:
        """Verify takeover by checking HTTP response content."""
        config = get_config()
        for scheme in ["https", "http"]:
            try:
                async with httpx.AsyncClient(
                    timeout=config.http_timeout, follow_redirects=True, verify=False
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
        config = get_config()
        async with sem:
            url = f"https://{name}.s3.amazonaws.com"
            try:
                async with httpx.AsyncClient(timeout=config.http_timeout) as client:
                    resp = await client.head(url)
                    if resp.status_code == 200:
                        # Public bucket — verify it's related by checking content
                        result.add_asset(Asset(
                            value=f"s3://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=AssetStatus.LIVE,
                            parent=target,
                            source="cloud-s3",
                            severity=Severity.MEDIUM,
                            notes="Publicly accessible S3 bucket — verify ownership",
                            metadata={
                                "provider": "aws",
                                "public": True,
                                "url": url,
                            },
                        ))
                    elif resp.status_code == 403:
                        # Exists but access denied — normal, INFO only
                        result.add_asset(Asset(
                            value=f"s3://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=AssetStatus.FILTERED,
                            parent=target,
                            source="cloud-s3",
                            severity=Severity.INFO,
                            metadata={"provider": "aws", "public": False, "url": url},
                        ))
            except Exception:
                pass

    async def _check_azure(
        self, name: str, target: str, result: ScanResult,
        sem: asyncio.Semaphore,
    ) -> None:
        """Check if an Azure Blob container exists."""
        config = get_config()
        async with sem:
            url = f"https://{name}.blob.core.windows.net"
            try:
                async with httpx.AsyncClient(timeout=config.http_timeout) as client:
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
        config = get_config()
        async with sem:
            url = f"https://storage.googleapis.com/{name}"
            try:
                async with httpx.AsyncClient(timeout=config.http_timeout) as client:
                    resp = await client.head(url)
                    if resp.status_code == 200:
                        result.add_asset(Asset(
                            value=f"gcs://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=AssetStatus.LIVE,
                            parent=target,
                            source="cloud-gcs",
                            severity=Severity.MEDIUM,
                            notes="Publicly accessible GCS bucket — verify ownership",
                            metadata={"provider": "gcp", "public": True, "url": url},
                        ))
                    elif resp.status_code == 403:
                        result.add_asset(Asset(
                            value=f"gcs://{name}",
                            type=AssetType.CLOUD_BUCKET,
                            status=AssetStatus.FILTERED,
                            parent=target,
                            source="cloud-gcs",
                            severity=Severity.INFO,
                            metadata={"provider": "gcp", "public": False, "url": url},
                        ))
            except Exception:
                pass


class SubdomainPermutationModule(DiscoveryModule):
    """Generate and resolve altdns-style subdomain permutations."""

    name = "Subdomain Permutation"
    description = "Generate and resolve subdomain permutations (altdns-style)"

    PREPEND_WORDS = [
        "dev", "staging", "test", "prod", "api", "internal", "uat", "qa", "beta",
    ]
    APPEND_WORDS = [
        "dev", "staging", "test", "prod", "api", "internal",
    ]
    SWAP_WORDS = [
        "dev", "staging", "test", "prod", "api", "internal", "uat", "qa", "beta",
    ]

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        existing_assets = result.get_by_type(AssetType.SUBDOMAIN)
        if not existing_assets:
            return

        known_subdomains: set[str] = {a.value.lower() for a in existing_assets}
        known_subdomains.add(target.lower())

        permutation_prefixes: set[str] = set()

        for asset in existing_assets:
            subdomain = asset.value.lower()
            # Extract prefix: everything before the first dot of the target domain
            suffix = f".{target.lower()}"
            if not subdomain.endswith(suffix):
                continue
            prefix = subdomain[: -len(suffix)]
            if not prefix:
                continue

            # Prepend common words: dev-{prefix}, staging-{prefix}, ...
            for word in self.PREPEND_WORDS:
                permutation_prefixes.add(f"{word}-{prefix}")

            # Append common words: {prefix}-dev, {prefix}-staging, ...
            for word in self.APPEND_WORDS:
                permutation_prefixes.add(f"{prefix}-{word}")

            # Number increment: if prefix ends with a digit, try next numbers
            if prefix and prefix[-1].isdigit():
                # Find the trailing number
                i = len(prefix) - 1
                while i > 0 and prefix[i - 1].isdigit():
                    i -= 1
                base = prefix[:i]
                num = int(prefix[i:])
                for n in range(num + 1, num + 3):
                    permutation_prefixes.add(f"{base}{n}")

            # Hyphen manipulation: swap each hyphen-separated word
            if "-" in prefix:
                parts = prefix.split("-")
                for idx, _part in enumerate(parts):
                    for word in self.SWAP_WORDS:
                        new_parts = list(parts)
                        new_parts[idx] = word
                        permutation_prefixes.add("-".join(new_parts))

        # Build FQDNs and deduplicate against known subdomains
        candidates: list[str] = []
        for perm_prefix in permutation_prefixes:
            fqdn = f"{perm_prefix}.{target}".lower()
            if fqdn not in known_subdomains:
                candidates.append(fqdn)

        # Cap total permutations
        candidates = candidates[: config.max_permutations]

        if not candidates:
            return

        logger.info(
            "Testing %d subdomain permutations for %s", len(candidates), target,
        )

        sem = asyncio.Semaphore(config.max_concurrent_dns)
        resolved: list[str] = []
        lock = asyncio.Lock()

        async def resolve(fqdn: str) -> None:
            async with sem:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        "dig", "+short", fqdn, "A",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=config.dns_timeout,
                    )
                    if stdout.decode().strip():
                        async with lock:
                            resolved.append(fqdn)
                except (asyncio.TimeoutError, FileNotFoundError):
                    pass
                except Exception:
                    pass

        tasks = [resolve(fqdn) for fqdn in candidates]
        await asyncio.gather(*tasks)

        for fqdn in sorted(resolved):
            result.add_asset(Asset(
                value=fqdn,
                type=AssetType.SUBDOMAIN,
                parent=target,
                source="subdomain-permutation",
            ))

        logger.info(
            "Permutation scan found %d new subdomains for %s",
            len(resolved), target,
        )
