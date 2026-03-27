"""OSINT discovery modules.

Includes WHOIS/RDAP lookups, ASN discovery, reverse DNS, SSL/TLS analysis,
DNS zone transfer detection, and email security (SPF/DKIM/DMARC) checks.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import socket
from datetime import datetime, timezone


def _sanitize_hostname(hostname: str) -> str:
    """Sanitize a hostname to prevent injection via subprocess."""
    return re.sub(r'[^a-zA-Z0-9.\-:]', '', hostname.strip())

import httpx

from surfacemap.core.config import get_config
from surfacemap.core.models import (
    Asset,
    AssetStatus,
    AssetType,
    ScanResult,
    Severity,
)
from surfacemap.discovery.base import DiscoveryModule

logger = logging.getLogger(__name__)

# Cipher suites considered weak
WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "NULL", "EXPORT", "anon", "MD5",
}


class WHOISModule(DiscoveryModule):
    """RDAP/WHOIS lookup for domain registration details."""

    name = "WHOIS Lookup"
    description = "Query RDAP for registrant, registrar, dates, and nameservers"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()
        url = f"https://rdap.org/domain/{target}"

        try:
            async with httpx.AsyncClient(
                timeout=config.whois_timeout,
                headers={"User-Agent": config.user_agent},
                follow_redirects=True,
            ) as client:
                resp = await client.get(url)

            if resp.status_code != 200:
                logger.warning(
                    "RDAP lookup returned %d for %s", resp.status_code, target,
                )
                return

            data = resp.json()

            # Extract registrar
            registrar = ""
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrar" in roles:
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for field in vcard:
                        if field[0] == "fn":
                            registrar = field[3]
                            break

            # Extract registrant
            registrant = ""
            for entity in data.get("entities", []):
                roles = entity.get("roles", [])
                if "registrant" in roles:
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for field in vcard:
                        if field[0] == "fn":
                            registrant = field[3]
                            break

            # Extract events (registration, expiration, last changed)
            events: dict[str, str] = {}
            for event in data.get("events", []):
                action = event.get("eventAction", "")
                date = event.get("eventDate", "")
                if action and date:
                    events[action] = date

            # Extract nameservers from RDAP response
            nameservers: list[str] = []
            for ns_entry in data.get("nameservers", []):
                ns_name = ns_entry.get("ldhName", "")
                if ns_name:
                    nameservers.append(ns_name.rstrip(".").lower())

            # Add nameserver assets
            for ns in nameservers:
                result.add_asset(Asset(
                    value=ns,
                    type=AssetType.NAMESERVER,
                    parent=target,
                    source="whois-rdap",
                ))

            # Build WHOIS record metadata
            metadata: dict[str, object] = {
                "registrar": registrar,
                "registrant": registrant,
                "nameservers": nameservers,
                "domain_status": data.get("status", []),
                "handle": data.get("handle", ""),
            }
            metadata.update(events)

            result.add_asset(Asset(
                value=target,
                type=AssetType.WHOIS_RECORD,
                status=AssetStatus.LIVE,
                parent=target,
                source="whois-rdap",
                metadata=metadata,
                notes=(
                    f"Registrar: {registrar or 'N/A'}, "
                    f"Created: {events.get('registration', 'N/A')}, "
                    f"Expires: {events.get('expiration', 'N/A')}"
                ),
            ))

        except httpx.TimeoutException:
            logger.warning("RDAP lookup timed out for %s", target)
        except Exception as e:
            logger.warning("RDAP lookup failed for %s: %s", target, e)


class ASNModule(DiscoveryModule):
    """ASN lookup via Team Cymru DNS service for discovered IPs."""

    name = "ASN Discovery"
    description = "Map IPs to ASN and IP ranges via Team Cymru"

    async def discover(self, target: str, result: ScanResult) -> None:
        # Only look up IPs from authoritative DNS resolution, not from
        # third-party sources (URLScan, Shodan) which return unrelated IPs
        dns_sources = {"dns-a", "dns-aaaa", "hackertarget"}
        ip_assets = [
            a for a in result.get_by_type(AssetType.IP)
            if a.source in dns_sources
        ]
        if not ip_assets:
            logger.info("No DNS-resolved IPs — skipping ASN lookup")
            return

        config = get_config()
        sem = asyncio.Semaphore(config.max_concurrent_dns)
        unique_ips = list({a.value for a in ip_assets if ":" not in a.value})  # Skip IPv6

        tasks = [self._lookup_ip(ip, target, result, sem, config) for ip in unique_ips]
        await asyncio.gather(*tasks)

    async def _lookup_ip(
        self,
        ip: str,
        target: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: object,
    ) -> None:
        """Query Team Cymru for ASN information about an IP."""
        cfg = config  # type: ignore[assignment]
        async with sem:
            try:
                # Reverse the IP octets for the DNS query
                reversed_ip = ".".join(ip.split(".")[::-1])
                origin_query = f"{reversed_ip}.origin.asn.cymru.com"

                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", origin_query, "TXT",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=cfg.dns_timeout,
                )
                origin_output = stdout.decode().strip().strip('"')

                if not origin_output:
                    return

                # Parse: "ASN | IP_RANGE | CC | RIR | DATE"
                parts = [p.strip() for p in origin_output.split("|")]
                if len(parts) < 3:
                    return

                asn_num = parts[0].strip()
                ip_range = parts[1].strip()
                country = parts[2].strip()

                # Get ASN name
                asn_name = ""
                asn_query = f"AS{asn_num}.asn.cymru.com"
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", asn_query, "TXT",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=cfg.dns_timeout,
                )
                name_output = stdout.decode().strip().strip('"')
                if name_output:
                    name_parts = [p.strip() for p in name_output.split("|")]
                    if len(name_parts) >= 5:
                        asn_name = name_parts[4].strip()

                # Add ASN asset
                result.add_asset(Asset(
                    value=f"AS{asn_num}",
                    type=AssetType.ASN,
                    status=AssetStatus.LIVE,
                    parent=target,
                    source="asn-cymru",
                    metadata={
                        "asn": asn_num,
                        "name": asn_name,
                        "country": country,
                        "ip_range": ip_range,
                        "source_ip": ip,
                    },
                    notes=f"AS{asn_num} — {asn_name} ({country})",
                ))

                # Add IP range asset
                if ip_range:
                    result.add_asset(Asset(
                        value=ip_range,
                        type=AssetType.IP_RANGE,
                        status=AssetStatus.LIVE,
                        parent=f"AS{asn_num}",
                        source="asn-cymru",
                        metadata={
                            "asn": asn_num,
                            "asn_name": asn_name,
                            "country": country,
                        },
                    ))

            except asyncio.TimeoutError:
                logger.warning("ASN lookup timed out for %s", ip)
            except FileNotFoundError:
                logger.warning("dig not found — skipping ASN lookup")
            except Exception as e:
                logger.warning("ASN lookup failed for %s: %s", ip, e)


class ReverseDNSModule(DiscoveryModule):
    """Reverse DNS (PTR) lookups for discovered IP addresses."""

    name = "Reverse DNS"
    description = "PTR record lookups to discover hostnames from IPs"

    async def discover(self, target: str, result: ScanResult) -> None:
        ip_assets = result.get_by_type(AssetType.IP)
        if not ip_assets:
            logger.info("No IPs discovered — skipping reverse DNS")
            return

        config = get_config()
        sem = asyncio.Semaphore(config.max_concurrent_dns)
        unique_ips = list({a.value for a in ip_assets})

        tasks = [
            self._reverse_lookup(ip, target, result, sem, config)
            for ip in unique_ips
        ]
        await asyncio.gather(*tasks)

    async def _reverse_lookup(
        self,
        ip: str,
        target: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: object,
    ) -> None:
        """Run reverse DNS lookup for a single IP."""
        cfg = config  # type: ignore[assignment]
        async with sem:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", "-x", ip,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=cfg.dns_timeout,
                )
                output = stdout.decode().strip()

                if not output:
                    return

                for line in output.split("\n"):
                    hostname = line.strip().rstrip(".")
                    if not hostname:
                        continue

                    logger.debug("PTR %s -> %s", ip, hostname)

                    # Add as subdomain if it belongs to the target domain
                    if hostname.endswith(f".{target}") or hostname == target:
                        result.add_asset(Asset(
                            value=hostname,
                            type=AssetType.SUBDOMAIN,
                            parent=target,
                            source="reverse-dns",
                            metadata={"ptr_ip": ip},
                        ))
                    else:
                        # Log non-target PTR records for reference
                        logger.debug(
                            "PTR record %s -> %s (outside target domain)",
                            ip, hostname,
                        )

            except asyncio.TimeoutError:
                logger.debug("Reverse DNS timed out for %s", ip)
            except FileNotFoundError:
                logger.warning("dig not found — skipping reverse DNS")
            except Exception as e:
                logger.debug("Reverse DNS failed for %s: %s", ip, e)


class SSLAnalysisModule(DiscoveryModule):
    """SSL/TLS certificate and configuration analysis for live hosts."""

    name = "SSL/TLS Analysis"
    description = "Analyze certificates, TLS versions, and cipher suites"

    async def discover(self, target: str, result: ScanResult) -> None:
        live_hosts = result.get_live_hosts()
        if not live_hosts:
            logger.info("No live hosts — skipping SSL analysis")
            return

        config = get_config()
        sem = asyncio.Semaphore(config.max_concurrent_ssl)

        tasks = [
            self._analyze_host(host, target, result, sem, config)
            for host in live_hosts
        ]
        await asyncio.gather(*tasks)

    async def _analyze_host(
        self,
        host: str,
        target: str,
        result: ScanResult,
        sem: asyncio.Semaphore,
        config: object,
    ) -> None:
        """Analyze SSL/TLS for a single host."""
        cfg = config  # type: ignore[assignment]
        async with sem:
            try:
                cert_info = await asyncio.wait_for(
                    asyncio.to_thread(self._get_cert_info, host),
                    timeout=cfg.ssl_timeout,
                )

                if cert_info is None:
                    return

                cert_dict = cert_info["cert"]
                tls_version = cert_info["tls_version"]
                cipher_name = cert_info["cipher_name"]
                cipher_bits = cert_info["cipher_bits"]

                # Extract subject
                subject_parts: list[str] = []
                for rdn in cert_dict.get("subject", ()):
                    for attr_type, attr_value in rdn:
                        subject_parts.append(f"{attr_type}={attr_value}")
                subject_str = ", ".join(subject_parts)

                # Extract issuer
                issuer_parts: list[str] = []
                for rdn in cert_dict.get("issuer", ()):
                    for attr_type, attr_value in rdn:
                        issuer_parts.append(f"{attr_type}={attr_value}")
                issuer_str = ", ".join(issuer_parts)

                # Extract SANs
                sans: list[str] = []
                for san_type, san_value in cert_dict.get("subjectAltName", ()):
                    if san_type == "DNS":
                        sans.append(san_value.lower())

                # Extract expiry
                not_after_str = cert_dict.get("notAfter", "")
                not_before_str = cert_dict.get("notBefore", "")

                # Check for expired certificate
                severity = Severity.INFO
                notes_parts: list[str] = []

                if not_after_str:
                    try:
                        not_after = datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z",
                        ).replace(tzinfo=timezone.utc)
                        if not_after < datetime.now(timezone.utc):
                            severity = Severity.CRITICAL
                            notes_parts.append("EXPIRED certificate")
                    except ValueError:
                        logger.debug("Could not parse notAfter: %s", not_after_str)

                # Check TLS version
                if tls_version and tls_version < "TLSv1.2":
                    if severity.value not in ("critical",):
                        severity = Severity.HIGH
                    notes_parts.append(f"Weak TLS version: {tls_version}")

                # Check cipher strength
                is_weak_cipher = any(
                    weak in cipher_name.upper() for weak in WEAK_CIPHERS
                )
                if is_weak_cipher:
                    if severity.value not in ("critical", "high"):
                        severity = Severity.MEDIUM
                    notes_parts.append(f"Weak cipher: {cipher_name}")

                # Add SANs as new subdomain discoveries
                for san in sans:
                    san_clean = san.lstrip("*.")
                    if (
                        san_clean.endswith(f".{target}") or san_clean == target
                    ) and san_clean != host:
                        result.add_asset(Asset(
                            value=san_clean,
                            type=AssetType.SUBDOMAIN,
                            parent=target,
                            source="ssl-san",
                            metadata={"discovered_from": host},
                        ))

                # Add certificate asset
                result.add_asset(Asset(
                    value=f"cert:{host}",
                    type=AssetType.CERTIFICATE,
                    status=AssetStatus.LIVE,
                    parent=host,
                    source="ssl-analysis",
                    severity=severity,
                    metadata={
                        "subject": subject_str,
                        "issuer": issuer_str,
                        "sans": sans,
                        "not_before": not_before_str,
                        "not_after": not_after_str,
                        "tls_version": tls_version,
                        "cipher_name": cipher_name,
                        "cipher_bits": cipher_bits,
                        "serial_number": cert_dict.get("serialNumber", ""),
                    },
                    notes="; ".join(notes_parts) if notes_parts else "Certificate OK",
                ))

            except asyncio.TimeoutError:
                logger.debug("SSL analysis timed out for %s", host)
            except Exception as e:
                logger.debug("SSL analysis failed for %s: %s", host, e)

    @staticmethod
    def _get_cert_info(host: str) -> dict[str, object] | None:
        """Connect to host and retrieve certificate details (blocking)."""
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert is None:
                        return None
                    cipher = ssock.cipher()
                    tls_version = ssock.version()
                    return {
                        "cert": cert,
                        "tls_version": tls_version or "",
                        "cipher_name": cipher[0] if cipher else "",
                        "cipher_bits": cipher[2] if cipher and len(cipher) > 2 else 0,
                    }
        except (ssl.SSLError, ssl.CertificateError, OSError):
            # Try again without verification for analysis purposes
            ctx_noverify = ssl.create_default_context()
            ctx_noverify.check_hostname = False
            ctx_noverify.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, 443)) as sock:
                    with ctx_noverify.wrap_socket(
                        sock, server_hostname=host,
                    ) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        cipher = ssock.cipher()
                        tls_version = ssock.version()
                        # Binary cert has limited info; return what we can
                        return {
                            "cert": {
                                "subject": (),
                                "issuer": (),
                                "subjectAltName": (),
                                "notAfter": "",
                                "notBefore": "",
                                "serialNumber": "",
                            },
                            "tls_version": tls_version or "",
                            "cipher_name": cipher[0] if cipher else "",
                            "cipher_bits": (
                                cipher[2] if cipher and len(cipher) > 2 else 0
                            ),
                        }
            except Exception:
                return None


class DNSZoneTransferModule(DiscoveryModule):
    """Attempt DNS zone transfers (AXFR) against discovered nameservers."""

    name = "DNS Zone Transfer"
    description = "Detect misconfigured nameservers allowing zone transfers"

    async def discover(self, target: str, result: ScanResult) -> None:
        ns_assets = result.get_by_type(AssetType.NAMESERVER)
        if not ns_assets:
            logger.info("No nameservers discovered — skipping zone transfer check")
            return

        config = get_config()
        unique_ns = list({a.value for a in ns_assets})

        tasks = [
            self._try_axfr(ns, target, result, config)
            for ns in unique_ns
        ]
        await asyncio.gather(*tasks)

    async def _try_axfr(
        self,
        ns: str,
        target: str,
        result: ScanResult,
        config: object,
    ) -> None:
        """Attempt AXFR against a single nameserver."""
        cfg = config  # type: ignore[assignment]
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", f"@{ns}", target, "AXFR",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.axfr_timeout,
            )
            output = stdout.decode().strip()

            if not output:
                return

            # Check for transfer failure indicators
            if "Transfer failed" in output or "failed" in output.lower():
                logger.debug("Zone transfer denied by %s (expected)", ns)
                return

            if "; XFR size:" not in output and "AXFR" not in output:
                logger.debug("No zone transfer data from %s", ns)
                return

            # Zone transfer succeeded — this is a security issue
            logger.warning(
                "ZONE TRANSFER: %s allows AXFR for %s", ns, target,
            )

            result.add_asset(Asset(
                value=f"axfr:{ns}:{target}",
                type=AssetType.DNS_ISSUE,
                status=AssetStatus.MISCONFIGURED,
                parent=target,
                source="zone-transfer",
                severity=Severity.HIGH,
                notes=(
                    f"Nameserver {ns} allows zone transfer (AXFR) for {target}. "
                    "Zone transfers should be restricted to authorized secondaries."
                ),
                metadata={"nameserver": ns, "domain": target},
            ))

            # Parse hostnames and IPs from the zone data
            hostname_pattern = re.compile(
                r"^(\S+)\.\s+\d+\s+IN\s+(?:A|AAAA|CNAME|MX|NS)\s+",
                re.MULTILINE,
            )
            ip_pattern = re.compile(
                r"\s+IN\s+A\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            )

            for match in hostname_pattern.finditer(output):
                hostname = match.group(1).rstrip(".").lower()
                if hostname.endswith(f".{target}") or hostname == target:
                    result.add_asset(Asset(
                        value=hostname,
                        type=AssetType.SUBDOMAIN,
                        parent=target,
                        source="zone-transfer",
                        metadata={"discovered_via_axfr": ns},
                    ))

            for match in ip_pattern.finditer(output):
                ip = match.group(1)
                result.add_asset(Asset(
                    value=ip,
                    type=AssetType.IP,
                    parent=target,
                    source="zone-transfer",
                    metadata={"discovered_via_axfr": ns},
                ))

        except asyncio.TimeoutError:
            logger.debug("Zone transfer timed out for %s", ns)
        except FileNotFoundError:
            logger.warning("dig not found — skipping zone transfer check")
        except Exception as e:
            logger.debug("Zone transfer check failed for %s: %s", ns, e)


class EmailSecurityModule(DiscoveryModule):
    """Check SPF, DKIM, and DMARC email security configuration."""

    name = "Email Security"
    description = "Analyze SPF, DKIM, and DMARC records for misconfigurations"

    async def discover(self, target: str, result: ScanResult) -> None:
        config = get_config()

        await asyncio.gather(
            self._check_spf(target, result, config),
            self._check_dmarc(target, result, config),
            self._check_dkim(target, result, config),
        )

    async def _check_spf(
        self, target: str, result: ScanResult, config: object,
    ) -> None:
        """Query and parse SPF records."""
        cfg = config  # type: ignore[assignment]
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", target, "TXT",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.dns_timeout,
            )
            output = stdout.decode().strip()

            if not output:
                result.add_asset(Asset(
                    value=f"spf:missing:{target}",
                    type=AssetType.DNS_ISSUE,
                    status=AssetStatus.MISCONFIGURED,
                    parent=target,
                    source="email-spf",
                    severity=Severity.MEDIUM,
                    notes=f"No TXT records found for {target} (SPF missing)",
                ))
                return

            # Find SPF record among TXT records
            spf_record = ""
            for line in output.split("\n"):
                cleaned = line.strip().strip('"')
                if "v=spf1" in cleaned.lower():
                    spf_record = cleaned
                    break

            if not spf_record:
                result.add_asset(Asset(
                    value=f"spf:missing:{target}",
                    type=AssetType.DNS_ISSUE,
                    status=AssetStatus.MISCONFIGURED,
                    parent=target,
                    source="email-spf",
                    severity=Severity.MEDIUM,
                    notes=f"No SPF record found for {target}",
                ))
                return

            # Parse SPF directives
            # Extract include: directives
            includes = re.findall(r"include:(\S+)", spf_record)
            for include_domain in includes:
                include_domain = include_domain.rstrip(".")
                result.add_asset(Asset(
                    value=include_domain,
                    type=AssetType.SUBDOMAIN,
                    parent=target,
                    source="email-spf-include",
                    metadata={"spf_directive": f"include:{include_domain}"},
                ))

            # Extract ip4: directives
            ip4s = re.findall(r"ip4:(\S+)", spf_record)
            for ip4 in ip4s:
                # Could be a single IP or CIDR
                ip_value = ip4.split("/")[0]
                result.add_asset(Asset(
                    value=ip_value,
                    type=AssetType.IP,
                    parent=target,
                    source="email-spf-ip4",
                    metadata={"spf_directive": f"ip4:{ip4}"},
                ))
                if "/" in ip4:
                    result.add_asset(Asset(
                        value=ip4,
                        type=AssetType.IP_RANGE,
                        parent=target,
                        source="email-spf-ip4",
                        metadata={"spf_directive": f"ip4:{ip4}"},
                    ))

            # Extract ip6: directives
            ip6s = re.findall(r"ip6:(\S+)", spf_record)
            for ip6 in ip6s:
                ip_value = ip6.split("/")[0]
                result.add_asset(Asset(
                    value=ip_value,
                    type=AssetType.IP,
                    parent=target,
                    source="email-spf-ip6",
                    metadata={"spf_directive": f"ip6:{ip6}"},
                ))
                if "/" in ip6:
                    result.add_asset(Asset(
                        value=ip6,
                        type=AssetType.IP_RANGE,
                        parent=target,
                        source="email-spf-ip6",
                        metadata={"spf_directive": f"ip6:{ip6}"},
                    ))

            # Check for overly permissive SPF (+all)
            if "+all" in spf_record:
                result.add_asset(Asset(
                    value=f"spf:permissive:{target}",
                    type=AssetType.DNS_ISSUE,
                    status=AssetStatus.MISCONFIGURED,
                    parent=target,
                    source="email-spf",
                    severity=Severity.HIGH,
                    notes=(
                        f"SPF record uses +all (allow all), "
                        f"defeating the purpose of SPF: {spf_record}"
                    ),
                    metadata={"spf_record": spf_record},
                ))

        except asyncio.TimeoutError:
            logger.warning("SPF lookup timed out for %s", target)
        except FileNotFoundError:
            logger.warning("dig not found — skipping SPF check")
        except Exception as e:
            logger.warning("SPF check failed for %s: %s", target, e)

    async def _check_dmarc(
        self, target: str, result: ScanResult, config: object,
    ) -> None:
        """Query and analyze DMARC record."""
        cfg = config  # type: ignore[assignment]
        try:
            dmarc_domain = f"_dmarc.{target}"
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", dmarc_domain, "TXT",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=cfg.dns_timeout,
            )
            output = stdout.decode().strip()

            if not output:
                result.add_asset(Asset(
                    value=f"dmarc:missing:{target}",
                    type=AssetType.DNS_ISSUE,
                    status=AssetStatus.MISCONFIGURED,
                    parent=target,
                    source="email-dmarc",
                    severity=Severity.MEDIUM,
                    notes=f"No DMARC record found for {target}",
                ))
                return

            # Find DMARC record
            dmarc_record = ""
            for line in output.split("\n"):
                cleaned = line.strip().strip('"')
                if "v=dmarc1" in cleaned.lower():
                    dmarc_record = cleaned
                    break

            if not dmarc_record:
                result.add_asset(Asset(
                    value=f"dmarc:missing:{target}",
                    type=AssetType.DNS_ISSUE,
                    status=AssetStatus.MISCONFIGURED,
                    parent=target,
                    source="email-dmarc",
                    severity=Severity.MEDIUM,
                    notes=f"No valid DMARC record found for {target}",
                ))
                return

            # Check policy
            policy_match = re.search(r"p=(\w+)", dmarc_record)
            policy = policy_match.group(1).lower() if policy_match else "none"

            if policy == "none":
                result.add_asset(Asset(
                    value=f"dmarc:weak:{target}",
                    type=AssetType.DNS_ISSUE,
                    status=AssetStatus.MISCONFIGURED,
                    parent=target,
                    source="email-dmarc",
                    severity=Severity.MEDIUM,
                    notes=(
                        f"DMARC policy is set to 'none' (monitoring only). "
                        f"Consider upgrading to 'quarantine' or 'reject': "
                        f"{dmarc_record}"
                    ),
                    metadata={
                        "dmarc_record": dmarc_record,
                        "policy": policy,
                    },
                ))

        except asyncio.TimeoutError:
            logger.warning("DMARC lookup timed out for %s", target)
        except FileNotFoundError:
            logger.warning("dig not found — skipping DMARC check")
        except Exception as e:
            logger.warning("DMARC check failed for %s: %s", target, e)

    async def _check_dkim(
        self, target: str, result: ScanResult, config: object,
    ) -> None:
        """Check DKIM records for configured selectors."""
        cfg = config  # type: ignore[assignment]
        sem = asyncio.Semaphore(cfg.max_concurrent_dns)

        async def check_selector(selector: str) -> None:
            async with sem:
                try:
                    dkim_domain = f"{selector}._domainkey.{target}"
                    proc = await asyncio.create_subprocess_exec(
                        "dig", "+short", dkim_domain, "TXT",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, _ = await asyncio.wait_for(
                        proc.communicate(), timeout=cfg.dns_timeout,
                    )
                    output = stdout.decode().strip()

                    if output and "NXDOMAIN" not in output:
                        logger.debug(
                            "DKIM selector found: %s for %s", selector, target,
                        )
                        # DKIM record exists — not an issue, informational
                except asyncio.TimeoutError:
                    logger.debug(
                        "DKIM check timed out for selector %s", selector,
                    )
                except FileNotFoundError:
                    logger.warning("dig not found — skipping DKIM check")
                except Exception as e:
                    logger.debug(
                        "DKIM check failed for %s._domainkey.%s: %s",
                        selector, target, e,
                    )

        tasks = [check_selector(s.strip()) for s in cfg.dkim_selectors]
        await asyncio.gather(*tasks)

        # If no DKIM selectors responded, flag it
        found_dkim = False
        for selector in cfg.dkim_selectors:
            selector = selector.strip()
            dkim_domain = f"{selector}._domainkey.{target}"
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", dkim_domain, "TXT",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await asyncio.wait_for(
                    proc.communicate(), timeout=cfg.dns_timeout,
                )
                output = stdout.decode().strip()
                if output and "NXDOMAIN" not in output:
                    found_dkim = True
                    break
            except Exception:
                continue

        if not found_dkim:
            result.add_asset(Asset(
                value=f"dkim:missing:{target}",
                type=AssetType.DNS_ISSUE,
                status=AssetStatus.MISCONFIGURED,
                parent=target,
                source="email-dkim",
                severity=Severity.LOW,
                notes=(
                    f"No DKIM records found for common selectors on {target}. "
                    "DKIM may use non-standard selectors or may not be configured."
                ),
                metadata={"selectors_checked": cfg.dkim_selectors},
            ))
