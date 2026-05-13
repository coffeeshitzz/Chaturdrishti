import shodan
import socket
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from dotenv import load_dotenv
from graph.schema import Signal, SourceType, Entity, SensitivityLevel

load_dotenv()


# Services that are almost always sensitive when exposed
CRITICAL_SERVICES = {
    "ssh", "telnet", "rdp", "vnc", "ftp",
    "mongodb", "redis", "elasticsearch",
    "memcached", "cassandra", "couchdb",
    "kubernetes", "docker", "etcd",
    "smtp", "smtps"
}

# Services that reveal infrastructure details
HIGH_SERVICES = {
    "http", "https", "jenkins", "grafana",
    "prometheus", "kibana", "rabbitmq",
    "mysql", "postgresql", "mssql",
    "oracle", "ldap", "snmp", "ntp"
}


class ShodanCollector:
    """
    Queries Shodan for exposed services, open ports, banners,
    and known CVEs associated with the target organization.
    Resolves domain to IPs first, then uses free-tier host lookup.
    Requires a Shodan API key (free tier works).
    """

    def __init__(self, target_org: str):
        self.target_org = target_org
        self.api_key    = os.getenv("SHODAN_API_KEY")
        self.signals: List[Signal] = []
        self._api       = None

    def _get_api(self):
        if not self.api_key:
            raise ValueError(
                "SHODAN_API_KEY not set in .env — "
                "get a free key at shodan.io"
            )
        if not self._api:
            self._api = shodan.Shodan(self.api_key)
        return self._api

    def collect(self) -> List[Signal]:
        """Main entry point."""
        logger.info(f"🔍 Starting Shodan collection for: {self.target_org}")

        try:
            api = self._get_api()

            # Step 1 — resolve domain to IPs
            ips = self._resolve_ips()
            if not ips:
                logger.warning(
                    f"  Could not resolve any IPs for {self.target_org}"
                )
                return self.signals

            logger.info(f"  Resolved {len(ips)} IP(s): {ips}")

            # Step 2 — look up each IP on Shodan (free tier supported)
            for ip in ips[:5]:
                self._lookup_ip(api, ip)

        except ValueError as e:
            logger.warning(f"  {e}")
        except Exception as e:
            logger.error(f"  Shodan collection failed: {e}")

        logger.success(
            f"✅ Shodan collection complete — {len(self.signals)} signals"
        )
        return self.signals

    def _resolve_ips(self) -> List[str]:
        """Resolve target domain to IPv4 addresses."""
        ips = []
        try:
            results = socket.getaddrinfo(self.target_org, None)
            ips = list(set([r[4][0] for r in results]))
            ips = [ip for ip in ips if ":" not in ip]  # IPv4 only
        except Exception as e:
            logger.warning(f"  DNS resolution failed: {e}")
        return ips

    def _lookup_ip(self, api, ip: str):
        """Look up a single IP on Shodan using free-tier host endpoint."""
        try:
            logger.info(f"  Looking up IP: {ip}")
            host = api.host(ip)

            for item in host.get("data", []):
                # Merge top-level host fields into each service item
                item["ip_str"]   = host.get("ip_str", ip)
                item["org"]      = host.get("org", "")
                item["hostnames"]= host.get("hostnames", [])
                item["os"]       = host.get("os", "")
                item["location"] = host.get("location", {})
                item["vulns"]    = item.get("vulns", {})
                self._process_host(item)

        except shodan.APIError as e:
            if "No information available" in str(e):
                logger.info(f"  No Shodan data for {ip}")
            else:
                logger.warning(f"  Shodan lookup failed for {ip}: {e}")
        except Exception as e:
            logger.warning(f"  Unexpected error for {ip}: {e}")

    def _process_host(self, host: dict):
        """Extract signals from a single Shodan service record."""
        ip        = host.get("ip_str", "")
        port      = host.get("port", "")
        transport = host.get("transport", "tcp")
        product   = host.get("product", "")
        version   = host.get("version", "")
        banner    = host.get("data", "")[:300]
        org       = host.get("org", "")
        hostnames = host.get("hostnames", [])
        cves      = host.get("vulns", {})
        os_info   = host.get("os", "")
        location  = host.get("location", {})
        country   = location.get("country_name", "")

        service_name = product.lower() if product else str(port)

        # ── Exposed service signal ─────────────────────────────────
        sensitivity, reason = self._assess_service(
            service_name, port, cves, banner
        )

        service_desc = f"{product} {version}".strip() if product else f"port {port}"
        content = (
            f"Exposed service: {service_desc} on {ip}:{port}/{transport}  |  "
            f"Org: {org}  |  "
            f"Hostnames: {', '.join(hostnames[:3]) or 'none'}  |  "
            f"Country: {country}"
        )

        entities = self._extract_entities(
            ip, port, product, version, hostnames, org
        )

        self.signals.append(Signal(
            target_org=self.target_org,
            source_type=SourceType.SHODAN,
            source_url=f"https://www.shodan.io/host/{ip}",
            raw_content=content,
            entities=entities,
            sensitivity=sensitivity,
            sensitivity_reason=reason,
            metadata={
                "ip":        ip,
                "port":      port,
                "transport": transport,
                "product":   product,
                "version":   version,
                "org":       org,
                "hostnames": hostnames,
                "os":        os_info,
                "country":   country,
                "banner":    banner,
                "cve_count": len(cves),
            }
        ))

        logger.info(
            f"  [{sensitivity}] {service_desc} on {ip}:{port}"
        )

        # ── CVE signals ────────────────────────────────────────────
        for cve_id, cve_data in list(cves.items())[:5]:
            self._process_cve(ip, port, cve_id, cve_data, product)

        # ── Banner signal ──────────────────────────────────────────
        if banner and self._banner_is_interesting(banner):
            self._process_banner(ip, port, banner, product)

    def _process_cve(
        self, ip: str, port: int,
        cve_id: str, cve_data: dict, product: str
    ):
        """Create a dedicated signal for each CVE found."""
        cvss    = cve_data.get("cvss", 0.0)
        summary = cve_data.get("summary", "No description available")[:200]

        if cvss >= 9.0:
            sensitivity = SensitivityLevel.CRITICAL
            reason      = f"{cve_id} CVSS {cvss} — critical severity"
        elif cvss >= 7.0:
            sensitivity = SensitivityLevel.HIGH
            reason      = f"{cve_id} CVSS {cvss} — high severity"
        else:
            sensitivity = SensitivityLevel.MEDIUM
            reason      = f"{cve_id} CVSS {cvss} — known vulnerability"

        content = (
            f"CVE: {cve_id} (CVSS {cvss}) on {ip}:{port}  |  "
            f"Product: {product}  |  {summary}"
        )

        self.signals.append(Signal(
            target_org=self.target_org,
            source_type=SourceType.SHODAN,
            source_url=f"https://www.shodan.io/host/{ip}",
            raw_content=content,
            entities=[
                Entity(
                    name=cve_id,
                    entity_type="CVE",
                    confidence=1.0,
                    context=f"{cve_id} on {product} at {ip}:{port}"
                )
            ],
            sensitivity=sensitivity,
            sensitivity_reason=reason,
            metadata={
                "cve_id":  cve_id,
                "cvss":    cvss,
                "summary": summary,
                "ip":      ip,
                "port":    port,
                "product": product,
            }
        ))
        logger.warning(
            f"  ⚠️  CVE: {cve_id} CVSS {cvss} on {ip}:{port}"
        )

    def _process_banner(self, ip: str, port: int, banner: str, product: str):
        """Signal from an interesting service banner."""
        self.signals.append(Signal(
            target_org=self.target_org,
            source_type=SourceType.SHODAN,
            source_url=f"https://www.shodan.io/host/{ip}",
            raw_content=(
                f"Service banner on {ip}:{port} "
                f"({product}): {banner}"
            ),
            entities=[],
            sensitivity=SensitivityLevel.MEDIUM,
            sensitivity_reason=(
                "Banner reveals software version and configuration details"
            ),
            metadata={
                "ip":     ip,
                "port":   port,
                "banner": banner,
            }
        ))

    def _assess_service(
        self, service: str, port: int,
        cves: dict, banner: str
    ):
        """Assign sensitivity to an exposed service."""
        s = service.lower()
        b = banner.lower()

        # CVEs always escalate severity
        if cves:
            max_cvss = max(
                (v.get("cvss", 0) for v in cves.values()),
                default=0
            )
            if max_cvss >= 7.0:
                return (
                    SensitivityLevel.CRITICAL,
                    f"{len(cves)} CVE(s) found, max CVSS {max_cvss}"
                )

        if any(svc in s for svc in CRITICAL_SERVICES):
            return (
                SensitivityLevel.CRITICAL,
                f"Sensitive service '{service}' exposed on port {port}"
            )

        if any(kw in b for kw in ["version", "server:", "x-powered-by"]):
            return (
                SensitivityLevel.HIGH,
                "Banner reveals software version details"
            )

        if any(svc in s for svc in HIGH_SERVICES):
            return (
                SensitivityLevel.HIGH,
                f"Service '{service}' on port {port} exposes infrastructure"
            )

        return (
            SensitivityLevel.MEDIUM,
            f"Open port {port} ({service}) publicly reachable"
        )

    def _banner_is_interesting(self, banner: str) -> bool:
        """Check if a banner leaks useful intelligence."""
        keywords = [
            "server:", "x-powered-by", "version",
            "apache", "nginx", "iis", "tomcat",
            "openssh", "openssl", "php", "python",
            "ruby", "node", "express", "django"
        ]
        b = banner.lower()
        return any(kw in b for kw in keywords)

    def _extract_entities(
        self, ip: str, port: int, product: str,
        version: str, hostnames: list, org: str
    ) -> List[Entity]:
        """Extract structured entities from a host record."""
        entities = []

        if ip:
            entities.append(Entity(
                name=ip,
                entity_type="IP_ADDRESS",
                confidence=1.0,
                context=f"IP found via Shodan for {self.target_org}"
            ))

        if product:
            name = f"{product} {version}".strip()
            entities.append(Entity(
                name=name,
                entity_type="TECHNOLOGY",
                confidence=0.95,
                context=f"{name} running on {ip}:{port}"
            ))

        for hostname in hostnames[:3]:
            if hostname:
                entities.append(Entity(
                    name=hostname,
                    entity_type="HOSTNAME",
                    confidence=1.0,
                    context=f"Hostname linked to {ip} via Shodan"
                ))

        if org:
            entities.append(Entity(
                name=org,
                entity_type="ORGANIZATION",
                confidence=0.9,
                context=f"Shodan org field for {ip}"
            ))

        return entities