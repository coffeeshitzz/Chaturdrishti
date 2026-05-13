import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List, Dict, Any, Optional
from graph.ingestion import Neo4jConnection
from graph.schema import AttackSurface, ConfirmedHost, PersonProfile


# ── Sensitive subdomain patterns ──────────────────────────────────────────────
SENSITIVE_PREFIXES = {
    "critical": [
        "internal", "intranet", "corp", "vpn", "ssh",
        "bastion", "jumpbox", "admin", "administrator",
        "root", "private", "secret",
    ],
    "high": [
        "staging", "stage", "stg", "dev", "development",
        "test", "testing", "beta", "sandbox", "preprod",
        "uat", "qa", "jenkins", "gitlab", "grafana",
        "kibana", "vault", "consul", "prometheus",
        "elasticsearch", "kibana", "rancher", "harbor",
        "k8s", "kube", "kubernetes", "docker",
        "registry", "artifactory", "nexus",
        "jira", "confluence", "bitbucket",
        "airflow", "superset", "metabase",
    ],
    "medium": [
        "api", "api2", "apiv1", "apiv2",
        "portal", "dashboard", "manage", "management",
        "control", "panel", "backend", "backoffice",
        "mail", "email", "smtp", "webmail",
        "ftp", "sftp", "files", "upload",
        "cdn", "static", "assets",
        "db", "database", "mysql", "postgres", "redis",
        "mongo", "elastic", "solr",
    ],
}

# ── Sensitive port → service mapping ─────────────────────────────────────────
SENSITIVE_PORTS = {
    22:    ("SSH",              "critical"),
    23:    ("Telnet",           "critical"),
    3389:  ("RDP",              "critical"),
    5900:  ("VNC",              "critical"),
    2375:  ("Docker API",       "critical"),
    2376:  ("Docker TLS API",   "critical"),
    6443:  ("Kubernetes API",   "critical"),
    2379:  ("etcd",             "critical"),
    8200:  ("HashiCorp Vault",  "critical"),
    9200:  ("Elasticsearch",    "critical"),
    27017: ("MongoDB",          "critical"),
    6379:  ("Redis",            "critical"),
    5432:  ("PostgreSQL",       "critical"),
    3306:  ("MySQL",            "critical"),
    1521:  ("Oracle DB",        "critical"),
    8080:  ("HTTP Alt",         "high"),
    8443:  ("HTTPS Alt",        "high"),
    8888:  ("Jupyter/Alt HTTP", "high"),
    9090:  ("Prometheus",       "high"),
    3000:  ("Grafana/Node",     "high"),
    5601:  ("Kibana",           "high"),
    15672: ("RabbitMQ Mgmt",   "high"),
    9092:  ("Kafka",            "high"),
    4040:  ("Spark UI",         "high"),
    8500:  ("Consul",           "high"),
}


class CorrelationEngine:
    """
    Queries the Neo4j knowledge graph to build a structured
    AttackSurface from cross-source correlated signals.

    Does not collect new data. Does not make network requests.
    Purely reasons over what has already been collected.
    """

    def __init__(self):
        pass

    def build_attack_surface(self, target_org: str) -> AttackSurface:
        """
        Main entry point. Builds a complete AttackSurface
        by running structured Cypher queries against the graph.
        """
        logger.info(
            f"🔗 Building attack surface for: {target_org}"
        )

        surface = AttackSurface(target_org=target_org)

        with Neo4jConnection() as conn:
            surface.confirmed_hosts  = self._find_confirmed_hosts(conn, target_org)
            surface.sensitive_hosts  = self._find_sensitive_hosts(conn, target_org)
            surface.technology_stack = self._find_technology_stack(conn, target_org)
            surface.cloud_profile    = self._build_cloud_profile(conn, target_org)
            surface.people_profiles  = self._find_people(conn, target_org)
            surface.saas_services    = self._find_saas_services(conn, target_org)
            surface.exposed_ports    = self._find_exposed_ports(conn, target_org)
            surface.cves_found       = self._find_cves(conn, target_org)
            surface.secrets_found    = self._find_secrets(conn, target_org)

        surface.risk_score    = self._calculate_risk_score(surface)
        surface.summary_stats = self._build_summary_stats(surface)

        self._log_surface(surface)
        return surface

    # ── Query methods ─────────────────────────────────────────────────────────

    def _find_confirmed_hosts(
        self, conn, target_org: str
    ) -> List[ConfirmedHost]:
        """
        Find hostnames confirmed by 2+ independent sources.
        These are high-confidence real targets.
        """
        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'HOSTNAME'
            AND e.source_count >= 2
            AND NOT e.name STARTS WITH '*'
            RETURN e.name        AS hostname,
                   e.source_count AS source_count,
                   e.sources      AS sources,
                   e.confidence   AS confidence
            ORDER BY e.source_count DESC
        """, {"domain": target_org})

        hosts = []
        for row in results:
            hostname = row["hostname"]
            host = ConfirmedHost(
                hostname=hostname,
                source_count=row["source_count"] or 1,
                sources=list(row["sources"] or []),
                confidence=float(row["confidence"] or 0.5),
            )
            # Get IPs linked to this hostname
            host.ip_addresses = self._get_ips_for_host(conn, hostname)
            # Get open ports on those IPs
            for ip in host.ip_addresses:
                host.open_ports.extend(
                    self._get_ports_for_ip(conn, ip)
                )
            # Assess sensitivity
            host.sensitivity, host.risk_reasons = \
                self._assess_host_sensitivity(hostname, host.open_ports)
            hosts.append(host)

        return hosts

    def _find_sensitive_hosts(
        self, conn, target_org: str
    ) -> List[ConfirmedHost]:
        """
        Find hostnames with sensitive naming patterns
        regardless of source count.
        """
        all_prefixes = (
            SENSITIVE_PREFIXES["critical"] +
            SENSITIVE_PREFIXES["high"] +
            SENSITIVE_PREFIXES["medium"]
        )

        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'HOSTNAME'
            AND ANY(prefix IN $prefixes
                WHERE toLower(e.name) STARTS WITH prefix + '.'
                   OR toLower(e.name) CONTAINS '.' + prefix + '.')
            RETURN e.name         AS hostname,
                   e.source_count  AS source_count,
                   e.sources       AS sources,
                   e.confidence    AS confidence
            ORDER BY e.source_count DESC
        """, {"domain": target_org, "prefixes": all_prefixes})

        hosts = []
        seen  = set()
        for row in results:
            hostname = row["hostname"]
            if hostname in seen:
                continue
            seen.add(hostname)

            host = ConfirmedHost(
                hostname=hostname,
                source_count=row["source_count"] or 1,
                sources=list(row["sources"] or []),
                confidence=float(row["confidence"] or 0.5),
            )
            host.ip_addresses = self._get_ips_for_host(conn, hostname)
            for ip in host.ip_addresses:
                host.open_ports.extend(
                    self._get_ports_for_ip(conn, ip)
                )
            host.sensitivity, host.risk_reasons = \
                self._assess_host_sensitivity(hostname, host.open_ports)
            hosts.append(host)

        return hosts

    def _find_technology_stack(
        self, conn, target_org: str
    ) -> List[Dict]:
        """
        Find technologies confirmed by multiple sources.
        High source count = high confidence stack fingerprint.
        """
        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type IN [
                'TECHNOLOGY', 'EXPOSED_SERVICE',
                'DOCKER_IMAGE', 'DOCKER_SERVICE',
                'CLOUD_PROVIDER', 'PROGRAMMING_LANGUAGE',
                'KUBERNETES', 'DOCKER', 'TERRAFORM',
                'AWS', 'GCP', 'AZURE',
                'POSTGRESQL', 'MYSQL', 'MONGODB', 'REDIS',
                'ELASTICSEARCH', 'KAFKA', 'RABBITMQ',
                'FASTAPI', 'DJANGO', 'FLASK', 'REACT',
                'JENKINS', 'GITLAB', 'GRAFANA', 'PROMETHEUS',
                'HASHICORP_VAULT', 'ISTIO', 'NGINX', 'TRAEFIK'
            ]
            RETURN e.name         AS name,
                   e.entity_type  AS entity_type,
                   e.source_count AS source_count,
                   e.sources      AS sources
            ORDER BY e.source_count DESC
        """, {"domain": target_org})

        return [
            {
                "name":         row["name"],
                "type":         row["entity_type"],
                "source_count": row["source_count"] or 1,
                "sources":      list(row["sources"] or []),
                "confidence":   min(1.0, (row["source_count"] or 1) * 0.25),
            }
            for row in results
        ]

    def _build_cloud_profile(
        self, conn, target_org: str
    ) -> Dict[str, Any]:
        """
        Build a cloud provider profile from all cloud-related signals.
        """
        profile: Dict[str, Any] = {
            "providers": [],
            "regions":   [],
            "services":  [],
            "ip_ranges": [],
        }

        # Cloud providers
        providers = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type IN ['CLOUD_PROVIDER', 'AWS', 'GCP', 'AZURE']
            RETURN DISTINCT e.name AS name, e.source_count AS sc
            ORDER BY sc DESC
        """, {"domain": target_org})
        profile["providers"] = [r["name"] for r in providers]

        # Cloud regions
        regions = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'CLOUD_REGION'
            RETURN DISTINCT e.name AS name
        """, {"domain": target_org})
        profile["regions"] = [r["name"] for r in regions]

        # Cloud services (SES, S3, EKS etc)
        services = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type IN [
                'AWS_SES', 'AWS_S3', 'AWS_EKS', 'AWS_ACM',
                'AWS_LAMBDA', 'AWS_CLOUDFRONT',
                'GOOGLE_CA', 'GOOGLE_WORKSPACE',
                'CLOUDFLARE', 'SENDGRID', 'MAILCHIMP',
                'ATLASSIAN', 'STRIPE', 'ZOOM', 'DOCUSIGN',
                'SAAS_SERVICE'
            ]
            RETURN DISTINCT e.name AS name, e.entity_type AS type
        """, {"domain": target_org})
        profile["services"] = [
            {"name": r["name"], "type": r["type"]}
            for r in services
        ]

        # AWS IP ranges confirmed
        aws_ips = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'IP_ADDRESS'
            AND (
                e.name STARTS WITH '13.'
                OR e.name STARTS WITH '18.'
                OR e.name STARTS WITH '54.'
                OR e.name STARTS WITH '52.'
                OR e.name STARTS WITH '34.'
                OR e.name STARTS WITH '35.'
            )
            RETURN e.name AS ip, e.source_count AS sc
            ORDER BY sc DESC
            LIMIT 10
        """, {"domain": target_org})
        profile["ip_ranges"] = [r["ip"] for r in aws_ips]

        if profile["ip_ranges"] and "AWS" not in profile["providers"]:
            profile["providers"].append("AWS (inferred from IP ranges)")

        return profile

    def _find_people(
        self, conn, target_org: str
    ) -> List[PersonProfile]:
        """
        Find individuals with multiple data points across sources.
        These are potential spearphishing targets.
        """
        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type IN ['PERSON', 'GITHUB_USER', 'EMAIL_ADDRESS']
            RETURN e.name         AS name,
                   e.entity_type  AS type,
                   e.source_count AS source_count,
                   e.sources      AS sources
            ORDER BY e.source_count DESC
            LIMIT 20
        """, {"domain": target_org})

        # Group by person — try to connect names, emails, GitHub users
        profiles: Dict[str, PersonProfile] = {}
        for row in results:
            name   = row["name"]
            etype  = row["type"]
            sc     = row["source_count"] or 1
            sources= list(row["sources"] or [])

            if etype == "EMAIL_ADDRESS":
                # Use the part before @ as a key
                key = name.split("@")[0].lower()
                if key not in profiles:
                    profiles[key] = PersonProfile(
                        name=key, email=name,
                        source_count=sc, sources=sources
                    )
                else:
                    profiles[key].email = name
            elif etype == "GITHUB_USER":
                key = name.lower()
                if key not in profiles:
                    profiles[key] = PersonProfile(
                        name=name, github_user=name,
                        source_count=sc, sources=sources
                    )
                else:
                    profiles[key].github_user = name
            elif etype == "PERSON":
                key = name.lower().replace(" ", "")
                if key not in profiles:
                    profiles[key] = PersonProfile(
                        name=name,
                        source_count=sc, sources=sources
                    )

        return list(profiles.values())

    def _find_saas_services(
        self, conn, target_org: str
    ) -> List[str]:
        """Find SaaS services used by the organization."""
        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'SAAS_SERVICE'
            RETURN DISTINCT e.name AS name
            ORDER BY e.name
        """, {"domain": target_org})
        return [r["name"] for r in results]

    def _find_exposed_ports(
        self, conn, target_org: str
    ) -> List[Dict]:
        """Find open ports with associated services."""
        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'OPEN_PORT'
            RETURN e.name AS port, e.source_count AS sc
            ORDER BY sc DESC
        """, {"domain": target_org})

        exposed = []
        for row in results:
            try:
                port_num = int(row["port"])
                service_info = SENSITIVE_PORTS.get(port_num)
                if service_info:
                    service, sensitivity = service_info
                    exposed.append({
                        "port":        port_num,
                        "service":     service,
                        "sensitivity": sensitivity,
                        "source_count": row["sc"] or 1,
                    })
            except (ValueError, TypeError):
                pass

        return sorted(exposed, key=lambda x: (
            0 if x["sensitivity"] == "critical" else 1
        ))

    def _find_cves(
        self, conn, target_org: str
    ) -> List[Dict]:
        """Find CVEs discovered via Shodan."""
        results = conn.run("""
            MATCH (o:Organization {domain: $domain})-[:EXPOSES]->(e:Entity)
            WHERE e.entity_type = 'CVE'
            RETURN e.name AS cve, e.source_count AS sc
            ORDER BY sc DESC
        """, {"domain": target_org})

        return [
            {"cve": r["cve"], "source_count": r["sc"] or 1}
            for r in results
        ]

    def _find_secrets(
        self, conn, target_org: str
    ) -> List[Dict]:
        """Find secret pattern matches from GitHub deep scan."""
        results = conn.run("""
            MATCH (s:Signal {target_org: $domain})
            WHERE s.sensitivity IN ['critical', 'high']
            AND s.source_type = 'github'
            AND s.raw_content CONTAINS 'Secret found'
            RETURN s.raw_content      AS content,
                   s.sensitivity      AS sensitivity,
                   s.sensitivity_reason AS reason
            LIMIT 20
        """, {"domain": target_org})

        return [
            {
                "content":     r["content"][:150],
                "sensitivity": r["sensitivity"],
                "reason":      r["reason"],
            }
            for r in results
        ]

    # ── Helper queries ────────────────────────────────────────────────────────

    def _get_ips_for_host(self, conn, hostname: str) -> List[str]:
        """Get IP addresses associated with a hostname."""
        results = conn.run("""
            MATCH (h:Entity {name: $hostname, entity_type: 'HOSTNAME'})
            MATCH (ip:Entity {entity_type: 'IP_ADDRESS'})
            WHERE EXISTS {
                MATCH (s:Signal)-[:CONTAINS_ENTITY]->(h)
                MATCH (s)-[:CONTAINS_ENTITY]->(ip)
            }
            RETURN DISTINCT ip.name AS ip
            LIMIT 5
        """, {"hostname": hostname})
        return [r["ip"] for r in results]

    def _get_ports_for_ip(self, conn, ip: str) -> List[int]:
        """Get open ports associated with an IP address."""
        results = conn.run("""
            MATCH (ip:Entity {name: $ip, entity_type: 'IP_ADDRESS'})
            MATCH (port:Entity {entity_type: 'OPEN_PORT'})
            WHERE EXISTS {
                MATCH (s:Signal)-[:CONTAINS_ENTITY]->(ip)
                MATCH (s)-[:CONTAINS_ENTITY]->(port)
            }
            RETURN DISTINCT port.name AS port
            LIMIT 10
        """, {"ip": ip})
        ports = []
        for r in results:
            try:
                ports.append(int(r["port"]))
            except (ValueError, TypeError):
                pass
        return ports

    def _assess_host_sensitivity(
        self, hostname: str, open_ports: List[int]
    ):
        """Score a hostname's sensitivity based on name and ports."""
        reasons = []
        sensitivity = "medium"
        h = hostname.lower()

        # Check prefix patterns
        for level, prefixes in SENSITIVE_PREFIXES.items():
            for prefix in prefixes:
                if h.startswith(f"{prefix}.") or f".{prefix}." in h:
                    sensitivity = level
                    reasons.append(
                        f"Sensitive subdomain pattern: '{prefix}'"
                    )
                    break

        # Check open ports
        for port in open_ports:
            if port in SENSITIVE_PORTS:
                service, port_sensitivity = SENSITIVE_PORTS[port]
                reasons.append(
                    f"Sensitive service on port {port}: {service}"
                )
                if port_sensitivity == "critical":
                    sensitivity = "critical"
                elif port_sensitivity == "high" and sensitivity != "critical":
                    sensitivity = "high"

        if not reasons:
            reasons.append("Externally visible hostname")

        return sensitivity, reasons

    # ── Risk scoring ──────────────────────────────────────────────────────────

    def _calculate_risk_score(self, surface: AttackSurface) -> int:
        """
        Calculate an overall risk score 0-100 based on
        breadth and depth of exposure.
        """
        score = 0

        # Sensitive hosts
        for host in surface.sensitive_hosts:
            if host.sensitivity == "critical":
                score += 15
            elif host.sensitivity == "high":
                score += 8
            else:
                score += 3

        # Confirmed hosts (multi-source)
        score += min(20, len(surface.confirmed_hosts) * 3)

        # CVEs found
        score += min(20, len(surface.cves_found) * 5)

        # Secrets found
        score += min(20, len(surface.secrets_found) * 5)

        # Exposed sensitive ports
        for port_info in surface.exposed_ports:
            if port_info["sensitivity"] == "critical":
                score += 10
            elif port_info["sensitivity"] == "high":
                score += 5

        # People identified (spearphishing surface)
        score += min(10, len(surface.people_profiles) * 2)

        return min(100, score)

    def _build_summary_stats(
        self, surface: AttackSurface
    ) -> Dict[str, int]:
        return {
            "confirmed_hosts":   len(surface.confirmed_hosts),
            "sensitive_hosts":   len(surface.sensitive_hosts),
            "technologies":      len(surface.technology_stack),
            "people":            len(surface.people_profiles),
            "saas_services":     len(surface.saas_services),
            "exposed_ports":     len(surface.exposed_ports),
            "cves":              len(surface.cves_found),
            "secrets":           len(surface.secrets_found),
            "risk_score":        surface.risk_score,
        }

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_surface(self, surface: AttackSurface):
        print("\n" + "=" * 60)
        print(f"  Correlation Engine — Attack Surface Report")
        print(f"  Target: {surface.target_org}")
        print(f"  Risk Score: {surface.risk_score}/100")
        print("=" * 60)

        if surface.sensitive_hosts:
            print(f"\n🎯 Sensitive Hosts ({len(surface.sensitive_hosts)}):")
            for h in surface.sensitive_hosts[:10]:
                ips = f" → {', '.join(h.ip_addresses)}" \
                      if h.ip_addresses else ""
                ports = f" [ports: {h.open_ports}]" \
                        if h.open_ports else ""
                print(f"  [{h.sensitivity.upper()}] {h.hostname}{ips}{ports}")
                for r in h.risk_reasons[:2]:
                    print(f"    • {r}")

        if surface.confirmed_hosts:
            print(
                f"\n✅ Multi-Source Confirmed Hosts "
                f"({len(surface.confirmed_hosts)}):"
            )
            for h in surface.confirmed_hosts[:5]:
                print(
                    f"  {h.hostname} "
                    f"({h.source_count} sources: "
                    f"{', '.join(h.sources)})"
                )

        if surface.technology_stack:
            techs = [t["name"] for t in surface.technology_stack[:10]]
            print(f"\n🛠️  Technology Stack: {', '.join(techs)}")

        if surface.cloud_profile.get("providers"):
            print(
                f"\n☁️  Cloud: "
                f"{', '.join(surface.cloud_profile['providers'])}"
            )
            if surface.cloud_profile.get("regions"):
                print(
                    f"   Regions: "
                    f"{', '.join(surface.cloud_profile['regions'])}"
                )
            if surface.cloud_profile.get("services"):
                svcs = [
                    s["name"]
                    for s in surface.cloud_profile["services"][:8]
                ]
                print(f"   Services: {', '.join(svcs)}")

        if surface.people_profiles:
            print(
                f"\n👤 People Identified "
                f"({len(surface.people_profiles)}):"
            )
            for p in surface.people_profiles[:5]:
                parts = [p.name]
                if p.email:
                    parts.append(p.email)
                if p.github_user:
                    parts.append(f"@{p.github_user}")
                print(f"  {' | '.join(parts)}")

        if surface.cves_found:
            print(f"\n⚠️  CVEs: {', '.join(c['cve'] for c in surface.cves_found[:5])}")

        if surface.secrets_found:
            print(f"\n🔴 Secrets: {len(surface.secrets_found)} potential secret(s) found in GitHub")

        if surface.exposed_ports:
            print(f"\n🔓 Exposed Services:")
            for p in surface.exposed_ports[:5]:
                print(
                    f"  [{p['sensitivity'].upper()}] "
                    f"Port {p['port']} — {p['service']}"
                )

        print("=" * 60)