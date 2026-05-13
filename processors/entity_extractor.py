import re
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from graph.schema import Signal, Entity, SourceType

# ── Noise filter ─────────────────────────────────────────────────────────────
# Entities whose names match these exactly are meaningless noise
ENTITY_NOISE = {
    # spaCy misreads from structured text
    "ttl", "dns", "dns txt", "dns a", "dns mx", "dns ns",
    "mx", "ns", "txt", "a", "aaaa", "cname", "soa",
    "us", "tx", "st", "ca", "ny", "uk", "gb",
    "valid", "true", "false", "none", "null",
    "http", "https", "ftp", "ssh",
    "record", "records", "type", "data",
    "issuer", "subject", "serial",
    # Certificate noise
    "let's encrypt", "lets encrypt",
    "c=us", "o=", "cn=",
    # Generic words spaCy wrongly extracts
    "inc", "llc", "ltd", "corp", "co",
    "monday", "tuesday", "wednesday", "thursday",
    "friday", "saturday", "sunday",
    "january", "february", "march", "april",
    "may", "june", "july", "august",
    "september", "october", "november", "december",
}

# Minimum name length — anything shorter is noise
MIN_ENTITY_LENGTH = 3

# ── Domain-specific extractors ────────────────────────────────────────────────
# These extract entities directly from structured metadata fields
# rather than running NLP on raw text strings

HOSTNAME_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
    r'+[a-zA-Z]{2,}$'
)

IP_PATTERN = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)

EMAIL_PATTERN = re.compile(
    r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
)

CVE_PATTERN = re.compile(
    r'CVE-\d{4}-\d{4,7}',
    re.IGNORECASE
)

AWS_KEY_PATTERN = re.compile(r'AKIA[0-9A-Z]{16}')


def _is_noise(name: str) -> bool:
    """Return True if this entity name is meaningless noise."""
    n = name.strip().lower()
    if n in ENTITY_NOISE:
        return True
    if len(n) < MIN_ENTITY_LENGTH:
        return True
    # Pure numbers are noise
    if n.isdigit():
        return True
    # Looks like a certificate field fragment
    if n.startswith(('c=', 'o=', 'cn=', 'ou=', 'st=')):
        return True
    # Timestamps
    if re.match(r'^\d{4}-\d{2}-\d{2}', n):
        return True
    return False


class EntityExtractor:
    """
    Extracts named entities from signals.

    Strategy by source type:
    - DNS, Certificate, Shodan, WHOIS → extract from structured metadata
    - GitHub, Web, Job Posting → extract from raw content with targeted regex
    - Never uses spaCy on structured OSINT data (produces too much noise)
    """

    def extract(self, signal: Signal) -> Signal:
        """Extract entities from a single signal."""
        # Route to the right extractor based on source type
        new_entities = []

        if signal.source_type == SourceType.DNS:
            new_entities = self._extract_from_dns(signal)
        elif signal.source_type == SourceType.CERTIFICATE:
            new_entities = self._extract_from_cert(signal)
        elif signal.source_type == SourceType.SHODAN:
            new_entities = self._extract_from_shodan(signal)
        elif signal.source_type == SourceType.GITHUB:
            new_entities = self._extract_from_github(signal)
        elif signal.source_type == SourceType.WEB:
            new_entities = self._extract_from_web(signal)
        else:
            new_entities = self._extract_generic(signal)

        # Filter noise and deduplicate
        existing_names = {e.name.lower() for e in signal.entities}
        for entity in new_entities:
            if _is_noise(entity.name):
                continue
            if entity.name.lower() in existing_names:
                continue
            signal.entities.append(entity)
            existing_names.add(entity.name.lower())

        return signal

    def extract_batch(self, signals: List[Signal]) -> List[Signal]:
        """Extract entities from a list of signals."""
        logger.info(f"  Extracting entities from {len(signals)} signals...")
        for signal in signals:
            self.extract(signal)
        logger.success(f"  ✅ Entity extraction complete")
        return signals

    # ── Source-specific extractors ────────────────────────────────────────

    def _extract_from_dns(self, signal: Signal) -> List[Entity]:
        """Extract entities from DNS signal metadata."""
        entities = []
        m = signal.metadata

        domain      = m.get("domain", "")
        record_type = m.get("record_type", "")
        value       = m.get("value", "")

        # Hostname from domain field
        if domain and HOSTNAME_PATTERN.match(domain):
            entities.append(Entity(
                name=domain,
                entity_type="HOSTNAME",
                confidence=1.0,
                context=f"DNS {record_type} record",
                sources=[signal.source_type]
            ))

        # IP address
        if record_type in ("A", "AAAA") and value:
            if IP_PATTERN.match(value.strip()):
                entities.append(Entity(
                    name=value.strip(),
                    entity_type="IP_ADDRESS",
                    confidence=1.0,
                    context=f"{domain} resolves to {value}",
                    sources=[signal.source_type]
                ))

        # Mail server
        if record_type == "MX" and value:
            host = value.split()[-1].rstrip(".") if value else ""
            if host and HOSTNAME_PATTERN.match(host):
                entities.append(Entity(
                    name=host,
                    entity_type="MAIL_SERVER",
                    confidence=1.0,
                    context=f"MX record for {domain}",
                    sources=[signal.source_type]
                ))

        # Nameserver → reveals DNS provider
        if record_type == "NS" and value:
            ns = value.rstrip(".")
            if ns and HOSTNAME_PATTERN.match(ns):
                entities.append(Entity(
                    name=ns,
                    entity_type="NAMESERVER",
                    confidence=1.0,
                    context=f"NS record for {domain}",
                    sources=[signal.source_type]
                ))

        # TXT record — extract specific verifications
        if record_type == "TXT" and value:
            entities.extend(
                self._extract_from_txt_record(value, domain, signal.source_type)
            )

        return entities

    def _extract_from_txt_record(
        self, value: str, domain: str, source_type: str
    ) -> List[Entity]:
        """Extract meaningful entities from DNS TXT records."""
        entities = []
        v = value.lower()

        # SaaS verification tokens → reveal which services are used
        saas_map = {
            "google-site-verification":     "GOOGLE_WORKSPACE",
            "v=spf1":                       "EMAIL_SPF",
            "v=dmarc1":                     "EMAIL_DMARC",
            "amazonses":                    "AWS_SES",
            "sendgrid":                     "SENDGRID",
            "mailchimp":                    "MAILCHIMP",
            "atlassian-domain-verification": "ATLASSIAN",
            "stripe-verification":          "STRIPE",
            "github-challenge":             "GITHUB",
            "facebook-domain-verification": "FACEBOOK",
            "zoom-domain-verification":     "ZOOM",
            "docusign":                     "DOCUSIGN",
        }
        for keyword, service in saas_map.items():
            if keyword in v:
                entities.append(Entity(
                    name=service,
                    entity_type="SAAS_SERVICE",
                    confidence=0.95,
                    context=f"TXT record reveals {service} usage",
                    sources=[source_type]
                ))
        return entities

    def _extract_from_cert(self, signal: Signal) -> List[Entity]:
        """Extract entities from certificate signal metadata."""
        entities = []
        m = signal.metadata

        domain = m.get("domain", "")
        issuer = m.get("issuer", "")

        # Domain from cert
        if domain:
            # Handle wildcard certs
            clean = domain.lstrip("*.")
            if clean and HOSTNAME_PATTERN.match(clean):
                entities.append(Entity(
                    name=domain,
                    entity_type="HOSTNAME",
                    confidence=1.0,
                    context=f"Certificate issued for {domain}",
                    sources=[signal.source_type]
                ))

        # Certificate authority
        ca_map = {
            "let's encrypt": "LETS_ENCRYPT",
            "digicert":      "DIGICERT",
            "cloudflare":    "CLOUDFLARE",
            "amazon":        "AWS_ACM",
            "google":        "GOOGLE_CA",
            "sectigo":       "SECTIGO",
            "globalsign":    "GLOBALSIGN",
            "cpanel":        "CPANEL",
            "comodo":        "COMODO",
        }
        issuer_lower = issuer.lower()
        for ca_name, entity_type in ca_map.items():
            if ca_name in issuer_lower:
                entities.append(Entity(
                    name=ca_name.title(),
                    entity_type="CERTIFICATE_AUTHORITY",
                    confidence=0.95,
                    context=f"Cert for {domain} issued by {ca_name}",
                    sources=[signal.source_type]
                ))
                break

        # Infrastructure hints from subdomain name
        infra_hints = {
            "jenkins":    "JENKINS",
            "gitlab":     "GITLAB",
            "grafana":    "GRAFANA",
            "kibana":     "KIBANA",
            "vault":      "HASHICORP_VAULT",
            "consul":     "HASHICORP_CONSUL",
            "prometheus": "PROMETHEUS",
            "airflow":    "AIRFLOW",
            "kafka":      "KAFKA",
            "elastic":    "ELASTICSEARCH",
            "k8s":        "KUBERNETES",
            "kube":       "KUBERNETES",
            "rancher":    "RANCHER",
            "harbor":     "HARBOR",
        }
        domain_lower = domain.lower()
        for hint, tech in infra_hints.items():
            if hint in domain_lower:
                entities.append(Entity(
                    name=tech,
                    entity_type="TECHNOLOGY",
                    confidence=0.9,
                    context=f"Subdomain {domain} suggests {tech}",
                    sources=[signal.source_type]
                ))

        return entities

    def _extract_from_shodan(self, signal: Signal) -> List[Entity]:
        """Extract entities from Shodan signal metadata."""
        entities = []
        m = signal.metadata

        ip       = m.get("ip", "")
        port     = m.get("port", "")
        product  = m.get("product", "")
        version  = m.get("version", "")
        org      = m.get("org", "")
        hostnames= m.get("hostnames", [])
        country  = m.get("country", "")
        cve_count= m.get("cve_count", 0)

        if ip and IP_PATTERN.match(str(ip)):
            entities.append(Entity(
                name=ip,
                entity_type="IP_ADDRESS",
                confidence=1.0,
                context=f"IP found via Shodan",
                sources=[signal.source_type]
            ))

        if product:
            tech_name = f"{product} {version}".strip()
            entities.append(Entity(
                name=tech_name,
                entity_type="EXPOSED_SERVICE",
                confidence=1.0,
                context=f"{tech_name} on port {port}",
                sources=[signal.source_type]
            ))

        for hostname in (hostnames or [])[:5]:
            if hostname and HOSTNAME_PATTERN.match(hostname):
                entities.append(Entity(
                    name=hostname,
                    entity_type="HOSTNAME",
                    confidence=1.0,
                    context=f"Hostname linked to {ip} via Shodan",
                    sources=[signal.source_type]
                ))

        if org and not _is_noise(org):
            entities.append(Entity(
                name=org,
                entity_type="ORGANIZATION",
                confidence=0.9,
                context=f"Shodan org for {ip}",
                sources=[signal.source_type]
            ))

        if port:
            entities.append(Entity(
                name=str(port),
                entity_type="OPEN_PORT",
                confidence=1.0,
                context=f"Port {port} open on {ip}",
                sources=[signal.source_type]
            ))

        return entities

    def _extract_from_github(self, signal: Signal) -> List[Entity]:
        """
        GitHub signals already have well-structured entities
        from the deep scanner. Just filter noise.
        """
        # GitHub collector already extracts good entities
        # Just return empty — filtering happens in extract()
        return []

    def _extract_from_web(self, signal: Signal) -> List[Entity]:
        """Extract entities from web/WHOIS/Wayback signals."""
        entities = []
        m = signal.metadata
        collector = m.get("collector", "")

        if collector == "whois":
            # WHOIS — extract from structured fields
            registrar = m.get("registrar", "")
            org       = m.get("org", "")
            email     = m.get("email", "")
            ns_list   = m.get("name_servers", [])

            if registrar and not _is_noise(registrar):
                entities.append(Entity(
                    name=registrar,
                    entity_type="REGISTRAR",
                    confidence=1.0,
                    context="WHOIS registrar",
                    sources=[signal.source_type]
                ))

            if org and not _is_noise(org):
                entities.append(Entity(
                    name=org,
                    entity_type="ORGANIZATION",
                    confidence=0.95,
                    context="WHOIS registrant org",
                    sources=[signal.source_type]
                ))

            if email and EMAIL_PATTERN.match(email):
                entities.append(Entity(
                    name=email,
                    entity_type="EMAIL_ADDRESS",
                    confidence=0.95,
                    context="WHOIS contact email",
                    sources=[signal.source_type]
                ))

            for ns in (ns_list or []):
                if ns and HOSTNAME_PATTERN.match(ns):
                    entities.append(Entity(
                        name=ns,
                        entity_type="NAMESERVER",
                        confidence=1.0,
                        context="WHOIS nameserver",
                        sources=[signal.source_type]
                    ))

        elif collector == "wayback":
            # Wayback — extract hostname from URL
            original_url = m.get("original_url", "")
            if original_url:
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(original_url).netloc
                    if hostname and HOSTNAME_PATTERN.match(hostname):
                        entities.append(Entity(
                            name=hostname,
                            entity_type="HOSTNAME",
                            confidence=1.0,
                            context=f"Historical URL: {original_url[:80]}",
                            sources=[signal.source_type]
                        ))
                except Exception:
                    pass

        else:
            # Google dork or other web signal
            url = m.get("url", "")
            if url:
                try:
                    from urllib.parse import urlparse
                    hostname = urlparse(url).netloc
                    if hostname and HOSTNAME_PATTERN.match(hostname):
                        entities.append(Entity(
                            name=hostname,
                            entity_type="HOSTNAME",
                            confidence=1.0,
                            context=f"Google dork result: {url[:80]}",
                            sources=[signal.source_type]
                        ))
                except Exception:
                    pass

        return entities

    def _extract_generic(self, signal: Signal) -> List[Entity]:
        """
        Fallback extractor for unknown source types.
        Uses targeted regex on raw content only.
        """
        entities = []
        text = signal.raw_content

        # Extract hostnames
        hostname_re = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
            r'+[a-zA-Z]{2,}\b'
        )
        for match in hostname_re.finditer(text):
            h = match.group(0)
            if not _is_noise(h) and HOSTNAME_PATTERN.match(h):
                entities.append(Entity(
                    name=h,
                    entity_type="HOSTNAME",
                    confidence=0.7,
                    context=text[max(0, match.start()-30):match.end()+30],
                    sources=[signal.source_type]
                ))

        # Extract IPs
        ip_re = re.compile(r'\b(\d{1,3}\.){3}\d{1,3}\b')
        for match in ip_re.finditer(text):
            ip = match.group(0)
            if IP_PATTERN.match(ip):
                entities.append(Entity(
                    name=ip,
                    entity_type="IP_ADDRESS",
                    confidence=0.9,
                    context=text[max(0, match.start()-20):match.end()+20],
                    sources=[signal.source_type]
                ))

        # Extract CVEs
        for match in CVE_PATTERN.finditer(text):
            entities.append(Entity(
                name=match.group(0).upper(),
                entity_type="CVE",
                confidence=1.0,
                context=text[max(0, match.start()-20):match.end()+20],
                sources=[signal.source_type]
            ))

        return entities