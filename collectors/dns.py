import httpx
import asyncio
from loguru import logger
from typing import List
from datetime import datetime
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from graph.schema import Signal, SourceType, Entity, SensitivityLevel


# DNS record types we care about
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# Subdomains to brute-force passively
COMMON_SUBDOMAINS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "app", "portal",
    "admin", "ssh", "cdn", "ftp", "mx", "email", "git", "gitlab",
    "jenkins", "jira", "confluence", "s3", "cloud", "beta", "test",
    "prod", "production", "internal", "corp", "office", "dashboard"
]


class DNSCollector:
    """
    Collects DNS records and enumerates subdomains for a target organization.
    Uses Google's public DNS-over-HTTPS API — no special credentials needed.
    """

    def __init__(self, target_org: str):
        self.target_org = target_org
        self.base_url = "https://dns.google/resolve"
        self.signals: List[Signal] = []

    async def collect(self) -> List[Signal]:
        """Main entry point. Runs all DNS collection tasks."""
        logger.info(f"🔍 Starting DNS collection for: {self.target_org}")

        async with httpx.AsyncClient(timeout=10.0) as client:
            # 1. Collect standard DNS records for root domain
            await self._collect_dns_records(client, self.target_org)

            # 2. Enumerate common subdomains
            await self._enumerate_subdomains(client)

        logger.success(f"✅ DNS collection complete — {len(self.signals)} signals found")
        return self.signals

    async def _collect_dns_records(self, client: httpx.AsyncClient, domain: str):
        """Query all DNS record types for a given domain."""
        for record_type in DNS_RECORD_TYPES:
            try:
                response = await client.get(self.base_url, params={
                    "name": domain,
                    "type": record_type
                })
                data = response.json()

                if data.get("Status") == 0 and "Answer" in data:
                    for answer in data["Answer"]:
                        signal = self._build_signal(
                            domain=domain,
                            record_type=record_type,
                            value=answer.get("data", ""),
                            ttl=answer.get("TTL", 0)
                        )
                        self.signals.append(signal)
                        logger.debug(f"  [{record_type}] {domain} → {answer.get('data', '')}")

            except Exception as e:
                logger.warning(f"  Failed to query {record_type} for {domain}: {e}")

    async def _enumerate_subdomains(self, client: httpx.AsyncClient):
        """Check common subdomains for existence."""
        logger.info(f"  Enumerating subdomains for {self.target_org}...")

        tasks = [
            self._check_subdomain(client, f"{sub}.{self.target_org}")
            for sub in COMMON_SUBDOMAINS
        ]
        await asyncio.gather(*tasks)

    async def _check_subdomain(self, client: httpx.AsyncClient, subdomain: str):
        """Check if a subdomain resolves."""
        try:
            response = await client.get(self.base_url, params={
                "name": subdomain,
                "type": "A"
            })
            data = response.json()

            if data.get("Status") == 0 and "Answer" in data:
                for answer in data["Answer"]:
                    signal = self._build_signal(
                        domain=subdomain,
                        record_type="A",
                        value=answer.get("data", ""),
                        ttl=answer.get("TTL", 0),
                        is_subdomain=True
                    )
                    self.signals.append(signal)
                    logger.info(f"  🌐 Subdomain found: {subdomain} → {answer.get('data', '')}")

        except Exception as e:
            logger.warning(f"  Failed subdomain check for {subdomain}: {e}")

    def _build_signal(
        self,
        domain: str,
        record_type: str,
        value: str,
        ttl: int,
        is_subdomain: bool = False
    ) -> Signal:
        """Packages a DNS record into a Signal object."""

        # Determine sensitivity based on what we found
        sensitivity, reason = self._assess_sensitivity(
            domain, record_type, value, is_subdomain
        )

        # Extract entities from this record
        entities = self._extract_entities(domain, record_type, value)

        raw_content = f"DNS {record_type} record: {domain} → {value} (TTL: {ttl})"

        return Signal(
            target_org=self.target_org,
            source_type=SourceType.DNS,
            source_url=f"https://dns.google/resolve?name={domain}&type={record_type}",
            raw_content=raw_content,
            entities=entities,
            sensitivity=sensitivity,
            sensitivity_reason=reason,
            metadata={
                "domain":       domain,
                "record_type":  record_type,
                "value":        value,
                "ttl":          ttl,
                "is_subdomain": is_subdomain
            }
        )

    def _assess_sensitivity(
        self,
        domain: str,
        record_type: str,
        value: str,
        is_subdomain: bool
    ):
        """
        Rule-based sensitivity scoring for DNS records.
        Later this will be replaced by the ML classifier.
        """
        domain_lower = domain.lower()
        value_lower = value.lower()

        # Critical — internal infrastructure accidentally exposed
        critical_keywords = ["internal", "corp", "prod", "production", "admin", "ssh"]
        if any(k in domain_lower for k in critical_keywords):
            return SensitivityLevel.CRITICAL, f"Sensitive keyword '{domain_lower}' in subdomain"

        # High — dev/staging environments exposed
        high_keywords = ["staging", "dev", "test", "beta", "jenkins", "gitlab", "jira"]
        if any(k in domain_lower for k in high_keywords):
            return SensitivityLevel.HIGH, f"Development/staging environment exposed: {domain}"

        # High — TXT records often leak API keys, verification tokens, SPF configs
        if record_type == "TXT":
            value_lower = value.lower()

            # Verification tokens — always public, always low sensitivity
            verification_patterns = [
                "v=spf1", "v=dmarc1", "v=dkim1",
                "google-site-verification",
                "ms=", "docusign", "atlassian-domain-verification",
                "facebook-domain-verification", "apple-domain-verification",
                "amazonses:", "zoom-domain-verification",
                "keybase-site-verification", "stripe-verification"
            ]
            if any(p in value_lower for p in verification_patterns):
                return (
                    SensitivityLevel.LOW,
                    "Standard domain verification token — intentionally public"
                )

            # TXT records with actual sensitive content
            sensitive_txt_patterns = [
                "api_key", "secret", "token", "password",
                "internal", "private", "credential"
            ]
            if any(p in value_lower for p in sensitive_txt_patterns):
                return (
                    SensitivityLevel.CRITICAL,
                    f"TXT record contains potentially sensitive data"
                )

            # Generic TXT — medium, worth noting but not alarming
            return SensitivityLevel.MEDIUM, "Non-standard TXT record — review manually"

        # Medium — subdomains reveal infrastructure shape
        if is_subdomain:
            return SensitivityLevel.MEDIUM, f"Subdomain enumerated: {domain}"

        # Low — standard DNS records
        return SensitivityLevel.LOW, f"Standard {record_type} record"

    def _extract_entities(
        self,
        domain: str,
        record_type: str,
        value: str
    ) -> List[Entity]:
        """Extract named entities from a DNS record."""
        entities = []

        # The domain itself is always a HOSTNAME entity
        entities.append(Entity(
            name=domain,
            entity_type="HOSTNAME",
            confidence=1.0,
            context=f"DNS {record_type} record for {domain}"
        ))

        # IP addresses
        if record_type in ["A", "AAAA"]:
            entities.append(Entity(
                name=value,
                entity_type="IP_ADDRESS",
                confidence=1.0,
                context=f"{domain} resolves to {value}"
            ))

        # Mail servers
        if record_type == "MX":
            entities.append(Entity(
                name=value,
                entity_type="MAIL_SERVER",
                confidence=1.0,
                context=f"Mail server for {domain}: {value}"
            ))

        # Nameservers — reveal hosting provider
        if record_type == "NS":
            entities.append(Entity(
                name=value,
                entity_type="NAMESERVER",
                confidence=1.0,
                context=f"Nameserver for {domain}: {value}"
            ))

        # TXT records — look for cloud provider verification strings
        if record_type == "TXT":
            providers = {
                "google": "GOOGLE_VERIFICATION",
                "amazonses": "AWS_SES",
                "sendgrid": "SENDGRID",
                "mailchimp": "MAILCHIMP",
                "stripe": "STRIPE_VERIFICATION",
                "atlassian": "ATLASSIAN",
                "github": "GITHUB_VERIFICATION"
            }
            for keyword, entity_type in providers.items():
                if keyword in value.lower():
                    entities.append(Entity(
                        name=keyword,
                        entity_type=entity_type,
                        confidence=0.95,
                        context=f"TXT record reveals {keyword} usage: {value}"
                    ))

        return entities