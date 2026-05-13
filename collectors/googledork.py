import httpx
import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List, Dict, Tuple
from dotenv import load_dotenv
from graph.schema import Signal, SourceType, Entity, SensitivityLevel

load_dotenv()


# ── Dork definitions ─────────────────────────────────────────────────────────
# Each dork: (query_suffix, sensitivity, reason, category)
DORKS: List[Tuple[str, str, str, str]] = [

    # ── CRITICAL: Exposed credentials & secrets ──────────────────────────────
    ('filetype:env "DB_PASSWORD"',
     "critical", "Exposed .env file with database credentials", "secrets"),
    ('filetype:env "SECRET_KEY"',
     "critical", "Exposed .env file with secret key", "secrets"),
    ('filetype:env "API_KEY"',
     "critical", "Exposed .env file with API key", "secrets"),
    ('filetype:sql "INSERT INTO" "password"',
     "critical", "SQL dump containing password data exposed", "secrets"),
    ('"-----BEGIN RSA PRIVATE KEY-----"',
     "critical", "RSA private key exposed publicly", "secrets"),
    ('"-----BEGIN PRIVATE KEY-----"',
     "critical", "Private key exposed publicly", "secrets"),
    ('filetype:pem "PRIVATE KEY"',
     "critical", "PEM private key file exposed", "secrets"),
    ('filetype:ppk "PRIVATE KEY"',
     "critical", "PuTTY private key exposed", "secrets"),
    ('filetype:cfg "password"',
     "critical", "Config file with password exposed", "secrets"),
    ('filetype:ini "password"',
     "critical", "INI config with password exposed", "secrets"),
    ('"aws_access_key_id"',
     "critical", "AWS access key ID exposed", "secrets"),
    ('"aws_secret_access_key"',
     "critical", "AWS secret access key exposed", "secrets"),

    # ── CRITICAL: Exposed config & backup files ───────────────────────────────
    ('filetype:bak',
     "critical", "Backup file exposed publicly", "exposed_files"),
    ('filetype:sql',
     "critical", "SQL file exposed publicly", "exposed_files"),
    ('filetype:dump',
     "critical", "Database dump file exposed", "exposed_files"),
    ('"wp-config.php"',
     "critical", "WordPress config file exposed", "exposed_files"),
    ('filetype:log "error"',
     "critical", "Error log file exposed publicly", "exposed_files"),
    ('"config.php" filetype:php',
     "critical", "PHP config file exposed", "exposed_files"),
    ('inurl:".git" "index of"',
     "critical", "Git repository directory exposed", "exposed_files"),
    ('filetype:htpasswd',
     "critical", "Password file .htpasswd exposed", "exposed_files"),

    # ── HIGH: Admin panels & login pages ─────────────────────────────────────
    ('inurl:admin intitle:login',
     "high", "Admin login panel exposed", "admin_panels"),
    ('inurl:administrator intitle:login',
     "high", "Administrator login panel exposed", "admin_panels"),
    ('inurl:wp-admin',
     "high", "WordPress admin panel exposed", "admin_panels"),
    ('inurl:phpmyadmin',
     "high", "phpMyAdmin panel exposed", "admin_panels"),
    ('inurl:adminer',
     "high", "Adminer database panel exposed", "admin_panels"),
    ('intitle:"Jenkins" inurl:jenkins',
     "high", "Jenkins CI/CD panel exposed", "admin_panels"),
    ('intitle:"Grafana" inurl:grafana',
     "high", "Grafana monitoring panel exposed", "admin_panels"),
    ('intitle:"Kibana" inurl:kibana',
     "high", "Kibana log panel exposed", "admin_panels"),
    ('intitle:"GitLab" inurl:gitlab',
     "high", "GitLab instance exposed", "admin_panels"),
    ('inurl:dashboard intitle:login',
     "high", "Dashboard login page exposed", "admin_panels"),
    ('inurl:portal intitle:login',
     "high", "Portal login page exposed", "admin_panels"),
    ('intitle:"Swagger UI"',
     "high", "Swagger API documentation exposed", "admin_panels"),
    ('intitle:"RabbitMQ Management"',
     "high", "RabbitMQ management panel exposed", "admin_panels"),
    ('intitle:"Traefik" inurl:dashboard',
     "high", "Traefik reverse proxy dashboard exposed", "admin_panels"),

    # ── HIGH: Development & staging environments ──────────────────────────────
    ('inurl:staging',
     "high", "Staging environment exposed", "environments"),
    ('inurl:dev.',
     "high", "Development environment exposed", "environments"),
    ('inurl:test.',
     "high", "Test environment exposed", "environments"),
    ('inurl:beta.',
     "high", "Beta environment exposed", "environments"),
    ('inurl:sandbox',
     "high", "Sandbox environment exposed", "environments"),
    ('inurl:preprod',
     "high", "Pre-production environment exposed", "environments"),
    ('inurl:uat.',
     "high", "UAT environment exposed", "environments"),

    # ── HIGH: API & infrastructure exposure ───────────────────────────────────
    ('inurl:api/v1',
     "high", "API v1 endpoints exposed", "api_exposure"),
    ('inurl:api/v2',
     "high", "API v2 endpoints exposed", "api_exposure"),
    ('inurl:/api/ intitle:"index of"',
     "high", "API directory listing exposed", "api_exposure"),
    ('filetype:json "api_key"',
     "high", "JSON file with API key exposed", "api_exposure"),
    ('filetype:yaml "password"',
     "high", "YAML config with password exposed", "api_exposure"),
    ('filetype:json "password"',
     "high", "JSON file with password exposed", "api_exposure"),
    ('inurl:swagger.json',
     "high", "Swagger JSON spec exposed", "api_exposure"),
    ('inurl:openapi.json',
     "high", "OpenAPI spec exposed", "api_exposure"),

    # ── HIGH: Error pages & stack traces ──────────────────────────────────────
    ('intitle:"Error" "stack trace"',
     "high", "Stack trace error page exposed", "error_pages"),
    ('"PHP Parse error" OR "PHP Warning" OR "PHP Fatal"',
     "high", "PHP error messages exposed", "error_pages"),
    ('"SQL syntax" "mysql_fetch"',
     "high", "SQL error messages leaking query structure", "error_pages"),
    ('"Warning: mysql_connect"',
     "high", "MySQL connection error exposed", "error_pages"),
    ('intitle:"Apache Tomcat" "Error Report"',
     "high", "Tomcat error report exposed", "error_pages"),
    ('"ORA-" "Oracle" error',
     "high", "Oracle database error exposed", "error_pages"),

    # ── MEDIUM: Technology fingerprinting ─────────────────────────────────────
    ('intitle:"index of" "server at"',
     "medium", "Apache directory listing exposed", "tech_fingerprint"),
    ('"X-Powered-By: PHP"',
     "medium", "PHP version exposed in headers", "tech_fingerprint"),
    ('inurl:robots.txt "disallow"',
     "medium", "robots.txt reveals hidden paths", "tech_fingerprint"),
    ('filetype:xml sitemap',
     "medium", "Sitemap reveals site structure", "tech_fingerprint"),
    ('intitle:"index of /" "parent directory"',
     "medium", "Directory listing exposed", "tech_fingerprint"),
    ('"Powered by WordPress"',
     "medium", "WordPress CMS identified", "tech_fingerprint"),
    ('"Powered by Drupal"',
     "medium", "Drupal CMS identified", "tech_fingerprint"),
    ('intitle:"Welcome to nginx"',
     "medium", "Nginx default page exposed", "tech_fingerprint"),

    # ── MEDIUM: Document & file exposure ──────────────────────────────────────
    ('filetype:pdf "confidential"',
     "medium", "Confidential PDF document exposed", "documents"),
    ('filetype:xlsx "password"',
     "medium", "Excel file with password data exposed", "documents"),
    ('filetype:docx "internal use only"',
     "medium", "Internal Word document exposed", "documents"),
    ('filetype:pptx "confidential"',
     "medium", "Confidential presentation exposed", "documents"),
    ('filetype:csv "email" "password"',
     "medium", "CSV with credentials exposed", "documents"),

    # ── MEDIUM: Cloud & infrastructure hints ──────────────────────────────────
    ('"s3.amazonaws.com"',
     "medium", "S3 bucket reference found", "cloud"),
    ('"storage.googleapis.com"',
     "medium", "GCS bucket reference found", "cloud"),
    ('"blob.core.windows.net"',
     "medium", "Azure blob storage reference found", "cloud"),
    ('inurl:".s3.amazonaws.com"',
     "medium", "S3 bucket URL exposed", "cloud"),
    ('"eks.amazonaws.com"',
     "medium", "AWS EKS endpoint reference found", "cloud"),
]


class GoogleDorkCollector:
    """
    Performs advanced Google dorking against a target domain
    using the Google Custom Search API.
    Covers secrets, admin panels, staging environments,
    API exposure, error pages, tech fingerprinting,
    document leaks, and cloud infrastructure hints.
    100 free queries/day — dorks are batched efficiently.
    """

    def __init__(self, target_org: str):
        self.target_org = target_org
        self.api_key    = os.getenv("GOOGLE_API_KEY")
        self.cse_id     = os.getenv("GOOGLE_CSE_ID")
        self.base_url   = "https://www.googleapis.com/customsearch/v1"
        self.signals: List[Signal] = []
        self._query_count = 0
        self._max_queries = 90  # stay under 100/day limit

    async def collect(self) -> List[Signal]:
        """Main entry point."""
        logger.info(
            f"🔍 Starting Google Dork collection for: {self.target_org}"
        )

        if not self.api_key or not self.cse_id:
            logger.warning(
                "  GOOGLE_API_KEY or GOOGLE_CSE_ID not set — "
                "skipping Google Dork collector"
            )
            return self.signals

        async with httpx.AsyncClient(timeout=15.0) as client:
            for dork, sensitivity, reason, category in DORKS:
                if self._query_count >= self._max_queries:
                    logger.warning(
                        f"  Reached query limit ({self._max_queries}) — stopping"
                    )
                    break

                await self._run_dork(
                    client, dork, sensitivity, reason, category
                )
                # Respect rate limits — 1 query per second
                await asyncio.sleep(1.0)

        logger.success(
            f"✅ Google Dork collection complete — "
            f"{len(self.signals)} signals from "
            f"{self._query_count} queries"
        )
        return self.signals

    async def _run_dork(
        self,
        client: httpx.AsyncClient,
        dork: str,
        sensitivity: str,
        reason: str,
        category: str
    ):
        """Execute a single dork query and process results."""
        # Always scope to target domain
        query = f"site:{self.target_org} {dork}"

        try:
            params = {
                "key": self.api_key,
                "cx":  self.cse_id,
                "q":   query,
                "num": 10,
            }
            response = await client.get(self.base_url, params=params)
            self._query_count += 1

            if response.status_code == 429:
                logger.warning("  Google rate limit hit — pausing 10s")
                await asyncio.sleep(10)
                return

            if response.status_code != 200:
                logger.debug(
                    f"  Dork returned {response.status_code}: {query[:60]}"
                )
                return

            data  = response.json()
            items = data.get("items", [])

            if not items:
                return

            logger.info(
                f"  [{sensitivity.upper()}] '{dork[:50]}' "
                f"→ {len(items)} results"
            )

            for item in items:
                self._process_result(
                    item, dork, query,
                    sensitivity, reason, category
                )

        except httpx.TimeoutException:
            logger.debug(f"  Timeout on dork: {query[:60]}")
        except Exception as e:
            logger.debug(f"  Dork failed: {e}")

    def _process_result(
        self,
        item: dict,
        dork: str,
        full_query: str,
        sensitivity: str,
        reason: str,
        category: str
    ):
        """Build a Signal from a single Google search result."""
        url     = item.get("link", "")
        title   = item.get("title", "")
        snippet = item.get("snippet", "")

        if not url:
            return

        # Map sensitivity string to enum
        sens_map = {
            "critical": SensitivityLevel.CRITICAL,
            "high":     SensitivityLevel.HIGH,
            "medium":   SensitivityLevel.MEDIUM,
            "low":      SensitivityLevel.LOW,
        }
        sens_level = sens_map.get(sensitivity, SensitivityLevel.MEDIUM)

        content = (
            f"Google Dork [{category}]: {title}  |  "
            f"URL: {url}  |  "
            f"Snippet: {snippet[:200]}  |  "
            f"Dork: {dork}"
        )

        entities = self._extract_entities(url, title, snippet, category)

        self.signals.append(Signal(
            target_org=self.target_org,
            source_type=SourceType.WEB,
            source_url=url,
            raw_content=content,
            entities=entities,
            sensitivity=sens_level,
            sensitivity_reason=reason,
            metadata={
                "url":        url,
                "title":      title,
                "snippet":    snippet,
                "dork":       dork,
                "query":      full_query,
                "category":   category,
            }
        ))

    def _extract_entities(
        self,
        url: str,
        title: str,
        snippet: str,
        category: str
    ) -> List[Entity]:
        """Extract entities from a Google search result."""
        entities = []
        combined = f"{url} {title} {snippet}".lower()

        # Hostname from URL
        try:
            from urllib.parse import urlparse
            hostname = urlparse(url).netloc
            if hostname:
                entities.append(Entity(
                    name=hostname,
                    entity_type="HOSTNAME",
                    confidence=1.0,
                    context=f"Google dork result URL: {url[:80]}"
                ))
        except Exception:
            pass

        # Technology hints
        tech_map = {
            "wordpress":  "WORDPRESS",
            "wp-admin":   "WORDPRESS",
            "drupal":     "DRUPAL",
            "jenkins":    "JENKINS",
            "gitlab":     "GITLAB",
            "grafana":    "GRAFANA",
            "kibana":     "KIBANA",
            "swagger":    "SWAGGER",
            "phpmyadmin": "PHPMYADMIN",
            "adminer":    "ADMINER",
            "nginx":      "NGINX",
            "apache":     "APACHE",
            "tomcat":     "TOMCAT",
            "rabbitmq":   "RABBITMQ",
            "traefik":    "TRAEFIK",
            "s3.amazonaws": "AWS_S3",
            "eks.amazonaws":"AWS_EKS",
            "googleapis": "GOOGLE_CLOUD",
            "azure":      "AZURE",
        }
        for keyword, tech in tech_map.items():
            if keyword in combined:
                entities.append(Entity(
                    name=tech,
                    entity_type="TECHNOLOGY",
                    confidence=0.85,
                    context=f"Technology detected in Google dork result"
                ))
                break

        # Category as entity type
        category_entity_map = {
            "secrets":      "CREDENTIAL_EXPOSURE",
            "admin_panels": "ADMIN_PANEL",
            "environments": "ENVIRONMENT_EXPOSURE",
            "api_exposure": "API_EXPOSURE",
            "error_pages":  "ERROR_DISCLOSURE",
            "cloud":        "CLOUD_EXPOSURE",
            "documents":    "DOCUMENT_EXPOSURE",
        }
        if category in category_entity_map:
            entities.append(Entity(
                name=category_entity_map[category],
                entity_type="FINDING_CATEGORY",
                confidence=1.0,
                context=f"Google dork category: {category}"
            ))

        return entities