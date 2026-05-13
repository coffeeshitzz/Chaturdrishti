import httpx
import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from graph.schema import Signal, SourceType, Entity, SensitivityLevel


# URL patterns that indicate sensitive historical exposure
SENSITIVE_PATTERNS = {
    # Critical
    "critical": [
        ".env", ".env.backup", ".env.local",
        "id_rsa", "id_dsa", ".pem", ".p12", ".pfx",
        "config.php", "wp-config.php", "settings.py",
        "database.yml", "secrets.yml", "credentials",
        "passwd", "shadow", ".htpasswd",
        "private_key", "secret_key",
    ],
    # High
    "high": [
        "admin", "administrator", "wp-admin",
        "phpmyadmin", "adminer", "dbadmin",
        "jenkins", "gitlab", "grafana", "kibana",
        "swagger", "api-docs", "openapi",
        ".git", ".svn", ".hg",
        "backup", "dump", "export",
        "phpinfo", "info.php", "test.php",
        "debug", "console", "shell",
    ],
    # Medium
    "medium": [
    "staging", "dev", "development", "beta",
    "api/v1", "api/v2", "api/internal",
    "internal", "intranet", "portal",
    "upload", "uploads", "files",
    ],
}

# File extensions that are inherently sensitive
SENSITIVE_EXTENSIONS = {
    "critical": [".sql", ".bak", ".backup", ".dump", ".tar", ".tar.gz", ".zip"],
    "high":     [".log", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".xml"],
    "medium":   [".php", ".asp", ".aspx", ".jsp", ".py", ".rb"],
}


class WaybackCollector:
    """
    Queries the Wayback Machine CDX API to find historically
    captured URLs for a target domain.
    Surfaces old admin panels, exposed configs, deprecated APIs,
    and files that were deleted but remain archived.
    No API key required.
    """

    def __init__(self, target_org: str):
        self.target_org = target_org
        self.cdx_url    = "http://web.archive.org/cdx/search/cdx"
        self.signals: List[Signal] = []

    async def collect(self) -> List[Signal]:
        """Main entry point."""
        logger.info(
            f"🔍 Starting Wayback Machine collection for: {self.target_org}"
        )

        async with httpx.AsyncClient(timeout=30.0) as client:
            # Fetch all unique URLs ever captured for this domain
            urls = await self._fetch_urls(client)

            if not urls:
                logger.warning(f"  No Wayback data found for {self.target_org}")
                return self.signals

            logger.info(f"  Found {len(urls)} unique archived URLs")

            # Analyse each URL for sensitivity
            for url, timestamp, status_code in urls:
                self._analyse_url(url, timestamp, status_code)

        logger.success(
            f"✅ Wayback collection complete — {len(self.signals)} signals"
        )
        return self.signals

    async def _fetch_urls(self, client: httpx.AsyncClient):
        
        patterns = [
            f"{self.target_org}/*",      # apex domain + paths
            f"*.{self.target_org}/*",    # subdomains + paths
        ]

        all_rows = []
        for pattern in patterns:
            try:
                params = {
                    "url":      pattern,
                    "output":   "json",
                    "fl":       "original,timestamp,statuscode",
                    "collapse": "urlkey",
                    "limit":    1500,
                }
                response = await client.get(self.cdx_url, params=params)

                if response.status_code != 200:
                    logger.warning(
                        f"  CDX returned {response.status_code} for pattern {pattern}"
                    )
                    continue

                data = response.json()
                if not data or len(data) < 2:
                    continue

                # First row is headers
                rows = data[1:]
                all_rows.extend(
                    (row[0], row[1], row[2])
                    for row in rows
                    if len(row) >= 3
                )

            except Exception as e:
                logger.warning(f"  CDX fetch failed for {pattern}: {e}")
                continue

        # Deduplicate by URL (in case apex and subdomain queries overlap)
        seen = set()
        unique = []
        for url, ts, sc in all_rows:
            if url not in seen:
                seen.add(url)
                unique.append((url, ts, sc))

        return unique

    def _analyse_url(self, url: str, timestamp: str, status_code: str):
        """
        Assess a captured URL for sensitivity.
        Creates a signal if the URL matches sensitive patterns.
        """
    
        url_lower = url.lower()
        sensitivity, reason = self._assess_url(url_lower)

        if sensitivity is None:
            return  # not interesting enough to record

        # Format timestamp readably: 20210315123456 → 2021-03-15
        readable_ts = self._format_timestamp(timestamp)

        # Build Wayback archive link
        archive_url = f"https://web.archive.org/web/{timestamp}/{url}"

        content = (
            f"Historical URL: {url}  |  "
            f"Captured: {readable_ts}  |  "
            f"Status: {status_code}"
        )

        entities = self._extract_entities(url, url_lower)

        self.signals.append(Signal(
            target_org=self.target_org,
            source_type=SourceType.WEB,
            source_url=archive_url,
            raw_content=content,
            entities=entities,
            sensitivity=sensitivity,
            sensitivity_reason=reason,
            metadata={
                "original_url": url,
                "timestamp":    timestamp,
                "captured_at":  readable_ts,
                "status_code":  status_code,
                "archive_url":  archive_url,
            }
        ))

        logger.info(
            f"  [{sensitivity}] {url[:80]} ({readable_ts})"
        )

    def _assess_url(self, url_lower: str):
        """
        Score a URL's sensitivity based on path tokens and file extensions.

        Uses token-based matching on the URL path (split on /, -, _, .)
        rather than substring matching. This prevents false positives like
        '0ddshadow' matching 'shadow' or '001white_devil' matching 'dev'.

        Returns (SensitivityLevel, reason) or (None, None).
        """
        import re
        from urllib.parse import urlparse

        # Parse the URL and work on the path only — the hostname is scored
        # separately by the classifier's hostname-token scorer.
        try:
            parsed = urlparse(url_lower)
            path = parsed.path or ""
        except Exception:
            path = url_lower

        # Tokenize the path on common separators. /admin/panel -> {admin, panel}
        # Keep file extensions as tokens too: /backup.sql -> {backup, sql}
        tokens = set(t for t in re.split(r"[/\-_.]", path) if t)

        # Check critical patterns against tokens
        for pattern in SENSITIVE_PATTERNS["critical"]:
            # Split multi-part patterns too: "wp-config.php" -> {wp, config, php}
            pattern_tokens = set(t for t in re.split(r"[/\-_.]", pattern) if t)
            # Match if ALL pattern tokens appear in the URL tokens
            if pattern_tokens and pattern_tokens.issubset(tokens):
                return (
                    SensitivityLevel.CRITICAL,
                    f"Historically exposed sensitive path: '{pattern}'"
                )

        # Check critical extensions — these still use endswith because
        # extensions are anchored to the end of the URL by definition
        for ext in SENSITIVE_EXTENSIONS["critical"]:
            if path.endswith(ext) or f"{ext}?" in url_lower:
                return (
                    SensitivityLevel.CRITICAL,
                    f"Sensitive file type historically accessible: {ext}"
                )

        # Check high patterns
        for pattern in SENSITIVE_PATTERNS["high"]:
            pattern_tokens = set(t for t in re.split(r"[/\-_.]", pattern) if t)
            if pattern_tokens and pattern_tokens.issubset(tokens):
                return (
                    SensitivityLevel.HIGH,
                    f"High-value historical URL: '{pattern}'"
                )

        # Check high extensions
        for ext in SENSITIVE_EXTENSIONS["high"]:
            if path.endswith(ext) or f"{ext}?" in url_lower:
                return (
                    SensitivityLevel.HIGH,
                    f"Configuration file type historically accessible: {ext}"
                )

        # Check medium patterns
        for pattern in SENSITIVE_PATTERNS["medium"]:
            pattern_tokens = set(t for t in re.split(r"[/\-_.]", pattern) if t)
            if pattern_tokens and pattern_tokens.issubset(tokens):
                return (
                    SensitivityLevel.MEDIUM,
                    f"Interesting historical URL: '{pattern}'"
                )

        return None, None

    def _extract_entities(self, url: str, url_lower: str) -> List[Entity]:
        """Extract entities from a historical URL."""
        entities = []

        # The URL itself as a hostname entity
        try:
            from urllib.parse import urlparse
            parsed   = urlparse(url)
            hostname = parsed.netloc
            path     = parsed.path

            if hostname:
                entities.append(Entity(
                    name=hostname,
                    entity_type="HOSTNAME",
                    confidence=1.0,
                    context=f"Historically archived URL: {url[:100]}"
                ))

            # Detect technology from path
            tech_hints = {
                "wp-":       "WORDPRESS",
                "wordpress": "WORDPRESS",
                "drupal":    "DRUPAL",
                "joomla":    "JOOMLA",
                "laravel":   "LARAVEL",
                "django":    "DJANGO",
                "rails":     "RAILS",
                "jenkins":   "JENKINS",
                "gitlab":    "GITLAB",
                "grafana":   "GRAFANA",
                "kibana":    "KIBANA",
                "phpmy":     "PHPMYADMIN",
                "adminer":   "ADMINER",
            }
            for hint, tech in tech_hints.items():
                if hint in url_lower:
                    entities.append(Entity(
                        name=tech,
                        entity_type="TECHNOLOGY",
                        confidence=0.85,
                        context=f"Technology inferred from historical URL: {url[:80]}"
                    ))
                    break

        except Exception:
            pass

        return entities

    def _format_timestamp(self, ts: str) -> str:
        """Convert CDX timestamp to readable date."""
        try:
            return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
        except Exception:
            return ts