import httpx
import asyncio
import json
import time
from pathlib import Path
from loguru import logger
from typing import List, Optional
from datetime import datetime
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from graph.schema import Signal, SourceType, Entity, SensitivityLevel


# ─────────────────────────────────────────────────────────────────────────────
# Cache configuration
# ─────────────────────────────────────────────────────────────────────────────
CACHE_DIR = Path(__file__).resolve().parent.parent / "cache" / "crt_sh"
CACHE_TTL_SECONDS = 24 * 60 * 60   # 24 hours

# In-memory cache shared across instances in a single process.
# Key: target_org string. Value: (timestamp_fetched, entries_list).
_MEMORY_CACHE: dict = {}


class CertCollector:
    """
    Collects certificate transparency log entries for a target organization.
    Uses crt.sh — a public certificate transparency search engine.
    No API key required.

    Caching: responses are cached to cache/crt_sh/<domain>.json with a 24h
    TTL. Retries on network failure with exponential backoff (2s, 4s, 8s).
    Falls back to stale cache if all retries fail — better to demo with
    yesterday's data than to crash on flaky network.
    """

    def __init__(self, target_org: str, use_cache: bool = True):
        self.target_org = target_org
        self.base_url = "https://crt.sh"
        self.signals: List[Signal] = []
        self.use_cache = use_cache

    def _belongs_to_target(self, name: str) -> bool:
        """
        Check if a certificate subject name actually belongs to the
        target domain. Rejects unrelated domains that crt.sh returns
        due to substring matching in its query.
        """
        clean = name.lower().lstrip("*.")
        target = self.target_org.lower()
        return clean == target or clean.endswith("." + target)

    async def collect(self) -> List[Signal]:
        """Main entry point."""
        logger.info(f"🔍 Starting certificate transparency collection for: {self.target_org}")

        async with httpx.AsyncClient(timeout=30.0) as client:
            entries = await self._fetch_certificates(client)
            if entries:
                await self._process_entries(entries)

        logger.success(f"✅ Cert collection complete — {len(self.signals)} signals found")
        return self.signals

    # ── Caching helpers ─────────────────────────────────────────────────────

    def _cache_path(self) -> Path:
        """Filesystem path for this target's cached response."""
        return CACHE_DIR / f"{self.target_org}.json"

    def _read_cache(self, allow_stale: bool = False) -> Optional[list]:
        """
        Try memory cache first, then disk. Returns entries if a valid
        cached response is found, or None otherwise. If allow_stale=True,
        returns expired cache as a last resort for demo reliability.
        """
        now = time.time()

        # Memory
        if self.target_org in _MEMORY_CACHE:
            fetched_at, entries = _MEMORY_CACHE[self.target_org]
            age = now - fetched_at
            if age < CACHE_TTL_SECONDS or allow_stale:
                logger.info(
                    f"  Cache hit (memory, age={int(age)}s): {len(entries)} entries"
                )
                return entries

        # Disk
        path = self._cache_path()
        if path.exists():
            try:
                with path.open() as f:
                    payload = json.load(f)
                fetched_at = payload.get("fetched_at", 0)
                entries = payload.get("entries", [])
                age = now - fetched_at
                if age < CACHE_TTL_SECONDS or allow_stale:
                    _MEMORY_CACHE[self.target_org] = (fetched_at, entries)
                    logger.info(
                        f"  Cache hit (disk, age={int(age)}s): {len(entries)} entries"
                        f"{' [STALE]' if age >= CACHE_TTL_SECONDS else ''}"
                    )
                    return entries
            except Exception as e:
                logger.warning(f"  Cache read failed: {e}")

        return None

    def _write_cache(self, entries: list):
        """Persist entries to memory + disk."""
        now = time.time()
        _MEMORY_CACHE[self.target_org] = (now, entries)

        try:
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            with self._cache_path().open("w") as f:
                json.dump({"fetched_at": now, "entries": entries}, f)
            logger.info(f"  Cached {len(entries)} entries to {self._cache_path()}")
        except Exception as e:
            logger.warning(f"  Cache write failed: {e}")

# ── Main fetch with retry + fallback ────────────────────────────────────

    async def _fetch_certificates(self, client: httpx.AsyncClient) -> list:
        """
        Fetch all certificate entries from crt.sh for the target domain.
        Cache-first: returns cached data if fresh. Falls back to stale
        cache on total network failure.
        """
        if self.use_cache:
            cached = self._read_cache(allow_stale=False)
            if cached is not None:
                return cached

        delays = [2, 4, 8]
        for attempt, delay in enumerate([0] + delays):
            if delay:
                logger.info(f"  Retry attempt {attempt} after {delay}s...")
                await asyncio.sleep(delay)

            try:
                logger.info(f"  Querying crt.sh for %.{self.target_org}...")
                response = await client.get(
                    self.base_url,
                    params={
                        "q": f"%.{self.target_org}",
                        "output": "json",
                    },
                )

                if response.status_code != 200:
                    logger.warning(
                        f"  crt.sh returned status {response.status_code} "
                        f"(attempt {attempt + 1})"
                    )
                    continue

                entries = response.json()
                logger.info(f"  Found {len(entries)} raw certificate entries")

                if self.use_cache:
                    self._write_cache(entries)
                return entries

            except Exception as e:
                logger.warning(
                    f"  crt.sh fetch attempt {attempt + 1} failed: {e}"
                )
                continue

        if self.use_cache:
            stale = self._read_cache(allow_stale=True)
            if stale is not None:
                logger.warning(
                    f"  All retries failed. Using stale cache as fallback."
                )
                return stale

        logger.error(f"  Failed to fetch certificates after all retries")
        return []

# ── Entry processing ────────────────────────────────────────────────────

    async def _process_entries(self, entries: list):
        """
        Deduplicate and process certificate entries into Signal objects.
        crt.sh returns a lot of duplicates — we deduplicate by common_name.
        """
        seen = set()

        for entry in entries:
            name_value = entry.get("name_value", "")
            common_name = entry.get("common_name", "")
            issuer = entry.get("issuer_name", "")
            not_before = entry.get("not_before", "")
            not_after = entry.get("not_after", "")
            cert_id = entry.get("id", "")

            all_names = set()
            for name in name_value.split("\n"):
                name = name.strip()
                if name and name not in seen:
                    all_names.add(name)
                    seen.add(name)

            if common_name and common_name not in seen:
                all_names.add(common_name)
                seen.add(common_name)

            for name in all_names:
                # Skip wildcard roots
                if name == f"*.{self.target_org}":
                    continue

                # Post-filter: reject certificates whose subject name
                # does not belong to the target domain. crt.sh substring
                # matching returns certs from unrelated orgs.
                if not self._belongs_to_target(name):
                    continue

                signal = self._build_signal(
                    domain=name,
                    issuer=issuer,
                    not_before=not_before,
                    not_after=not_after,
                    cert_id=cert_id,
                )
                self.signals.append(signal)
                logger.debug(f"  📜 Certificate found: {name}")

    def _build_signal(
        self,
        domain: str,
        issuer: str,
        not_before: str,
        not_after: str,
        cert_id: str,
    ) -> Signal:
        """Packages a certificate entry into a Signal object."""

        sensitivity, reason = self._assess_sensitivity(domain, issuer)
        entities = self._extract_entities(domain, issuer)

        raw_content = (
            f"Certificate issued for: {domain} | "
            f"Issuer: {issuer} | "
            f"Valid: {not_before} to {not_after}"
        )

        return Signal(
            target_org=self.target_org,
            source_type=SourceType.CERTIFICATE,
            source_url=f"https://crt.sh/?id={cert_id}",
            raw_content=raw_content,
            entities=entities,
            sensitivity=sensitivity,
            sensitivity_reason=reason,
            metadata={
                "domain":     domain,
                "issuer":     issuer,
                "not_before": not_before,
                "not_after":  not_after,
                "cert_id":    cert_id,
            },
        )

    def _assess_sensitivity(self, domain: str, issuer: str):
        """Rule-based sensitivity scoring for certificate entries."""
        domain_lower = domain.lower()

        critical_keywords = [
            "internal", "corp", "intranet", "vpn",
            "admin", "ssh", "bastion", "jumpbox",
        ]
        if any(k in domain_lower for k in critical_keywords):
            return (
                SensitivityLevel.CRITICAL,
                f"Internal infrastructure subdomain exposed in cert log: {domain}",
            )

        high_keywords = [
            "staging", "dev", "test", "beta", "sandbox",
            "jenkins", "gitlab", "jira", "confluence",
            "grafana", "kibana", "vault", "consul",
        ]
        if any(k in domain_lower for k in high_keywords):
            return (
                SensitivityLevel.HIGH,
                f"Development/ops tooling subdomain exposed: {domain}",
            )

        if domain.startswith("*"):
            return (
                SensitivityLevel.HIGH,
                f"Wildcard certificate reveals subdomain pattern: {domain}",
            )

        if domain != self.target_org and domain != f"www.{self.target_org}":
            return (
                SensitivityLevel.MEDIUM,
                f"Non-standard subdomain found in certificate log: {domain}",
            )

        return SensitivityLevel.LOW, "Standard domain certificate"

    def _extract_entities(self, domain: str, issuer: str) -> List[Entity]:
        """Extract entities from a certificate entry."""
        entities = []

        entities.append(Entity(
            name=domain,
            entity_type="HOSTNAME",
            confidence=1.0,
            context=f"Certificate issued for {domain}",
        ))

        ca_map = {
            "Let's Encrypt": "LETS_ENCRYPT",
            "DigiCert":      "DIGICERT",
            "Cloudflare":    "CLOUDFLARE",
            "Amazon":        "AWS_ACM",
            "Google":        "GOOGLE_CA",
            "Sectigo":       "SECTIGO",
            "GlobalSign":    "GLOBALSIGN",
        }
        for ca_name, entity_type in ca_map.items():
            if ca_name.lower() in issuer.lower():
                entities.append(Entity(
                    name=ca_name,
                    entity_type=entity_type,
                    confidence=0.95,
                    context=f"Certificate for {domain} issued by {ca_name}",
                ))

        tool_map = {
            "jenkins":    "CI_CD_TOOL",
            "gitlab":     "SOURCE_CONTROL",
            "grafana":    "MONITORING_TOOL",
            "kibana":     "LOG_ANALYSIS_TOOL",
            "vault":      "SECRETS_MANAGER",
            "consul":     "SERVICE_MESH",
            "prometheus": "MONITORING_TOOL",
            "airflow":    "WORKFLOW_TOOL",
            "kafka":      "MESSAGE_BROKER",
            "elastic":    "SEARCH_ENGINE",
        }
        for tool, entity_type in tool_map.items():
            if tool in domain.lower():
                entities.append(Entity(
                    name=tool,
                    entity_type=entity_type,
                    confidence=0.90,
                    context=f"Subdomain {domain} suggests {tool} usage",
                ))

        return entities