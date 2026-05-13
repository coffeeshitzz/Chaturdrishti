import whois
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from datetime import datetime
from graph.schema import Signal, SourceType, Entity, SensitivityLevel


class WHOISCollector:
    """
    Collects WHOIS registration data for a target domain.
    Reveals registrar, org name, creation date, expiry,
    name servers, and registrant contact details.
    No API key required.
    """

    def __init__(self, target_org: str):
        self.target_org = target_org
        self.signals: List[Signal] = []

    def collect(self) -> List[Signal]:
        """Main entry point."""
        logger.info(f"🔍 Starting WHOIS collection for: {self.target_org}")

        try:
            w = whois.whois(self.target_org)
            if not w:
                logger.warning(f"  No WHOIS data returned for {self.target_org}")
                return self.signals

            self._process_whois(w)

        except Exception as e:
            logger.error(f"  WHOIS lookup failed: {e}")

        logger.success(f"✅ WHOIS collection complete — {len(self.signals)} signals")
        return self.signals

    def _process_whois(self, w):
        """Extract signals from WHOIS response."""

        # ── Registrar signal ──────────────────────────────────────────
        registrar = self._safe_str(w.get("registrar"))
        if registrar:
            self.signals.append(self._build_signal(
                content=f"Domain registrar: {registrar}",
                sensitivity=SensitivityLevel.LOW,
                reason="Registrar is public information",
                entities=[Entity(
                    name=registrar,
                    entity_type="REGISTRAR",
                    confidence=1.0,
                    context=f"{self.target_org} registered with {registrar}"
                )],
                metadata={"registrar": registrar}
            ))

        # ── Registration & expiry dates ───────────────────────────────
        creation = self._safe_date(w.get("creation_date"))
        expiry   = self._safe_date(w.get("expiration_date"))
        updated  = self._safe_date(w.get("updated_date"))

        if creation or expiry:
            # Flag domains expiring soon — attackers target these
            days_to_expiry = None
            sensitivity    = SensitivityLevel.LOW
            reason         = "Domain registration dates are public"

            if expiry:
                try:
                    delta = (expiry - datetime.utcnow()).days
                    days_to_expiry = delta
                    if delta < 30:
                        sensitivity = SensitivityLevel.CRITICAL
                        reason = f"Domain expires in {delta} days — takeover risk"
                    elif delta < 90:
                        sensitivity = SensitivityLevel.HIGH
                        reason = f"Domain expires in {delta} days — monitor closely"
                except Exception:
                    pass

            content = (
                f"Domain registration — "
                f"Created: {creation or 'unknown'}  |  "
                f"Expires: {expiry or 'unknown'}  |  "
                f"Updated: {updated or 'unknown'}"
            )

            self.signals.append(self._build_signal(
                content=content,
                sensitivity=sensitivity,
                reason=reason,
                entities=[],
                metadata={
                    "creation_date":  str(creation),
                    "expiration_date": str(expiry),
                    "updated_date":   str(updated),
                    "days_to_expiry": days_to_expiry,
                }
            ))

        # ── Organisation name ─────────────────────────────────────────
        org = self._safe_str(w.get("org") or w.get("organization"))
        if org:
            self.signals.append(self._build_signal(
                content=f"Registrant organization: {org}",
                sensitivity=SensitivityLevel.MEDIUM,
                reason="Organisation name links domain to legal entity",
                entities=[Entity(
                    name=org,
                    entity_type="ORGANIZATION",
                    confidence=0.95,
                    context=f"WHOIS registrant org for {self.target_org}"
                )],
                metadata={"org": org}
            ))

        # ── Registrant email ──────────────────────────────────────────
        emails = w.get("emails")
        if emails:
            if isinstance(emails, str):
                emails = [emails]
            for email in set(emails):
                if email and "@" in email:
                    self.signals.append(self._build_signal(
                        content=f"WHOIS contact email: {email}",
                        sensitivity=SensitivityLevel.HIGH,
                        reason="Registrant email reveals contact identity",
                        entities=[Entity(
                            name=email,
                            entity_type="EMAIL_ADDRESS",
                            confidence=0.95,
                            context=f"WHOIS registrant contact for {self.target_org}"
                        )],
                        metadata={"email": email}
                    ))

        # ── Name servers ──────────────────────────────────────────────
        name_servers = w.get("name_servers")
        if name_servers:
            if isinstance(name_servers, str):
                name_servers = [name_servers]
            ns_list = list(set([ns.lower() for ns in name_servers if ns]))
            if ns_list:
                content = f"Name servers: {', '.join(ns_list)}"
                self.signals.append(self._build_signal(
                    content=content,
                    sensitivity=SensitivityLevel.LOW,
                    reason="Name servers reveal DNS hosting provider",
                    entities=[
                        Entity(
                            name=ns,
                            entity_type="NAMESERVER",
                            confidence=1.0,
                            context=f"WHOIS name server for {self.target_org}"
                        )
                        for ns in ns_list
                    ],
                    metadata={"name_servers": ns_list}
                ))

        # ── DNSSEC status ─────────────────────────────────────────────
        dnssec = self._safe_str(w.get("dnssec"))
        if dnssec:
            is_unsigned = "unsigned" in dnssec.lower()
            self.signals.append(self._build_signal(
                content=f"DNSSEC status: {dnssec}",
                sensitivity=(
                    SensitivityLevel.MEDIUM if is_unsigned
                    else SensitivityLevel.LOW
                ),
                reason=(
                    "DNSSEC unsigned — vulnerable to DNS spoofing"
                    if is_unsigned else "DNSSEC enabled"
                ),
                entities=[],
                metadata={"dnssec": dnssec}
            ))

        # ── Status flags ──────────────────────────────────────────────
        status = w.get("status")
        if status:
            if isinstance(status, str):
                status = [status]
            status_str = ", ".join(status) if status else ""
            if status_str:
                self.signals.append(self._build_signal(
                    content=f"Domain status flags: {status_str[:200]}",
                    sensitivity=SensitivityLevel.LOW,
                    reason="Domain status flags are public registry information",
                    entities=[],
                    metadata={"status": status}
                ))

    def _build_signal(self, content, sensitivity, reason, entities, metadata):
        return Signal(
            target_org=self.target_org,
            source_type=SourceType.WEB,
            source_url=f"https://www.whois.com/whois/{self.target_org}",
            raw_content=content,
            entities=entities,
            sensitivity=sensitivity,
            sensitivity_reason=reason,
            metadata={"collector": "whois", **metadata}
        )

    def _safe_str(self, val) -> str:
        if val is None:
            return ""
        if isinstance(val, list):
            val = val[0] if val else ""
        return str(val).strip()

    def _safe_date(self, val) -> datetime:
        if val is None:
            return None
        if isinstance(val, list):
            val = val[0] if val else None
        if isinstance(val, datetime):
            return val
        return None