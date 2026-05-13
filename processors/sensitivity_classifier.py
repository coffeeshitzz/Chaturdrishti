import re
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List, Tuple, Pattern
from graph.schema import Signal, SensitivityLevel, SourceType


# ─────────────────────────────────────────────────────────────────────────────
# Sensitivity rules — keywords matched with WORD BOUNDARIES (\b...\b).
# This kills the entire class of bugs where "dev" matched "developer",
# "admin" matched "administrator", etc.
#
# Rules removed from the previous version because they fired on prose:
#   internal, dev, vpn, exception, stack trace, email, repository,
#   subdomain, mx record, nameserver, contributor, employee
#
# These were either meta-words (every GitHub signal contains "repository"),
# too broad (every blog post contains "internal"), or required structural
# context that prose-matching cannot provide (a stack trace in an error page
# is sensitive; the word "exception" in a tutorial is not).
#
# The infrastructure-name rules that DO belong (admin, internal, vpn, dev)
# moved into HOSTNAME_TOKEN_RULES below, where they're applied as token
# membership against hostname-shaped signals.
# ─────────────────────────────────────────────────────────────────────────────
SENSITIVITY_RULES = [
    # Critical — high-confidence credential / secret indicators
    ("private_key",       SensitivityLevel.CRITICAL, 10),
    ("secret_key",        SensitivityLevel.CRITICAL, 10),
    ("api_key",           SensitivityLevel.CRITICAL, 10),
    ("access_token",      SensitivityLevel.CRITICAL, 10),
    ("aws_secret_access_key", SensitivityLevel.CRITICAL, 10),
    ("aws_access_key_id",     SensitivityLevel.CRITICAL, 10),
    ("database_url",      SensitivityLevel.CRITICAL, 9),
    ("connection_string", SensitivityLevel.CRITICAL, 9),
    ("bastion",           SensitivityLevel.CRITICAL, 9),
    ("jumpbox",           SensitivityLevel.CRITICAL, 9),
    ("credentials",       SensitivityLevel.CRITICAL, 8),

    # High — infrastructure exposure indicators
    ("jenkins",           SensitivityLevel.HIGH, 6),
    ("vault",             SensitivityLevel.HIGH, 6),
    ("staging",           SensitivityLevel.HIGH, 6),
    ("grafana",           SensitivityLevel.HIGH, 5),
    ("kibana",            SensitivityLevel.HIGH, 5),
    ("gitlab",            SensitivityLevel.HIGH, 5),
    ("terraform",         SensitivityLevel.HIGH, 4),
    ("dockerfile",        SensitivityLevel.HIGH, 4),
    ("kubernetes",        SensitivityLevel.HIGH, 3),
]

# Hostname-token rules apply ONLY to hostname-shaped signals.
# A token is a label between dots / dashes / underscores. In
# "admin-staging.example.com" the tokens are {admin, staging, example, com}.
HOSTNAME_TOKEN_RULES = [
    ("internal", SensitivityLevel.CRITICAL, 8),
    ("bastion",  SensitivityLevel.CRITICAL, 9),
    ("jumpbox",  SensitivityLevel.CRITICAL, 9),
    ("vpn",      SensitivityLevel.CRITICAL, 7),
    ("vault",    SensitivityLevel.HIGH, 6),
    ("admin",    SensitivityLevel.HIGH, 6),
    ("staging",  SensitivityLevel.HIGH, 6),
    ("jenkins",  SensitivityLevel.HIGH, 6),
    ("grafana",  SensitivityLevel.HIGH, 5),
    ("kibana",   SensitivityLevel.HIGH, 5),
    ("gitlab",   SensitivityLevel.HIGH, 5),
    ("dev",      SensitivityLevel.MEDIUM, 3),
    ("test",     SensitivityLevel.MEDIUM, 3),
    ("uat",      SensitivityLevel.MEDIUM, 3),
    ("qa",       SensitivityLevel.MEDIUM, 3),
]

# Pre-compile word-boundary regexes once at import time.
COMPILED_RULES: List[Tuple[Pattern, SensitivityLevel, int, str]] = [
    (re.compile(rf'\b{re.escape(kw)}\b', re.IGNORECASE), level, weight, kw)
    for kw, level, weight in SENSITIVITY_RULES
]

LEVEL_WEIGHTS = {
    SensitivityLevel.LOW:      1,
    SensitivityLevel.MEDIUM:   2,
    SensitivityLevel.HIGH:     3,
    SensitivityLevel.CRITICAL: 4,
}

# Whitelist — content patterns that are intentionally public.
# If any appear, the signal is forced to LOW regardless of other matches.
WHITELIST_PATTERNS = [
    # Domain verification tokens
    "google-site-verification",
    "atlassian-domain-verification",
    "facebook-domain-verification",
    "apple-domain-verification",
    "have-i-been-pwned-verification",
    "stripe-verification",
    "keybase-site-verification",
    "zoom-domain-verification",
    "docusign",
    "sendgrid-",
    "amazonses:",
    "ms=",
    # Email auth records — standard public DNS infrastructure
    "v=spf1",
    "v=dmarc1",
    "v=dkim1",
    # Standard public infrastructure markers
    "_acme-challenge",   # Let's Encrypt validation
    "_domainkey",        # DKIM selector subdomain
    "autodiscover",      # MS Exchange standard
    "_dmarc",            # DMARC subdomain
    "sitemap"            # sitemap*.xml files are intentionally public
]


# Sources whose raw_content is hostname-shaped and should be scored
# by token membership rather than prose substring matching.
#
# Stored as raw string values (not enum members) because the Signal model
# uses `use_enum_values = True`, which means signal.source_type is the
# string value of the enum at runtime, not the enum member itself.
HOSTNAME_SOURCES = {
    SourceType.DNS.value,
    SourceType.CERTIFICATE.value,
    SourceType.SHODAN.value,
    SourceType.WEB.value,  # Wayback URLs — hostname is the meaningful part
}


class SensitivityClassifier:
    """
    Word-boundary, source-aware sensitivity classifier.

    Key changes from the previous version:
      1. Word-boundary matching — "dev" no longer matches "developer".
      2. Hostname signals (DNS, CERTIFICATE, SHODAN, WEB) are scored by
         tokenizing on dots / dashes / underscores / slashes and checking
         token membership instead of substring matching against prose.
      3. Removed twelve meta-word and overly-broad rules.
      4. Whitelist expanded to cover standard public DNS infrastructure
         (_acme-challenge, _domainkey, autodiscover, _dmarc).
      5. Replaced the "never downgrade" ratchet with unconditional
         classification — the old ratchet was hiding bugs by preserving
         incorrect upgrades from earlier passes.
    """

    def classify(self, signal: Signal) -> Signal:
        """Classify a single signal's sensitivity."""
        text = signal.raw_content or ""

        # Hard whitelist short-circuit — public infrastructure markers
        # are always LOW regardless of what else matches.
        if self._is_whitelisted(text):
            signal.sensitivity = SensitivityLevel.LOW
            signal.sensitivity_reason = "Whitelisted public infrastructure marker"
            return signal

        # Source-aware scoring. Because Signal uses use_enum_values=True,
        # signal.source_type is the string value of the enum at runtime.
        source = signal.source_type
        if source in HOSTNAME_SOURCES:
            score, reason = self._score_hostname(text)
        else:
            score, reason = self._score_text(text)

        classifier_level = self._score_to_level(score)

        # Take the max of (collector's prior label, classifier's computed level).
        # Collectors often know things the classifier cannot see from raw_content
        # alone — e.g., Wayback path patterns, GitHub file priority tiers. We
        # respect those as a floor, but still allow the classifier to raise
        # sensitivity when it matches a rule the collector missed.
        prior = signal.sensitivity
        prior_weight = LEVEL_WEIGHTS.get(
            SensitivityLevel(prior) if prior else SensitivityLevel.LOW,
            1,
        ) if prior else 1
        new_weight = LEVEL_WEIGHTS.get(classifier_level, 1)

        if new_weight >= prior_weight:
            signal.sensitivity = classifier_level
            signal.sensitivity_reason = reason
            if prior != classifier_level:
                logger.debug(f"  Sensitivity {prior} → {classifier_level}: {reason[:80]}")
        # else: keep the collector's prior label — it knew something we don't

        return signal

    def classify_batch(self, signals: List[Signal]) -> List[Signal]:
        """Classify a batch of signals and report the level distribution."""
        logger.info(f"  Classifying sensitivity for {len(signals)} signals...")

        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for signal in signals:
            self.classify(signal)
            val = signal.sensitivity
            key = (val.value if hasattr(val, "value") else str(val)).lower()
            if key in distribution:
                distribution[key] += 1

        logger.success(
            f"  ✅ Sensitivity classification complete  "
            f"CRITICAL={distribution['critical']}  "
            f"HIGH={distribution['high']}  "
            f"MEDIUM={distribution['medium']}  "
            f"LOW={distribution['low']}"
        )
        return signals

    # ── Scoring strategies ──────────────────────────────────────────────────

    def _is_whitelisted(self, text: str) -> bool:
        t = text.lower()
        return any(p in t for p in WHITELIST_PATTERNS)

    def _score_text(self, text: str) -> Tuple[int, str]:
        """
        Score arbitrary text using word-boundary keyword matching.
        Used for non-hostname signals (GITHUB, JOB_POSTING).
        """
        total_score = 0
        matched: List[Tuple[str, int]] = []

        for pattern, _level, weight, kw in COMPILED_RULES:
            if pattern.search(text):
                total_score += weight
                matched.append((kw, weight))

        if not matched:
            return 0, "No sensitive patterns detected"

        matched.sort(key=lambda x: x[1], reverse=True)
        top = ", ".join(kw for kw, _ in matched[:3])
        return total_score, f"Sensitive patterns detected: {top}"

    def _score_hostname(self, text: str) -> Tuple[int, str]:
        """
        Score a hostname-shaped signal by tokenizing on dots, dashes,
        underscores, slashes, and colons. This is the right way to catch
        "admin.example.com" or "vpn-prod.corp" without matching
        "administrator" or "developer" in prose.

        Slashes and colons are included so full URLs (e.g., from Wayback)
        tokenize correctly:
            "https://example.com/admin/login" → {https, example, com, admin, login}
        """
        tokens = set(
            t for t in re.split(r"[.\-_/:]", text.lower()) if t
        )

        if not tokens:
            return 0, "No hostname tokens"

        total_score = 0
        matched: List[Tuple[str, int]] = []

        for kw, _level, weight in HOSTNAME_TOKEN_RULES:
            if kw in tokens:
                total_score += weight
                matched.append((kw, weight))

        if not matched:
            return 0, "No sensitive hostname tokens"

        matched.sort(key=lambda x: x[1], reverse=True)
        top = ", ".join(kw for kw, _ in matched[:3])
        return total_score, f"Sensitive hostname tokens: {top}"

    def _score_to_level(self, score: int) -> SensitivityLevel:
        """
        Convert numeric score to sensitivity level.

        Thresholds raised from the previous version (was 8/5/2) because
        word-boundary matching produces tighter scores. Recalibrate against
        your real data after the first run by checking the distribution
        log line.
        """
        if score >= 10:
            return SensitivityLevel.CRITICAL
        elif score >= 6:
            return SensitivityLevel.HIGH
        elif score >= 3:
            return SensitivityLevel.MEDIUM
        else:
            return SensitivityLevel.LOW