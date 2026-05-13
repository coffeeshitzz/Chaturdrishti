import re
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ollama
from loguru import logger
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from graph.ingestion import Neo4jConnection
from inference.retriever import SignalRetriever


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InferenceChain:
    """A single attacker inference finding with evidence and risk score."""
    title:            str
    inference:        str
    evidence:         List[str]       # rendered evidence lines (human-readable)
    evidence_sig_ids: List[str]       # real Signal.id values cited, for auditing
    attacker_value:   str
    risk_level:       str             # critical / high / medium / low
    mitigations:      List[str] = field(default_factory=list)


@dataclass
class InferenceReport:
    """Complete inference report for a target organization."""
    target_org:    str
    summary:       str
    findings:      List[InferenceChain]
    total_signals: int
    risk_score:    int                # 0-100, deterministic from findings


# ─────────────────────────────────────────────────────────────────────────────
# Prompt construction
#
# Signals get short tags [S1], [S2]... in the prompt — LLMs cite short tags
# far more reliably than UUIDs. We keep a tag → real_id map so we can resolve
# citations back to real Signal IDs during validation.
# ─────────────────────────────────────────────────────────────────────────────

def _build_context_prompt(
    context: Dict[str, Any]
) -> Tuple[str, Dict[str, str]]:
    """
    Build the prompt and return (prompt_text, tag_to_id_map).
    tag_to_id_map maps "S1" → real Signal UUID for post-validation.
    """
    target = context["target_org"]
    tag_to_id: Dict[str, str] = {}

    # Format signals with explicit tags and real IDs in the map
    signals_text = ""
    for i, s in enumerate(context["high_signals"][:15], 1):
        tag = f"S{i}"
        real_id = s.get("id", "")
        if real_id:
            tag_to_id[tag] = real_id
        signals_text += (
            f"\n  [{tag}] [{s.get('sensitivity', 'unknown').upper()}]"
            f" [{s.get('source_type', 'unknown')}]:\n"
            f"  {s.get('raw_content', '')[:200]}\n"
            f"  Reason: {s.get('sensitivity_reason', '')}\n"
        )

    if not signals_text:
        signals_text = "  No high sensitivity signals found."

    tech_names = list({t.get("name", "") for t in context["technologies"] if t.get("name")})
    tech_text = ", ".join(tech_names[:20]) if tech_names else "None detected"

    hostname_names = list({h.get("name", "") for h in context["hostnames"] if h.get("name")})
    hostname_text = "\n  ".join(hostname_names[:20]) if hostname_names else "None detected"

    people_names = list({p.get("name", "") for p in context["people"] if p.get("name")})
    people_text = ", ".join(people_names[:10]) if people_names else "None detected"

    repo_names = list({r.get("name", "") for r in context["repositories"] if r.get("name")})
    repo_text = ", ".join(repo_names[:10]) if repo_names else "None detected"

    prompt = f"""You are a senior threat intelligence analyst performing defensive OSINT analysis.
Your task is to analyze publicly available information about {target} and identify
what sensitive operational insights an attacker could infer.

This is a DEFENSIVE analysis — the goal is to help the organization reduce their
reconnaissance footprint.

═══════════════════════════════════════════
TARGET: {target}
═══════════════════════════════════════════

TECHNOLOGIES DETECTED:
  {tech_text}

PUBLIC HOSTNAMES/SUBDOMAINS:
  {hostname_text}

KNOWN CONTRIBUTORS/PEOPLE:
  {people_text}

PUBLIC REPOSITORIES:
  {repo_text}

HIGH/CRITICAL SENSITIVITY SIGNALS:
{signals_text}

═══════════════════════════════════════════
CRITICAL RULES — READ CAREFULLY
═══════════════════════════════════════════

1. Every finding MUST cite at least one signal tag from the list above, in the
   format [S1], [S2], etc. Tags that are not in the list above DO NOT EXIST.
2. Do NOT invent signals. Do NOT reference evidence that is not in the list.
3. Every EVIDENCE bullet must start with one or more signal tags, e.g.:
      - [S3] WHOIS email reveals registrant identity
4. Only produce a finding if you can cite at least ONE real signal tag for it.
   If there is no supporting signal, DO NOT write that finding.
5. A finding that combines 2+ signals from different sources is more valuable
   than a finding built on a single signal.
6. If the signals are weak or sparse, it is BETTER to produce fewer, stronger
   findings than to pad the report. Zero findings is an acceptable answer.

═══════════════════════════════════════════
OUTPUT FORMAT — FOLLOW EXACTLY
═══════════════════════════════════════════

SUMMARY:
[2-3 sentence overview]

FINDING_1:
TITLE: [short title]
INFERENCE: [what an attacker can conclude]
EVIDENCE:
- [S1] [brief paraphrase of what S1 shows]
- [S3] [brief paraphrase of what S3 shows]
ATTACKER_VALUE: [why this matters]
RISK: [critical|high|medium|low]
MITIGATION: [concrete step]

FINDING_2:
[same structure, or omit if no evidence supports a second finding]

FINDING_3:
[same structure, or omit]
"""
    return prompt, tag_to_id


# ─────────────────────────────────────────────────────────────────────────────
# Response parsing
# ─────────────────────────────────────────────────────────────────────────────

TAG_RE = re.compile(r"\[S(\d+)\]")


def _extract_tags(text: str) -> List[str]:
    """Extract all [SN] tags from a line of text."""
    return [f"S{m.group(1)}" for m in TAG_RE.finditer(text)]


def _parse_response(
    response_text: str,
    target_org: str,
    tag_to_id: Dict[str, str],
) -> Tuple[str, List[InferenceChain]]:
    """
    Parse the LLM response. Returns (summary, findings).
    Findings with no validated citations are dropped.
    """
    response_text = response_text.replace("**", "")
    lines = response_text.strip().split("\n")

    summary = ""
    findings: List[InferenceChain] = []
    current: Dict[str, Any] = {}

    def flush():
        if not current:
            return
        built = _build_finding(current, tag_to_id)
        if built is not None:
            findings.append(built)

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("SUMMARY:"):
            summary_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith("FINDING_"):
                summary_lines.append(lines[i].strip())
                i += 1
            summary = " ".join(filter(None, summary_lines))
            continue

        if line.startswith("FINDING_"):
            flush()
            current = {}
            i += 1
            continue

        if line.startswith("TITLE:"):
            current["title"] = line.replace("TITLE:", "").strip()
        elif line.startswith("INFERENCE:"):
            current["inference"] = line.replace("INFERENCE:", "").strip()
        elif line.startswith("EVIDENCE:"):
            evidence_lines = []
            i += 1
            while i < len(lines) and not lines[i].strip().startswith(
                ("ATTACKER_VALUE:", "RISK:", "MITIGATION:", "FINDING_")
            ):
                ev = lines[i].strip().lstrip("•-*").strip()
                if ev:
                    evidence_lines.append(ev)
                i += 1
            current["evidence"] = evidence_lines
            continue
        elif line.startswith("ATTACKER_VALUE:"):
            current["attacker_value"] = line.replace("ATTACKER_VALUE:", "").strip()
        elif line.startswith("RISK:"):
            current["risk"] = line.replace("RISK:", "").strip().lower()
        elif line.startswith("MITIGATION:"):
            mitigation = line.replace("MITIGATION:", "").strip()
            current["mitigations"] = [mitigation] if mitigation else []

        i += 1

    flush()
    return summary, findings


def _build_finding(
    data: Dict,
    tag_to_id: Dict[str, str],
) -> Optional[InferenceChain]:
    """
    Build an InferenceChain with citation validation.
    Returns None if the finding has no valid cited evidence — this is the
    citation guardrail that prevents ungrounded findings from reaching the UI.
    """
    evidence_lines = data.get("evidence", []) or []

    # Collect all tags cited across all evidence lines, validated against
    # the real tag_to_id map. Unknown tags are silently dropped.
    validated_ids: List[str] = []
    kept_lines: List[str] = []
    for line in evidence_lines:
        tags = _extract_tags(line)
        real_ids = [tag_to_id[t] for t in tags if t in tag_to_id]
        if real_ids:
            validated_ids.extend(real_ids)
            kept_lines.append(line)

    # GUARDRAIL: drop findings with zero validated citations.
    # This is what kills Whatnot-Finding-#2-style hallucinations.
    if not validated_ids:
        logger.warning(
            f"  Dropped ungrounded finding: "
            f"{data.get('title', '<untitled>')[:60]}"
        )
        return None

    # Default risk to LOW (not MEDIUM) — safer failure mode for unparsed fields.
    risk = data.get("risk", "low")
    if risk not in {"critical", "high", "medium", "low"}:
        risk = "low"

    return InferenceChain(
        title=data.get("title", "Untitled Finding"),
        inference=data.get("inference", ""),
        evidence=kept_lines,
        evidence_sig_ids=validated_ids,
        attacker_value=data.get("attacker_value", ""),
        risk_level=risk,
        mitigations=data.get("mitigations", []),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Deterministic risk score
# ─────────────────────────────────────────────────────────────────────────────

def _compute_risk_score(findings: List[InferenceChain]) -> int:
    """
    Deterministic risk score from validated findings.
    Documented formula — when asked, point at this function.
        critical × 30 + high × 15 + medium × 5 + low × 1, capped at 100.
    """
    weights = {"critical": 30, "high": 15, "medium": 5, "low": 1}
    score = sum(weights.get(f.risk_level, 0) for f in findings)
    return max(0, min(100, score))


# ─────────────────────────────────────────────────────────────────────────────
# Engine
# ─────────────────────────────────────────────────────────────────────────────

class InferenceEngine:
    """
    Core intelligence engine — retrieves OSINT context from Neo4j,
    constructs attacker reasoning prompts with signal-tag citations,
    runs a local LLM, validates citations, and returns a grounded report.
    """

    def __init__(self, model: str = "llama3.1:8b"):
        self.model = model
        logger.info(f"InferenceEngine initialized with model: {model}")

    def analyze(self, target_org: str) -> InferenceReport:
        logger.info(f"🤖 Starting inference analysis for: {target_org}")

        with Neo4jConnection() as conn:
            retriever = SignalRetriever(conn)
            context = retriever.get_full_context(target_org)

        total_signals = len(context["high_signals"])
        logger.info(f"  Retrieved context: {total_signals} high-sensitivity signals")

        if total_signals == 0:
            logger.warning("  No signals found. Run collectors first.")
            return InferenceReport(
                target_org=target_org,
                summary="No signals found. Run the collection pipeline first.",
                findings=[],
                total_signals=0,
                risk_score=0,
            )

        prompt, tag_to_id = _build_context_prompt(context)
        logger.info(
            f"  Prompt constructed with {len(tag_to_id)} citable signals. "
            f"Running LLM inference..."
        )

        response = ollama.chat(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            options={
                "temperature": 0.2,    # lower than before — less creative drift
                "num_ctx":     8192,   # bumped from 4096 to avoid truncation
            },
        )
        response_text = response["message"]["content"]
        logger.info("  LLM response received. Parsing and validating citations...")

        summary, findings = _parse_response(response_text, target_org, tag_to_id)

        risk_score = _compute_risk_score(findings)

        logger.success(
            f"✅ Inference complete — "
            f"{len(findings)} grounded findings, "
            f"risk score: {risk_score}/100"
        )

        return InferenceReport(
            target_org=target_org,
            summary=summary or "Analysis complete.",
            findings=findings,
            total_signals=total_signals,
            risk_score=risk_score,
        )