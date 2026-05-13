import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from inference.engine import InferenceReport, InferenceChain


RISK_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢"
}


def print_report(report: InferenceReport):
    """Print a formatted inference report to the terminal."""

    width = 60
    print("\n" + "═" * width)
    print(f"  ChaturDrishti — Inference Report")
    print(f"  Target: {report.target_org}")
    print(f"  Risk Score: {report.risk_score}/100  {_risk_bar(report.risk_score)}")
    print(f"  Signals Analyzed: {report.total_signals}")
    print("═" * width)

    print(f"\n📋 SUMMARY:")
    print(f"  {report.summary}")

    if not report.findings:
        print("\n  No findings generated.")
        return

    print(f"\n🔍 FINDINGS ({len(report.findings)} total):\n")

    for i, finding in enumerate(report.findings, 1):
        icon = RISK_ICONS.get(finding.risk_level, "⚪")
        print(f"  {icon} Finding #{i} — {finding.title.upper()}")
        print(f"  {'─' * (width - 4)}")

        print(f"\n  Inference:")
        print(f"    {finding.inference}")

        if finding.evidence:
            print(f"\n  Evidence:")
            for ev in finding.evidence:
                print(f"    → {ev}")

        if finding.attacker_value:
            print(f"\n  Attacker Value:")
            print(f"    {finding.attacker_value}")

        if finding.mitigations:
            print(f"\n  Mitigation:")
            for m in finding.mitigations:
                print(f"    ✅ {m}")

        print()

    print("═" * width)
    print(f"  End of Report — ChaturDrishti v0.1")
    print("═" * width + "\n")


def _risk_bar(score: int) -> str:
    """Visual risk bar for terminal output."""
    filled = int(score / 10)
    bar = "█" * filled + "░" * (10 - filled)
    return f"[{bar}]"