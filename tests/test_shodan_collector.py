import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.shodan import ShodanCollector
from graph.ingestion import Neo4jConnection, SignalIngestion


def run():
    target = "hackerone.com"

    collector = ShodanCollector(target_org=target)
    signals   = collector.collect()

    print(f"\n🔭 Shodan — {len(signals)} signals")

    # Show by severity
    for level in ["critical", "high", "medium"]:
        found = [s for s in signals if s.sensitivity == level]
        if found:
            print(f"\n  {level.upper()} ({len(found)}):")
            for s in found[:3]:
                print(f"    → {s.raw_content[:100]}")

    # CVEs specifically
    cve_signals = [
        s for s in signals
        if any(e.entity_type == "CVE" for e in s.entities)
    ]
    if cve_signals:
        print(f"\n  ⚠️  CVEs found: {len(cve_signals)}")
        for s in cve_signals:
            print(f"    → {s.raw_content[:120]}")

    # Write to Neo4j
    print(f"\n📥 Writing to Neo4j...")
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        for signal in signals:
            ingestion.ingest_signal(signal)

    print(f"✅ Done.")


if __name__ == "__main__":
    run()