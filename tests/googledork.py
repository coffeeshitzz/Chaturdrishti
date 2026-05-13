import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.googledork import GoogleDorkCollector
from graph.ingestion import Neo4jConnection, SignalIngestion


async def run():
    target = "hackerone.com"

    collector = GoogleDorkCollector(target_org=target)
    signals   = await collector.collect()

    print(f"\n🔎 Google Dorks — {len(signals)} signals")

    # Group by category
    by_category: dict = {}
    for s in signals:
        cat = s.metadata.get("category", "unknown")
        by_category.setdefault(cat, []).append(s)

    for cat, cat_signals in sorted(by_category.items()):
        print(f"\n  [{cat.upper()}] {len(cat_signals)} findings:")
        for s in cat_signals[:3]:
            print(f"    [{s.sensitivity}] {s.metadata.get('title', '')[:60]}")
            print(f"    → {s.metadata.get('url', '')[:80]}")

    # Highlight critical and high
    critical = [s for s in signals if s.sensitivity == "critical"]
    high     = [s for s in signals if s.sensitivity == "high"]

    if critical:
        print(f"\n  🔴 CRITICAL ({len(critical)}):")
        for s in critical:
            print(f"    → {s.sensitivity_reason}")
            print(f"       {s.metadata.get('url', '')[:80]}")

    if high:
        print(f"\n  🟠 HIGH ({len(high)}):")
        for s in high[:5]:
            print(f"    → {s.sensitivity_reason}")

    # Write to Neo4j
    if signals:
        print(f"\n📥 Writing to Neo4j...")
        with Neo4jConnection() as conn:
            ingestion = SignalIngestion(conn)
            for signal in signals:
                ingestion.ingest_signal(signal)
        print(f"✅ Done.")
    else:
        print(f"\n  No results found — domain may have minimal public exposure.")


if __name__ == "__main__":
    asyncio.run(run())