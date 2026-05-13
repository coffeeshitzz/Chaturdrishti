import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.wayback import WaybackCollector
from graph.ingestion import Neo4jConnection, SignalIngestion


async def run():
    target = "hackerone.com"

    collector = WaybackCollector(target_org=target)
    signals   = await collector.collect()

    print(f"\n🕰️  Wayback Machine — {len(signals)} signals")

    for level in ["critical", "high", "medium"]:
        found = [s for s in signals if s.sensitivity == level]
        if found:
            print(f"\n  {level.upper()} ({len(found)}):")
            for s in found[:5]:
                print(f"    → {s.metadata.get('original_url', '')[:90]}")
                print(f"       Captured: {s.metadata.get('captured_at')}  |  {s.sensitivity_reason}")

    print(f"\n📥 Writing to Neo4j...")
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        for signal in signals:
            ingestion.ingest_signal(signal)

    print(f"✅ Done.")


if __name__ == "__main__":
    asyncio.run(run())