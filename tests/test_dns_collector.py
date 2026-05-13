import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.dns import DNSCollector
from graph.ingestion import Neo4jConnection, SignalIngestion
from loguru import logger


async def run():
    target = "hackerone.com"

    # Step 1: Collect DNS signals
    collector = DNSCollector(target_org=target)
    signals = await collector.collect()

    print(f"\n📡 Collected {len(signals)} DNS signals")
    print("\nSample signals:")
    for s in signals[:5]:
        print(f"  [{s.sensitivity}] {s.raw_content}")

    # Step 2: Write everything to Neo4j
    print(f"\n📥 Writing signals to Neo4j...")
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        for signal in signals:
            ingestion.ingest_signal(signal)

    print(f"\n✅ Done. {len(signals)} signals ingested into Neo4j.")
    print("   Open http://localhost:7474 and run:")
    print("   MATCH (n) RETURN n LIMIT 100")


if __name__ == "__main__":
    asyncio.run(run())