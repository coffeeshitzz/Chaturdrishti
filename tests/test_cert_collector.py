import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.cert import CertCollector
from graph.ingestion import Neo4jConnection, SignalIngestion
from loguru import logger


async def run():
    target = "hackerone.com"

    # Step 1: Collect certificate signals
    collector = CertCollector(target_org=target)
    signals = await collector.collect()

    print(f"\n📜 Collected {len(signals)} certificate signals")

    # Step 2: Show interesting findings
    print("\n🔍 High/Critical sensitivity findings:")
    interesting = [s for s in signals if s.sensitivity in ["high", "critical"]]
    for s in interesting:
        print(f"  [{s.sensitivity.upper()}] {s.metadata.get('domain')}")
        print(f"    Reason: {s.sensitivity_reason}")

    # Step 3: Write to Neo4j
    print(f"\n📥 Writing {len(signals)} signals to Neo4j...")
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        for signal in signals:
            ingestion.ingest_signal(signal)

    print(f"\n✅ Done. Check Neo4j at http://localhost:7474")
    print("   Run: MATCH (n) RETURN n LIMIT 200")


if __name__ == "__main__":
    asyncio.run(run())