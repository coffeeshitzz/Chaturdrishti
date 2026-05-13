import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.whois import WHOISCollector
from graph.ingestion import Neo4jConnection, SignalIngestion
from loguru import logger


def run():
    target = "hackerone.com"

    collector = WHOISCollector(target_org=target)
    signals = collector.collect()

    print(f"\n📋 WHOIS — {len(signals)} signals")
    for s in signals:
        print(f"\n  [{s.sensitivity.upper()}] {s.raw_content[:100]}")
        print(f"  Reason: {s.sensitivity_reason}")
        if s.entities:
            print(f"  Entities: {[e.name for e in s.entities]}")

    print(f"\n📥 Writing to Neo4j...")
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        for signal in signals:
            ingestion.ingest_signal(signal)

    print(f"✅ Done.")


if __name__ == "__main__":
    run()