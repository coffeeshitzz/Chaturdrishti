import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.github import GitHubCollector
from graph.ingestion import Neo4jConnection, SignalIngestion
from loguru import logger


async def run():
    target = "hackerone.com"

    # Step 1: Collect GitHub signals
    collector = GitHubCollector(target_org=target)
    signals = await collector.collect()

    print(f"\n📁 Collected {len(signals)} GitHub signals")

    # Step 2: Show findings by sensitivity
    for level in ["critical", "high", "medium"]:
        found = [s for s in signals if s.sensitivity == level]
        if found:
            print(f"\n🔍 {level.upper()} findings ({len(found)}):")
            for s in found:
                print(f"  → {s.raw_content[:100]}")
                print(f"     Reason: {s.sensitivity_reason}")

    # Step 3: Show all unique technologies detected
    tech_types = [
        "KUBERNETES", "DOCKER", "TERRAFORM", "AWS", "GCP", "AZURE",
        "POSTGRESQL", "REDIS", "FASTAPI", "DJANGO", "REACT",
        "GITHUB_ACTIONS", "DATADOG", "GRAFANA", "ISTIO", "KAFKA"
    ]
    detected_techs = set()
    for signal in signals:
        for entity in signal.entities:
            if entity.entity_type in tech_types:
                detected_techs.add(entity.name)

    if detected_techs:
        print(f"\n🛠️  Technologies detected: {', '.join(detected_techs)}")

    # Step 4: Write to Neo4j
    print(f"\n📥 Writing signals to Neo4j...")
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        for signal in signals:
            ingestion.ingest_signal(signal)

    print(f"\n✅ Done. Check your graph at http://localhost:7474")
    print("\nRun this Cypher query to see the full picture:")
    print("""
    MATCH (o:Organization {domain: "hackerone.com"})-[:EXPOSES]->(e:Entity)
    RETURN o, e
    LIMIT 200
    """)


if __name__ == "__main__":
    asyncio.run(run())