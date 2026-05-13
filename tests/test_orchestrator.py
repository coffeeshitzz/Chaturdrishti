import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.orchestrator import CollectionOrchestrator


async def run():
    orchestrator = CollectionOrchestrator(target_org="hackerone.com")
    signals = await orchestrator.run()

    print(f"\n🏁 Pipeline complete.")
    print(f"   Total signals in Neo4j: {len(signals)}")
    print(f"   Open http://localhost:7474 and run:")
    print(f'   MATCH (n) RETURN n LIMIT 200')


if __name__ == "__main__":
    asyncio.run(run())