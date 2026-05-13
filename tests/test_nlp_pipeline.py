import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.orchestrator import CollectionOrchestrator
from processors.pipeline import NLPPipeline


async def run():
    # Step 1: Collect signals
    print("🔍 Step 1: Collecting OSINT signals...")
    orchestrator = CollectionOrchestrator(target_org="hackerone.com")
    signals = await orchestrator.run()

    # Step 2: Run NLP pipeline
    print("\n🧠 Step 2: Running NLP pipeline...")
    pipeline = NLPPipeline()
    enriched_signals = pipeline.process_and_store(signals)

    # Step 3: Demo semantic search
    print("\n🔎 Step 3: Semantic similarity search demo...")
    query = "cloud infrastructure and kubernetes deployment"
    similar = pipeline.embedder.find_similar(
        query=query,
        signals=enriched_signals,
        top_k=3
    )

    print(f"\n  Query: '{query}'")
    print(f"  Top 3 most semantically similar signals:")
    for i, s in enumerate(similar, 1):
        print(f"\n  {i}. [{s.source_type}] [{s.sensitivity}]")
        print(f"     {s.raw_content[:120]}")

    print(f"\n🏁 Milestone 2 complete.")
    print(f"   {len(enriched_signals)} signals collected, enriched, and stored.")


if __name__ == "__main__":
    asyncio.run(run())