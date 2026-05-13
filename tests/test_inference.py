import sys
import os
import asyncio
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from collectors.orchestrator import CollectionOrchestrator
from processors.pipeline import NLPPipeline
from inference.engine import InferenceEngine
from inference.reporter import print_report


async def run():
    target = "hackerone.com"

    # Step 1: Collect
    print("🔍 Step 1: Collecting OSINT signals...")
    orchestrator = CollectionOrchestrator(target_org=target)
    signals = await orchestrator.run()

    # Step 2: NLP
    print("\n🧠 Step 2: Running NLP pipeline...")
    pipeline = NLPPipeline()
    pipeline.process_and_store(signals)

    # Step 3: Inference
    print("\n🤖 Step 3: Running inference engine...")
    print("   (This takes 30-60 seconds — LLM is reasoning...)\n")
    engine = InferenceEngine(model="llama3.1:8b")
    report = engine.analyze(target)

    # Step 4: Print report
    print_report(report)


if __name__ == "__main__":
    asyncio.run(run())