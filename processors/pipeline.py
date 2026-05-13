import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from graph.schema import Signal
from processors.entity_extractor import EntityExtractor
from processors.sensitivity_classifier import SensitivityClassifier
from processors.embedder import SignalEmbedder
from graph.ingestion import Neo4jConnection, SignalIngestion


class NLPPipeline:
    """
    Orchestrates signal processing:
    1. Entity extraction (source-aware, no spaCy noise)
    2. Sensitivity classification
    3. Semantic embedding
    4. Storage to Neo4j
    """

    def __init__(self):
        self.extractor  = EntityExtractor()
        self.classifier = SensitivityClassifier()
        self.embedder   = SignalEmbedder()

    def process(self, signals: List[Signal]) -> List[Signal]:
        logger.info(f"🧠 Processing {len(signals)} signals...")

        # Step 1 — entity extraction (source-aware)
        logger.info("  Step 1/3: Entity extraction...")
        signals = self.extractor.extract_batch(signals)

        # Step 2 — sensitivity classification
        logger.info("  Step 2/3: Sensitivity classification...")
        signals = self.classifier.classify_batch(signals)

        # Step 3 — semantic embedding
        logger.info("  Step 3/3: Semantic embedding...")
        signals = self.embedder.embed_batch(signals)

        logger.success(f"✅ Processing complete")
        self._print_summary(signals)
        return signals

    def process_and_store(self, signals: List[Signal]) -> List[Signal]:
        signals = self.process(signals)
        logger.info("📥 Storing to Neo4j...")
        with Neo4jConnection() as conn:
            ingestion = SignalIngestion(conn)
            for signal in signals:
                ingestion.ingest_signal(signal)
        logger.success("✅ Stored")
        return signals

    def _print_summary(self, signals: List[Signal]):
        total_entities = sum(len(s.entities) for s in signals)
        by_sensitivity = {}
        for s in signals:
            lvl = s.sensitivity or "unknown"
            by_sensitivity[lvl] = by_sensitivity.get(lvl, 0) + 1

        print("\n" + "="*50)
        print("  Processing Report")
        print("="*50)
        print(f"  Signals:  {len(signals)}")
        print(f"  Entities: {total_entities}")
        print(f"  Avg entities/signal: {total_entities/max(len(signals),1):.1f}")
        print("\n  Sensitivity:")
        for level in ["critical", "high", "medium", "low", "unknown"]:
            count = by_sensitivity.get(level, 0)
            if count:
                icons = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🟢"}
                print(f"    {icons.get(level,'⚪')} {level:<10} {count}")
        print("="*50)