import asyncio
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List
from graph.schema import Signal
from graph.ingestion import Neo4jConnection, SignalIngestion
from collectors.dns import DNSCollector
from collectors.cert import CertCollector
from collectors.googledork import GoogleDorkCollector
from collectors.github import GitHubCollector
from collectors.whois import WHOISCollector
from collectors.shodan import ShodanCollector
from collectors.wayback import WaybackCollector


class CollectionOrchestrator:
    """
    Runs all collectors for a target organization.
    Async collectors run in parallel.
    Sync collectors run in a thread pool.
    All signals ingested into Neo4j in one pass.
    """

    def __init__(self, target_org: str):
        self.target_org  = target_org
        self.all_signals: List[Signal] = []

    async def run(self) -> List[Signal]:
        """Run all collectors and ingest results."""
        logger.info(
            f"🚀 Starting full collection pipeline for: {self.target_org}"
        )

        # ── Async collectors (run in parallel) ───────────────────────
        async_results = await asyncio.gather(
            DNSCollector(self.target_org).collect(),
            CertCollector(self.target_org).collect(),
            WaybackCollector(self.target_org).collect(),
            GitHubCollector(self.target_org).collect(),
            #GoogleDorkCollector(self.target_org).collect(),
            return_exceptions=True
        )

        async_names = ["DNS", "Certificate", "Wayback", "GitHub"]
        for name, result in zip(async_names, async_results):
            if isinstance(result, Exception):
                logger.error(f"  ❌ {name} collector failed: {result}")
            else:
                logger.success(f"  ✅ {name}: {len(result)} signals")
                self.all_signals.extend(result)

        # ── Sync collectors (run sequentially) ───────────────────────
        sync_collectors = [
            ("WHOIS",  WHOISCollector(self.target_org).collect),
            ("Shodan", ShodanCollector(self.target_org).collect),
        ]

        for name, collector_fn in sync_collectors:
            try:
                results = await asyncio.get_event_loop().run_in_executor(
                    None, collector_fn
                )
                logger.success(f"  ✅ {name}: {len(results)} signals")
                self.all_signals.extend(results)
            except Exception as e:
                logger.error(f"  ❌ {name} collector failed: {e}")

        logger.info(
            f"\n📊 Total signals collected: {len(self.all_signals)}"
        )
        self._print_summary()
        self._ingest_all()

        return self.all_signals

    def _ingest_all(self):
        """Write all signals to Neo4j."""
        logger.info(
            f"\n📥 Ingesting {len(self.all_signals)} signals into Neo4j..."
        )
        with Neo4jConnection() as conn:
            ingestion = SignalIngestion(conn)
            for signal in self.all_signals:
                ingestion.ingest_signal(signal)
        logger.success("✅ All signals ingested into Neo4j")

    def _print_summary(self):
        """Print a clean collection summary."""
        by_source = {}
        for signal in self.all_signals:
            src = signal.source_type
            by_source[src] = by_source.get(src, 0) + 1

        by_sensitivity = {}
        for signal in self.all_signals:
            s = signal.sensitivity or "unknown"
            by_sensitivity[s] = by_sensitivity.get(s, 0) + 1

        all_entities = {}
        for signal in self.all_signals:
            for entity in signal.entities:
                all_entities[entity.entity_type] = \
                    all_entities.get(entity.entity_type, 0) + 1

        print("\n" + "=" * 55)
        print(f"  ChaturDrishti — Collection Report")
        print(f"  Target: {self.target_org}")
        print("=" * 55)

        print("\n📡 Signals by source:")
        for src, count in sorted(
            by_source.items(), key=lambda x: x[1], reverse=True
        ):
            print(f"   {src:<22} {count} signals")

        print("\n🎯 Signals by sensitivity:")
        icons = {
            "critical": "🔴", "high": "🟠",
            "medium":   "🟡", "low":  "🟢"
        }
        for level in ["critical", "high", "medium", "low", "unknown"]:
            count = by_sensitivity.get(level, 0)
            if count:
                icon = icons.get(level, "⚪")
                print(f"   {icon} {level:<15} {count} signals")

        print("\n🧩 Top entity types:")
        for entity_type, count in sorted(
            all_entities.items(), key=lambda x: x[1], reverse=True
        )[:10]:
            print(f"   {entity_type:<28} {count}")

        print("=" * 55)