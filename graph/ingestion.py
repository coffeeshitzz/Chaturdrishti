from neo4j import GraphDatabase
from loguru import logger
import os
from dotenv import load_dotenv
from graph.schema import Signal, Entity

load_dotenv()


class Neo4jConnection:

    def __init__(self):
        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASSWORD", "chaturdrishti123")
        self._driver = None

    def connect(self):
        try:
            self._driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password)
            )
            self._driver.verify_connectivity()
            logger.success("✅ Connected to Neo4j successfully")
        except Exception as e:
            logger.error(f"❌ Failed to connect to Neo4j: {e}")
            raise

    def close(self):
        if self._driver:
            self._driver.close()
            logger.info("Neo4j connection closed")

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def run(self, query: str, parameters: dict = {}):
        with self._driver.session() as session:
            result = session.run(query, parameters)
            return list(result)


class SignalIngestion:

    def __init__(self, connection: Neo4jConnection):
        self.conn = connection

    def ingest_signal(self, signal: Signal):
        logger.info(f"Ingesting signal [{signal.source_type}] for {signal.target_org}")
        self._create_organization_node(signal.target_org)
        self._create_signal_node(signal)
        self._link_signal_to_org(signal)
        for entity in signal.entities:
            self._create_entity_node(entity, signal)
        logger.success(f"✅ Signal {signal.id[:8]}... ingested successfully")

    def _create_organization_node(self, target_org: str):
        query = """
        MERGE (o:Organization {domain: $domain})
        ON CREATE SET o.created_at = timestamp()
        RETURN o
        """
        self.conn.run(query, {"domain": target_org})

    def _create_signal_node(self, signal: Signal):
        query = """
        MERGE (s:Signal {id: $id})
        ON CREATE SET
            s.target_org         = $target_org,
            s.source_type        = $source_type,
            s.source_url         = $source_url,
            s.raw_content        = $raw_content,
            s.sensitivity        = $sensitivity,
            s.sensitivity_reason = $sensitivity_reason,
            s.collected_at       = $collected_at
        RETURN s
        """
        self.conn.run(query, {
            "id":                 signal.id,
            "target_org":         signal.target_org,
            "source_type":        signal.source_type,
            "source_url":         signal.source_url or "",
            "raw_content":        signal.raw_content,
            "sensitivity":        signal.sensitivity or "unknown",
            "sensitivity_reason": signal.sensitivity_reason or "",
            "collected_at":       signal.collected_at.isoformat()
        })

    def _link_signal_to_org(self, signal: Signal):
        query = """
        MATCH (o:Organization {domain: $domain})
        MATCH (s:Signal {id: $signal_id})
        MERGE (s)-[:COLLECTED_FROM {source_type: $source_type}]->(o)
        """
        self.conn.run(query, {
            "domain":      signal.target_org,
            "signal_id":   signal.id,
            "source_type": signal.source_type
        })

    def _create_entity_node(self, entity: Entity, signal: Signal):
        """
        MERGE an entity node, correctly accumulating sources across
        multiple collectors that reference the same entity.

        - ON CREATE: initialize sources list with this signal's source_type
        - ON MATCH: append source_type to sources list if not already present
        - After either branch: recalculate source_count from the list length

        This is the single place where cross-source confirmation count gets
        computed. The correlation engine reads e.sources and e.source_count
        from here.
        """
        query = """
        MERGE (e:Entity {name: $name, entity_type: $entity_type})
        ON CREATE SET
            e.confidence   = $confidence,
            e.sources      = [$source_type],
            e.source_count = 1,
            e.created_at   = timestamp()
        ON MATCH SET
            e.sources = CASE
                WHEN $source_type IN coalesce(e.sources, [])
                    THEN e.sources
                ELSE coalesce(e.sources, []) + $source_type
            END,
            e.confidence = CASE
                WHEN $confidence > coalesce(e.confidence, 0.0)
                    THEN $confidence
                ELSE e.confidence
            END
        SET e.source_count = size(e.sources)
        WITH e
        MATCH (s:Signal {id: $signal_id})
        MERGE (s)-[:CONTAINS_ENTITY]->(e)
        WITH e
        MATCH (o:Organization {domain: $domain})
        MERGE (o)-[:EXPOSES]->(e)
        """
        self.conn.run(query, {
            "name":        entity.name,
            "entity_type": entity.entity_type,
            "confidence":  entity.confidence,
            "source_type": signal.source_type if isinstance(signal.source_type, str)
                        else signal.source_type.value,
            "signal_id":   signal.id,
            "domain":      signal.target_org,
        })