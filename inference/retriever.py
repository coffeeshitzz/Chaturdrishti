import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from loguru import logger
from typing import List, Dict, Any
from graph.ingestion import Neo4jConnection


class SignalRetriever:

    def __init__(self, connection: Neo4jConnection):
        self.conn = connection

    def get_all_signals(self, target_org: str) -> List[Dict]:
        query = """
        MATCH (s:Signal {target_org: $target_org})
        RETURN s
        ORDER BY s.collected_at DESC
        """
        result = self.conn.run(query, {"target_org": target_org})
        return [dict(record["s"]) for record in result]

    def get_high_sensitivity_signals(self, target_org: str) -> List[Dict]:
        query = """
        MATCH (s:Signal {target_org: $target_org})
        WHERE s.sensitivity IN ['critical', 'high']
        RETURN DISTINCT s
        ORDER BY s.collected_at DESC
        """
        result = self.conn.run(query, {"target_org": target_org})
        return [dict(record["s"]) for record in result]

    def get_entities_by_type(
        self,
        target_org: str,
        entity_types: List[str]
    ) -> List[Dict]:
        query = """
        MATCH (o:Organization {domain: $target_org})-[:EXPOSES]->(e:Entity)
        WHERE e.entity_type IN $entity_types
        RETURN e
        """
        result = self.conn.run(query, {
            "target_org":   target_org,
            "entity_types": entity_types
        })
        return [dict(record["e"]) for record in result]

    def get_full_context(self, target_org: str) -> Dict[str, Any]:
        high_signals = self.get_high_sensitivity_signals(target_org)

        technologies = self.get_entities_by_type(
            target_org,
            ["TECHNOLOGY", "KUBERNETES", "DOCKER", "TERRAFORM",
             "AWS", "GCP", "AZURE", "FASTAPI", "DJANGO", "REACT",
             "POSTGRESQL", "REDIS", "KAFKA", "ISTIO"]
        )

        hostnames = self.get_entities_by_type(
            target_org,
            ["HOSTNAME"]
        )

        people = self.get_entities_by_type(
            target_org,
            ["PERSON", "GITHUB_USER", "EMAIL_ADDRESS"]
        )

        repos = self.get_entities_by_type(
            target_org,
            ["GITHUB_REPOSITORY"]
        )

        return {
            "target_org":   target_org,
            "high_signals": high_signals,
            "technologies": technologies,
            "hostnames":    hostnames,
            "people":       people,
            "repositories": repos,
        }