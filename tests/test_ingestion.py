import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from graph.schema import Signal, SourceType, Entity, SensitivityLevel
from graph.ingestion import Neo4jConnection, SignalIngestion


def test_ingest_signal():
    # Create a sample signal (simulating DNS collector output)
    signal = Signal(
        target_org="acme.com",
        source_type=SourceType.DNS,
        source_url="https://crt.sh/?q=acme.com",
        raw_content="Subdomain found: staging.acme.com → 192.168.1.10",
        sensitivity=SensitivityLevel.MEDIUM,
        sensitivity_reason="Staging subdomain publicly exposed",
        entities=[
            Entity(
                name="staging.acme.com",
                entity_type="HOSTNAME",
                confidence=0.99,
                context="Subdomain found: staging.acme.com"
            ),
            Entity(
                name="192.168.1.10",
                entity_type="IP_ADDRESS",
                confidence=0.99,
                context="staging.acme.com → 192.168.1.10"
            )
        ],
        metadata={
            "subdomain": "staging.acme.com",
            "ip": "192.168.1.10",
            "record_type": "A"
        }
    )

    # Write to Neo4j
    with Neo4jConnection() as conn:
        ingestion = SignalIngestion(conn)
        ingestion.ingest_signal(signal)
        print("\n✅ Signal written to Neo4j successfully")
        print(f"   Signal ID: {signal.id}")
        print(f"   Target:    {signal.target_org}")
        print(f"   Entities:  {[e.name for e in signal.entities]}")


if __name__ == "__main__":
    test_ingest_signal()