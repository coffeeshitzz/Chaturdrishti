from graph.schema import Signal, SourceType, Entity, SensitivityLevel
from datetime import datetime

def test_signal_creation():
    # Simulate what a DNS collector will produce
    signal = Signal(
        target_org="acme.com",
        source_type=SourceType.DNS,
        source_url="https://dns.google/resolve?name=acme.com",
        raw_content="Subdomain found: staging.acme.com → 192.168.1.10",
        metadata={
            "subdomain": "staging.acme.com",
            "ip": "192.168.1.10",
            "record_type": "A"
        }
    )

    # Simulate what NLP layer will add later
    signal.entities = [
        Entity(
            name="staging.acme.com",
            entity_type="HOSTNAME",
            confidence=0.99,
            context="Subdomain found: staging.acme.com → 192.168.1.10"
        )
    ]
    signal.sensitivity = SensitivityLevel.MEDIUM
    signal.sensitivity_reason = "Staging subdomain publicly exposed"

    print("\n✅ Signal created successfully:")
    print(signal.model_dump_json(indent=2))

if __name__ == "__main__":
    test_signal_creation()