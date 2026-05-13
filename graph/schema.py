from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime
import uuid


class SourceType(str, Enum):
    DNS         = "dns"
    CERTIFICATE = "certificate"
    GITHUB      = "github"
    SHODAN      = "shodan"
    WEB         = "web"
    JOB_POSTING = "job_posting"


class SensitivityLevel(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class Entity(BaseModel):
    """
    A named entity extracted from a signal.
    source_count tracks how many independent sources confirm this entity.
    confidence reflects extraction certainty (0.0 to 1.0).
    """
    name:         str
    entity_type:  str
    confidence:   float = 1.0
    context:      str   = ""
    source_count: int   = 1       # incremented on deduplication
    sources:      List[str] = []  # which source_types confirmed this


class Signal(BaseModel):
    """
    The universal data object that flows through all layers.
    Every collector produces this. Every processor enriches this.
    """
    # Identity
    id:         str = Field(default_factory=lambda: str(uuid.uuid4()))
    target_org: str

    # Source
    source_type:  SourceType
    source_url:   Optional[str]      = None
    collected_at: datetime           = Field(default_factory=datetime.utcnow)

    # Content
    raw_content: str

    # Entities — populated by extractors, not spaCy for structured data
    entities: List[Entity] = []

    # Sensitivity
    sensitivity:        Optional[SensitivityLevel] = None
    sensitivity_reason: Optional[str]              = None

    # Embedding — populated by embedder
    embedding: Optional[List[float]] = None

    # Metadata — source-specific structured fields
    metadata: Dict[str, Any] = {}

    class Config:
        use_enum_values = True


class CorrelatedEntity(BaseModel):
    """
    An entity confirmed by multiple independent sources.
    Output of the Correlation Engine.
    Used as input to the Inference Engine.
    """
    name:          str
    entity_type:   str
    source_count:  int
    sources:       List[str]          # e.g. ["dns", "certificate", "shodan"]
    confidence:    float              # 0.0 to 1.0
    signals:       List[str]          # signal IDs that reference this entity
    sensitivity:   str                = "medium"
    notes:         List[str]          = []  # human-readable observations


class ConfirmedHost(BaseModel):
    """
    A host confirmed by one or more collectors. Used by the correlation
    engine to represent cross-source hostname findings with metadata.
    """
    hostname:     str
    source_count: int
    sources:      List[str]
    ip_addresses: List[str] = []
    open_ports:   List[int] = []
    technologies: List[str] = []
    sensitivity:  str       = "medium"
    risk_reasons: List[str] = []
    confidence:   float     = 0.5


class PersonProfile(BaseModel):
    """
    A person identified across sources — GitHub, emails, WHOIS contacts.
    """
    name:         str
    email:        Optional[str] = None
    github_user:  Optional[str] = None
    repos:        List[str]     = []
    source_count: int           = 1
    sources:      List[str]     = []


class AttackSurface(BaseModel):
    """
    Full attack surface for a target organization, built by the
    correlation engine from the Neo4j knowledge graph.

    This is the single authoritative AttackSurface definition in the
    codebase. Previous versions existed as a dataclass inside
    intelligence/correlation.py — those have been removed to eliminate
    schema drift between the correlation engine and the API layer.
    """
    target_org:       str
    confirmed_hosts:  List[ConfirmedHost] = []
    sensitive_hosts:  List[ConfirmedHost] = []
    technology_stack: List[Dict[str, Any]] = []
    cloud_profile:    Dict[str, Any]       = {}
    people_profiles:  List[PersonProfile]  = []
    saas_services:    List[str]            = []
    exposed_ports:    List[Dict[str, Any]] = []
    cves_found:       List[Dict[str, Any]] = []
    secrets_found:    List[Dict[str, Any]] = []
    risk_score:       int                  = 0
    summary_stats:    Dict[str, int]       = {}
    generated_at:     datetime             = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


class GraphNode(BaseModel):
    node_id:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    label:      str
    properties: Dict[str, Any] = {}


class GraphRelationship(BaseModel):
    from_node_id:      str
    to_node_id:        str
    relationship_type: str
    properties:        Dict[str, Any] = {}