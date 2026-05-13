from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime


class AnalyzeRequest(BaseModel):
    """Request body for starting an analysis."""
    target_org: str
    run_collectors: bool = True
    run_nlp: bool = True
    run_inference: bool = True


class FindingResponse(BaseModel):
    """A single inference finding."""
    title: str
    inference: str
    evidence: List[str]
    attacker_value: str
    risk_level: str
    mitigations: List[str]


# ─────────────────────────────────────────────────────────────────────────────
# Attack surface response models — mirror the correlation engine's output
# so the dashboard can render confirmed hosts, sensitive hosts, tech stack,
# people, exposed ports, and CVEs alongside the LLM findings.
# ─────────────────────────────────────────────────────────────────────────────

class ConfirmedHostResponse(BaseModel):
    hostname:     str
    source_count: int
    sources:      List[str]
    ip_addresses: List[str] = []
    open_ports:   List[int] = []
    technologies: List[str] = []
    sensitivity:  str       = "medium"
    risk_reasons: List[str] = []
    confidence:   float     = 0.5


class PersonProfileResponse(BaseModel):
    name:         str
    email:        Optional[str] = None
    github_user:  Optional[str] = None
    repos:        List[str]     = []
    source_count: int           = 1
    sources:      List[str]     = []


class AttackSurfaceResponse(BaseModel):
    """Full attack surface from the correlation engine."""
    confirmed_hosts:  List[ConfirmedHostResponse]  = []
    sensitive_hosts:  List[ConfirmedHostResponse]  = []
    technology_stack: List[Dict[str, Any]]         = []
    cloud_profile:    Dict[str, Any]               = {}
    people_profiles:  List[PersonProfileResponse]  = []
    saas_services:    List[str]                    = []
    exposed_ports:    List[Dict[str, Any]]         = []
    cves_found:       List[Dict[str, Any]]         = []
    secrets_found:    List[Dict[str, Any]]         = []
    correlation_risk_score: int                    = 0
    summary_stats:    Dict[str, int]               = {}


class ReportResponse(BaseModel):
    """Full inference + correlation report response."""
    target_org:     str
    summary:        str
    findings:       List[FindingResponse]
    total_signals:  int
    risk_score:     int
    attack_surface: Optional[AttackSurfaceResponse] = None
    generated_at:   datetime = Field(default_factory=datetime.utcnow)


class GraphNode(BaseModel):
    id: str
    label: str
    properties: Dict[str, Any]


class GraphEdge(BaseModel):
    source: str
    target: str
    relationship: str


class GraphResponse(BaseModel):
    target_org: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_nodes: int
    total_edges: int


class HealthResponse(BaseModel):
    status: str
    neo4j: str
    ollama: str