export interface Finding {
  title: string;
  inference: string;
  evidence: string[];
  attacker_value: string;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  mitigations: string[];
}

export interface ConfirmedHost {
  hostname: string;
  source_count: number;
  sources: string[];
  ip_addresses: string[];
  open_ports: number[];
  technologies: string[];
  sensitivity: string;
  risk_reasons: string[];
  confidence: number;
}

export interface PersonProfile {
  name: string;
  email: string | null;
  github_user: string | null;
  repos: string[];
  source_count: number;
  sources: string[];
}

export interface AttackSurface {
  confirmed_hosts: ConfirmedHost[];
  sensitive_hosts: ConfirmedHost[];
  technology_stack: Record<string, any>[];
  cloud_profile: Record<string, any>;
  people_profiles: PersonProfile[];
  saas_services: string[];
  exposed_ports: Record<string, any>[];
  cves_found: Record<string, any>[];
  secrets_found: Record<string, any>[];
  correlation_risk_score: number;
  summary_stats: Record<string, number>;
}

export interface Report {
  target_org: string;
  summary: string;
  findings: Finding[];
  total_signals: number;
  risk_score: number;
  attack_surface: AttackSurface | null;
  generated_at: string;
}

export interface GraphNode {
  id: string;
  label: string;
  properties: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
}

export interface GraphData {
  target_org: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
  total_nodes: number;
  total_edges: number;
}