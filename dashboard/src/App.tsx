import React, { useState } from 'react';
import { analyzeTarget, getGraph } from './api';
import { Report, GraphData } from './types';
import FindingCard from './components/FindingCard';
import RiskMeter from './components/RiskMeter';
import GraphView from './components/GraphView';
import { Search, Shield, Activity, GitBranch, Loader } from 'lucide-react';

type View = 'home' | 'report' | 'graph';

const App: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [view, setView] = useState<View>('home');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [error, setError] = useState('');
  const [activeTab, setActiveTab] = useState<'report' | 'graph'>('report');

  const handleAnalyze = async () => {
    if (!domain.trim()) return;
    setLoading(true);
    setError('');
    setReport(null);
    setGraphData(null);

    try {
      const reportResult = await analyzeTarget(domain.trim());
      setReport(reportResult);

      try {
        const graphResult = await getGraph(domain.trim());
        setGraphData(graphResult);
      } catch (graphErr) {
        console.warn('Graph data unavailable:', graphErr);
        setGraphData(null);
      }

      setView('report');
      setActiveTab('report');
    } catch (err: any) {
      setError(
        err.response?.data?.detail ||
        'Analysis failed. Make sure the API is running on port 8000.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0a0e1a' }}>

      {/* Header */}
      <header style={{
        borderBottom: '1px solid #1e2a3a',
        padding: '16px 32px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Shield size={24} color="#60a5fa" />
          <span style={{
            fontSize: '18px',
            fontWeight: 700,
            letterSpacing: '0.05em'
          }}>
            Chatur<span style={{ color: '#60a5fa' }}>Drishti</span>
          </span>
        </div>
        {report && (
          <div style={{ display: 'flex', gap: '8px' }}>
            <TabButton
              active={activeTab === 'report'}
              onClick={() => setActiveTab('report')}
              icon={<Activity size={14} />}
              label="Report"
            />
            <TabButton
              active={activeTab === 'graph'}
              onClick={() => setActiveTab('graph')}
              icon={<GitBranch size={14} />}
              label="Graph (Beta)"
            />
          </div>
        )}
      </header>

      <main style={{ maxWidth: '900px', margin: '0 auto', padding: '32px 24px' }}>

        {/* Search Bar */}
        <div style={{
          display: 'flex',
          gap: '12px',
          marginBottom: '32px'
        }}>
          <div style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            backgroundColor: '#0f1624',
            border: '1px solid #1e2a3a',
            borderRadius: '8px',
            padding: '12px 16px'
          }}>
            <Search size={16} color="#4a5568" />
            <input
              value={domain}
              onChange={e => setDomain(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleAnalyze()}
              placeholder="Enter target domain (e.g. hackerone.com)"
              disabled={loading}
              style={{
                flex: 1,
                background: 'none',
                border: 'none',
                outline: 'none',
                color: '#e2e8f0',
                fontSize: '15px'
              }}
            />
          </div>
          <button
            onClick={handleAnalyze}
            disabled={loading || !domain.trim()}
            style={{
              padding: '12px 24px',
              backgroundColor: loading ? '#1e2a3a' : '#2563eb',
              color: loading ? '#4a5568' : '#fff',
              border: 'none',
              borderRadius: '8px',
              fontSize: '14px',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              transition: 'background-color 0.2s'
            }}
          >
            {loading
              ? <><Loader size={14} /> Analyzing...</>
              : 'Analyze'
            }
          </button>
        </div>

        {/* Error */}
        {error && (
          <div style={{
            padding: '12px 16px',
            backgroundColor: '#1a0f0f',
            border: '1px solid #3a1a1a',
            borderRadius: '8px',
            color: '#fc8181',
            marginBottom: '24px',
            fontSize: '14px'
          }}>
            ⚠️ {error}
          </div>
        )}

        {/* Loading State */}
        {loading && (
          <div style={{ textAlign: 'center', padding: '60px 0' }}>
            <div style={{ fontSize: '40px', marginBottom: '20px' }}>🔍</div>
            <p style={{
              color: '#60a5fa',
              fontSize: '16px',
              fontWeight: 600,
              marginBottom: '8px'
            }}>
              Analyzing {domain}...
            </p>
            <p style={{ color: '#4a5568', fontSize: '13px', marginBottom: '4px' }}>
              Step 1: Collecting OSINT signals from DNS, certificates, GitHub
            </p>
            <p style={{ color: '#4a5568', fontSize: '13px', marginBottom: '4px' }}>
              Step 2: Running NLP pipeline and knowledge graph ingestion
            </p>
            <p style={{ color: '#4a5568', fontSize: '13px', marginBottom: '24px' }}>
              Step 3: LLM generating attacker inference chains
            </p>
            <p style={{ color: '#2d3748', fontSize: '12px' }}>
              This takes 2–4 minutes. Please wait.
            </p>
          </div>
        )}

        {/* Home State */}
        {!loading && !report && !error && (
          <div style={{ textAlign: 'center', padding: '60px 0' }}>
            <Shield
              size={56}
              color="#1e2a3a"
              style={{ margin: '0 auto 20px', display: 'block' }}
            />
            <h1 style={{
              fontSize: '28px',
              fontWeight: 700,
              marginBottom: '12px',
              color: '#e2e8f0'
            }}>
              OSINT Exposure Analysis
            </h1>
            <p style={{
              color: '#4a5568',
              fontSize: '15px',
              maxWidth: '500px',
              margin: '0 auto 32px',
              lineHeight: '1.7'
            }}>
              Enter a target domain to analyze its public reconnaissance
              footprint. ChaturDrishti collects signals from DNS, certificate
              logs, and GitHub, then uses LLM reasoning to simulate attacker
              inference chains.
            </p>
            <div style={{
              display: 'flex',
              justifyContent: 'center',
              gap: '32px',
              flexWrap: 'wrap'
            }}>
              {[
                { icon: '🌐', label: 'DNS Enumeration' },
                { icon: '📜', label: 'Certificate Logs' },
                { icon: '🐙', label: 'GitHub OSINT' },
                { icon: '🤖', label: 'LLM Inference' },
              ].map(item => (
                <div key={item.label} style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '8px'
                }}>
                  <span style={{ fontSize: '24px' }}>{item.icon}</span>
                  <span style={{ color: '#4a5568', fontSize: '12px' }}>
                    {item.label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Report View */}
        {!loading && report && activeTab === 'report' && (
          <div>
            {/* Summary Card */}
            <div style={{
              backgroundColor: '#0f1624',
              border: '1px solid #1e2a3a',
              borderRadius: '8px',
              padding: '24px',
              marginBottom: '24px'
            }}>
              <div style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'flex-start',
                marginBottom: '20px',
                flexWrap: 'wrap',
                gap: '8px'
              }}>
                <div>
                  <h2 style={{
                    fontSize: '22px',
                    fontWeight: 700,
                    color: '#e2e8f0'
                  }}>
                    {report.target_org}
                  </h2>
                  <p style={{
                    color: '#4a5568',
                    fontSize: '12px',
                    marginTop: '4px'
                  }}>
                    {report.total_signals} signals analyzed
                    · {report.findings.length} findings
                    · {new Date(report.generated_at).toLocaleString()}
                  </p>
                </div>
              </div>
              <RiskMeter score={report.risk_score} />
              <p style={{
                color: '#94a3b8',
                fontSize: '14px',
                lineHeight: '1.7',
                marginTop: '16px'
              }}>
                {report.summary}
              </p>
            </div>

            {/* Attack Surface — from correlation engine */}
            {report.attack_surface && (
              <div style={{ marginBottom: '24px' }}>
                <h3 style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: '#4a5568',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  marginBottom: '12px'
                }}>
                  Attack Surface
                </h3>

                {/* Sensitive Hosts */}
                {report.attack_surface.sensitive_hosts.length > 0 && (
                  <SurfaceSection
                    label={`Sensitive Hosts (${report.attack_surface.sensitive_hosts.length})`}
                    accent="#fc8181"
                  >
                    {report.attack_surface.sensitive_hosts.map((h, i) => (
                      <div key={i} style={{
                        padding: '10px 12px',
                        borderBottom: '1px solid #1e2a3a',
                        fontSize: '13px'
                      }}>
                        <div style={{ color: '#e2e8f0', fontFamily: 'monospace' }}>
                          {h.hostname}
                          {h.ip_addresses.length > 0 && (
                            <span style={{ color: '#4a5568', marginLeft: '8px' }}>
                              → {h.ip_addresses.join(', ')}
                            </span>
                          )}
                        </div>
                        {h.risk_reasons.length > 0 && (
                          <div style={{
                            color: '#94a3b8',
                            fontSize: '11px',
                            marginTop: '4px'
                          }}>
                            {h.risk_reasons.join(' · ')}
                          </div>
                        )}
                        <div style={{
                          color: '#4a5568',
                          fontSize: '11px',
                          marginTop: '4px'
                        }}>
                          confirmed by {h.source_count} source{h.source_count !== 1 ? 's' : ''}: {h.sources.join(', ')}
                        </div>
                      </div>
                    ))}
                  </SurfaceSection>
                )}

                {/* Confirmed Hosts */}
                {report.attack_surface.confirmed_hosts.length > 0 && (
                  <SurfaceSection
                    label={`Cross-Source Confirmed Hosts (${report.attack_surface.confirmed_hosts.length})`}
                    accent="#60a5fa"
                  >
                    {report.attack_surface.confirmed_hosts.map((h, i) => (
                      <div key={i} style={{
                        padding: '10px 12px',
                        borderBottom: '1px solid #1e2a3a',
                        fontSize: '13px',
                        color: '#e2e8f0',
                        fontFamily: 'monospace'
                      }}>
                        {h.hostname}
                        <span style={{
                          color: '#4a5568',
                          marginLeft: '8px',
                          fontFamily: 'inherit'
                        }}>
                          ({h.source_count} sources)
                        </span>
                      </div>
                    ))}
                  </SurfaceSection>
                )}

                {/* Technology Stack */}
                {report.attack_surface.technology_stack.length > 0 && (
                  <SurfaceSection
                    label={`Technology Stack (${report.attack_surface.technology_stack.length})`}
                    accent="#68d391"
                  >
                    <div style={{
                      padding: '12px',
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '6px'
                    }}>
                      {report.attack_surface.technology_stack.map((t, i) => (
                        <span key={i} style={{
                          padding: '4px 10px',
                          backgroundColor: '#0a1628',
                          border: '1px solid #1e2a3a',
                          borderRadius: '4px',
                          fontSize: '12px',
                          color: '#94a3b8'
                        }}>
                          {t.name || JSON.stringify(t)}
                        </span>
                      ))}
                    </div>
                  </SurfaceSection>
                )}

                {/* People */}
                {report.attack_surface.people_profiles.length > 0 && (
                  <SurfaceSection
                    label={`People Identified (${report.attack_surface.people_profiles.length})`}
                    accent="#b794f4"
                  >
                    {report.attack_surface.people_profiles.slice(0, 10).map((p, i) => (
                      <div key={i} style={{
                        padding: '8px 12px',
                        borderBottom: '1px solid #1e2a3a',
                        fontSize: '13px',
                        color: '#e2e8f0'
                      }}>
                        {p.name}
                        {p.github_user && (
                          <span style={{ color: '#94a3b8', marginLeft: '8px' }}>
                            @{p.github_user}
                          </span>
                        )}
                        {p.email && (
                          <span style={{
                            color: '#4a5568',
                            marginLeft: '8px',
                            fontSize: '11px'
                          }}>
                            {p.email}
                          </span>
                        )}
                      </div>
                    ))}
                    {report.attack_surface.people_profiles.length > 10 && (
                      <div style={{
                        padding: '8px 12px',
                        color: '#4a5568',
                        fontSize: '11px',
                        fontStyle: 'italic'
                      }}>
                        + {report.attack_surface.people_profiles.length - 10} more
                      </div>
                    )}
                  </SurfaceSection>
                )}

                {/* CVEs */}
                {report.attack_surface.cves_found.length > 0 && (
                  <SurfaceSection
                    label={`CVEs Found (${report.attack_surface.cves_found.length})`}
                    accent="#f6ad55"
                  >
                    {report.attack_surface.cves_found.map((c, i) => (
                      <div key={i} style={{
                        padding: '8px 12px',
                        borderBottom: '1px solid #1e2a3a',
                        fontSize: '13px',
                        color: '#e2e8f0',
                        fontFamily: 'monospace'
                      }}>
                        {c.cve_id || JSON.stringify(c)}
                      </div>
                    ))}
                  </SurfaceSection>
                )}

                {/* Secrets */}
                {report.attack_surface.secrets_found.length > 0 && (
                  <SurfaceSection
                    label={`Secrets Detected (${report.attack_surface.secrets_found.length})`}
                    accent="#fc8181"
                  >
                    {report.attack_surface.secrets_found.map((s, i) => (
                      <div key={i} style={{
                        padding: '8px 12px',
                        borderBottom: '1px solid #1e2a3a',
                        fontSize: '13px',
                        color: '#e2e8f0'
                      }}>
                        {s.type || 'secret'}
                        {s.location && (
                          <span style={{
                            color: '#4a5568',
                            marginLeft: '8px',
                            fontSize: '11px'
                          }}>
                            {s.location}
                          </span>
                        )}
                      </div>
                    ))}
                  </SurfaceSection>
                )}
              </div>
            )}

            {/* Findings */}
            {report.findings.length > 0 ? (
              <>
                <h3 style={{
                  fontSize: '13px',
                  fontWeight: 600,
                  color: '#4a5568',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  marginBottom: '12px'
                }}>
                  Findings ({report.findings.length})
                </h3>
                {report.findings.map((finding, i) => (
                  <FindingCard key={i} finding={finding} index={i} />
                ))}
              </>
            ) : (
              <div style={{
                textAlign: 'center',
                padding: '40px',
                color: '#4a5568',
                backgroundColor: '#0f1624',
                borderRadius: '8px',
                border: '1px solid #1e2a3a'
              }}>
                No findings generated. The domain may have minimal
                public exposure.
              </div>
            )}
          </div>
        )}

        {/* Graph View */}
        {!loading && activeTab === 'graph' && (
          <div>
            <div style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              marginBottom: '16px'
            }}>
              <h3 style={{
                fontSize: '13px',
                fontWeight: 600,
                color: '#4a5568',
                textTransform: 'uppercase',
                letterSpacing: '0.08em'
              }}>
                Knowledge Graph (Beta)
              </h3>
              {graphData && (
                <span style={{ color: '#4a5568', fontSize: '12px' }}>
                  {graphData.total_nodes} nodes · {graphData.total_edges} edges
                </span>
              )}
            </div>

            {/* Legend */}
            <div style={{
              display: 'flex',
              gap: '16px',
              marginBottom: '16px',
              flexWrap: 'wrap'
            }}>
              {[
                { label: 'Organization', color: '#60a5fa' },
                { label: 'Hostname',     color: '#f6ad55' },
                { label: 'IP Address',   color: '#fc8181' },
                { label: 'Technology',   color: '#68d391' },
                { label: 'User',         color: '#b794f4' },
                { label: 'Signal',       color: '#4a5568' },
              ].map(item => (
                <div key={item.label} style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px'
                }}>
                  <div style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    backgroundColor: item.color
                  }} />
                  <span style={{ fontSize: '11px', color: '#94a3b8' }}>
                    {item.label}
                  </span>
                </div>
              ))}
            </div>

            {graphData ? (
              <GraphViewWrapper data={graphData} />
            ) : (
              <div style={{
                textAlign: 'center',
                padding: '40px',
                color: '#4a5568',
                backgroundColor: '#0f1624',
                borderRadius: '8px',
                border: '1px solid #1e2a3a'
              }}>
                Graph data unavailable for this domain.
              </div>
            )}
          </div>
        )}

      </main>
    </div>
  );
};


/* ── Helper Components ──────────────────────────────────────────────────── */

const TabButton: React.FC<{
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}> = ({ active, onClick, icon, label }) => (
  <button
    onClick={onClick}
    style={{
      display: 'flex',
      alignItems: 'center',
      gap: '6px',
      padding: '6px 14px',
      backgroundColor: active ? '#1e3a5f' : 'transparent',
      color: active ? '#60a5fa' : '#4a5568',
      border: `1px solid ${active ? '#2563eb44' : '#1e2a3a'}`,
      borderRadius: '6px',
      fontSize: '13px',
      fontWeight: 500,
      cursor: 'pointer'
    }}
  >
    {icon}
    {label}
  </button>
);

const SurfaceSection: React.FC<{
  label: string;
  accent: string;
  children: React.ReactNode;
}> = ({ label, accent, children }) => (
  <div style={{
    backgroundColor: '#0f1624',
    border: '1px solid #1e2a3a',
    borderLeft: `3px solid ${accent}`,
    borderRadius: '6px',
    marginBottom: '12px',
    overflow: 'hidden'
  }}>
    <div style={{
      padding: '10px 12px',
      borderBottom: '1px solid #1e2a3a',
      fontSize: '12px',
      fontWeight: 600,
      color: accent,
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }}>
      {label}
    </div>
    {children}
  </div>
);

/**
 * Error boundary wrapper for the Cytoscape graph view.
 * If Cytoscape crashes (known issue with notify() on unmount),
 * the user sees a graceful message instead of a white screen.
 */
class GraphViewWrapper extends React.Component<
  { data: GraphData },
  { hasError: boolean }
> {
  constructor(props: { data: GraphData }) {
    super(props);
    this.state = { hasError: false };
  }

  static getDerivedStateFromError() {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('GraphView crashed:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          textAlign: 'center',
          padding: '40px',
          color: '#4a5568',
          backgroundColor: '#0f1624',
          borderRadius: '8px',
          border: '1px solid #1e2a3a'
        }}>
          <p style={{ marginBottom: '8px' }}>
            Graph visualization encountered an error.
          </p>
          <p style={{ fontSize: '12px' }}>
            The knowledge graph data is available via the API.
          </p>
        </div>
      );
    }
    return <GraphView data={this.props.data} />;
  }
}

export default App;