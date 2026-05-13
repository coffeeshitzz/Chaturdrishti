import React, { useState } from 'react';
import { Finding } from '../types';
import RiskBadge from './RiskBadge';
import { ChevronDown, ChevronUp, Shield, AlertTriangle, Target } from 'lucide-react';

interface Props {
  finding: Finding;
  index: number;
}

const FindingCard: React.FC<Props> = ({ finding, index }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div style={{
      backgroundColor: '#0f1624',
      border: '1px solid #1e2a3a',
      borderRadius: '8px',
      marginBottom: '12px',
      overflow: 'hidden'
    }}>
      {/* Header */}
      <div
        onClick={() => setExpanded(!expanded)}
        style={{
          padding: '16px 20px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          cursor: 'pointer',
          userSelect: 'none'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span style={{ color: '#4a5568', fontSize: '13px', minWidth: '24px' }}>
            #{index + 1}
          </span>
          <RiskBadge level={finding.risk_level} />
          <span style={{ fontWeight: 600, fontSize: '15px' }}>
            {finding.title}
          </span>
        </div>
        {expanded
          ? <ChevronUp size={16} color="#4a5568" />
          : <ChevronDown size={16} color="#4a5568" />
        }
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div style={{
          padding: '0 20px 20px',
          borderTop: '1px solid #1e2a3a'
        }}>
          {/* Inference */}
          <div style={{ marginTop: '16px' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              marginBottom: '8px'
            }}>
              <Target size={14} color="#60a5fa" />
              <span style={{
                fontSize: '12px',
                color: '#60a5fa',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em'
              }}>
                Inference
              </span>
            </div>
            <p style={{ color: '#cbd5e0', fontSize: '14px', lineHeight: '1.6' }}>
              {finding.inference}
            </p>
          </div>

          {/* Evidence */}
          {finding.evidence.length > 0 && (
            <div style={{ marginTop: '16px' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                marginBottom: '8px'
              }}>
                <AlertTriangle size={14} color="#f6ad55" />
                <span style={{
                  fontSize: '12px',
                  color: '#f6ad55',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Evidence
                </span>
              </div>
              {finding.evidence.map((ev: string, i: number) => (
                <div key={i} style={{
                  display: 'flex',
                  gap: '8px',
                  marginBottom: '6px'
                }}>
                  <span style={{ color: '#4a5568', flexShrink: 0 }}>→</span>
                  <span style={{
                    color: '#94a3b8',
                    fontSize: '13px',
                    fontFamily: 'monospace'
                  }}>
                    {ev}
                  </span>
                </div>
              ))}
            </div>
          )}

          {/* Attacker Value */}
          {finding.attacker_value && (
            <div style={{
              marginTop: '16px',
              padding: '12px',
              backgroundColor: '#1a0f0f',
              borderRadius: '6px',
              border: '1px solid #3a1a1a'
            }}>
              <span style={{
                fontSize: '11px',
                color: '#fc8181',
                fontWeight: 600,
                textTransform: 'uppercase',
                letterSpacing: '0.05em',
                display: 'block',
                marginBottom: '6px'
              }}>
                Attacker Value
              </span>
              <p style={{ color: '#feb2b2', fontSize: '13px', lineHeight: '1.5' }}>
                {finding.attacker_value}
              </p>
            </div>
          )}

          {/* Mitigations */}
          {finding.mitigations.length > 0 && (
            <div style={{ marginTop: '16px' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                marginBottom: '8px'
              }}>
                <Shield size={14} color="#68d391" />
                <span style={{
                  fontSize: '12px',
                  color: '#68d391',
                  fontWeight: 600,
                  textTransform: 'uppercase',
                  letterSpacing: '0.05em'
                }}>
                  Mitigation
                </span>
              </div>
              {finding.mitigations.map((m: string, i: number) => (
                <div key={i} style={{
                  display: 'flex',
                  gap: '8px',
                  marginBottom: '6px'
                }}>
                  <span style={{ color: '#68d391', flexShrink: 0 }}>✓</span>
                  <span style={{ color: '#9ae6b4', fontSize: '13px' }}>{m}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default FindingCard;