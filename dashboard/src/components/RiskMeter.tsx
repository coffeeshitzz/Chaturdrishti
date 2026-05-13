import React from 'react';

interface Props {
  score: number;
}

const RiskMeter: React.FC<Props> = ({ score }) => {
  const getColor = () => {
    if (score >= 75) return '#ff4444';
    if (score >= 50) return '#ff8800';
    if (score >= 25) return '#ffcc00';
    return '#44cc44';
  };

  const color = getColor();

  return (
    <div style={{ width: '100%' }}>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        marginBottom: '8px'
      }}>
        <span style={{ color: '#94a3b8', fontSize: '14px' }}>
          Overall Risk Score
        </span>
        <span style={{
          color,
          fontSize: '24px',
          fontWeight: 700
        }}>
          {score}/100
        </span>
      </div>
      <div style={{
        width: '100%',
        height: '8px',
        backgroundColor: '#1e2a3a',
        borderRadius: '4px',
        overflow: 'hidden'
      }}>
        <div style={{
          width: `${score}%`,
          height: '100%',
          backgroundColor: color,
          borderRadius: '4px',
          transition: 'width 1s ease'
        }} />
      </div>
    </div>
  );
};

export default RiskMeter;