import React from 'react';

interface Props {
  level: string;
  size?: 'sm' | 'md' | 'lg';
}

const colors: Record<string, string> = {
  critical: '#ff4444',
  high:     '#ff8800',
  medium:   '#ffcc00',
  low:      '#44cc44',
  unknown:  '#888888'
};

const RiskBadge: React.FC<Props> = ({ level, size = 'md' }) => {
  const color = colors[level.toLowerCase()] || colors.unknown;
  const padding = size === 'sm' ? '2px 8px' : size === 'lg' ? '6px 16px' : '4px 12px';
  const fontSize = size === 'sm' ? '10px' : size === 'lg' ? '14px' : '12px';

  return (
    <span style={{
      backgroundColor: `${color}22`,
      color: color,
      border: `1px solid ${color}44`,
      borderRadius: '4px',
      padding,
      fontSize,
      fontWeight: 600,
      textTransform: 'uppercase',
      letterSpacing: '0.05em'
    }}>
      {level}
    </span>
  );
};

export default RiskBadge;