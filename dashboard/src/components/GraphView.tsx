import React, { useEffect, useRef } from 'react';
import CytoscapeComponent from 'react-cytoscapejs';
import { GraphData } from '../types';

interface Props {
  data: GraphData;
}

const NODE_COLORS: Record<string, string> = {
  Organization: '#60a5fa',
  HOSTNAME:     '#f6ad55',
  IP_ADDRESS:   '#fc8181',
  TECHNOLOGY:   '#68d391',
  GITHUB_USER:  '#b794f4',
  Signal:       '#4a5568',
  default:      '#94a3b8'
};

const GraphView: React.FC<Props> = ({ data }) => {
  const elements = [
    ...data.nodes.map(node => ({
      data: {
        id: node.id,
        label: node.properties.name
          || node.properties.domain
          || node.properties.source_type
          || node.label,
        nodeType: node.label,
        ...node.properties
      }
    })),
    ...data.edges.map((edge, i) => ({
      data: {
        id: `edge_${i}`,
        source: edge.source,
        target: edge.target,
        label: edge.relationship
      }
    }))
  ];

  const stylesheet: any[] = [
    {
      selector: 'node',
      style: {
        'background-color': (ele: any) => {
          const type = ele.data('nodeType');
          return NODE_COLORS[type] || NODE_COLORS.default;
        },
        'label': 'data(label)',
        'color': '#e2e8f0',
        'font-size': '10px',
        'text-valign': 'bottom',
        'text-margin-y': '4px',
        'width': 20,
        'height': 20,
        'border-width': 1,
        'border-color': '#2d3748'
      }
    },
    {
      selector: 'node[nodeType = "Organization"]',
      style: {
        'width': 40,
        'height': 40,
        'font-size': '12px',
        'font-weight': 'bold'
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 1,
        'line-color': '#2d3748',
        'target-arrow-color': '#2d3748',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'label': 'data(label)',
        'font-size': '8px',
        'color': '#4a5568'
      }
    }
  ];

  return (
    <div style={{
      width: '100%',
      height: '500px',
      backgroundColor: '#0a0e1a',
      borderRadius: '8px',
      border: '1px solid #1e2a3a',
      overflow: 'hidden'
    }}>
      <CytoscapeComponent
        elements={elements}
        stylesheet={stylesheet}
        layout={{ name: 'cose', animate: true }}
        style={{ width: '100%', height: '100%' }}
        cy={(cy) => {
          cy.on('tap', 'node', (evt) => {
            const node = evt.target;
            console.log('Node clicked:', node.data());
          });
        }}
      />
    </div>
  );
};

export default GraphView;