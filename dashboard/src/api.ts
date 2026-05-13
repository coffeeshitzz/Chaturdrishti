import axios from 'axios';
import { Report, GraphData } from './types';

const BASE_URL = 'http://localhost:8000';

export const analyzeTarget = async (domain: string): Promise<Report> => {
  const response = await axios.post(`${BASE_URL}/analyze`, {
    target_org: domain,
    run_collectors: true,
    run_nlp: true,
    run_inference: true
  });
  return response.data;
};

export const getReport = async (domain: string): Promise<Report> => {
  const response = await axios.get(`${BASE_URL}/report/${domain}`);
  return response.data;
};

export const getGraph = async (domain: string): Promise<GraphData> => {
  const response = await axios.get(`${BASE_URL}/graph/${domain}`);
  return response.data;
};