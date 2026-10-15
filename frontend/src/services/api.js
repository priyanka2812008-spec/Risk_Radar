import axios from 'axios';

const getApiBase = () => {
  if (import.meta.env.VITE_API_URL && !import.meta.env.VITE_API_URL.includes('localhost')) {
    return import.meta.env.VITE_API_URL;
  }
  if (typeof window !== 'undefined' && window.location.hostname && window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
    return `http://${window.location.hostname}:5000/api`;
  }
  return import.meta.env.VITE_API_URL || 'http://localhost:5000/api';
};

const API_BASE_URL = getApiBase();

const client = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000
});

/** Turn an axios failure into one sentence a person can act on */
export const errorMessage = (err) => {
  if (err?.response?.data?.error) return err.response.data.error;
  if (err?.code === 'ECONNABORTED') return 'The scan took too long. Try again in a moment.';
  if (err?.message === 'Network Error') return `Can't reach the Risk Radar backend at ${API_BASE_URL}. Start it with "npm run dev" in the backend folder.`;
  return err?.message || 'Something went wrong.';
};

export const api = {
  health: async () => {
    const res = await client.get('/health', { timeout: 4000 });
    return res.data;
  },

  // 7D Website Risk Classification Engine
  scan7D: async (url, options = {}) => {
    const res = await client.post('/scan/7d', {
      url,
      demoMode: options.demoMode
    });
    return res.data;
  },

  get7DDimensions: async () => {
    const res = await client.get('/scan/7d/dimensions');
    return res.data;
  },

  // Pre-Execution Risk Intelligence
  scanPreExecution: async (url, options = {}) => {
    const res = await client.post('/scan/pre-execution', {
      url,
      demoMode: options.demoMode,
      demoScenario: options.demoScenario
    });
    return res.data;
  },

  getDemoScenarios: async () => {
    const res = await client.get('/scan/demo-scenarios');
    return res.data;
  },

  getPassport: async (token) => {
    const res = await client.get(`/scan/passport/${encodeURIComponent(token)}`);
    return res.data;
  },

  // Modular Intelligence Endpoints
  getDomainIntelligence: async (urlOrDomain) => {
    const res = await client.post('/domain-intelligence', { url: urlOrDomain });
    return res.data;
  },

  getThreatIntelligence: async (urlOrDomain, options = {}) => {
    const res = await client.post('/threat-intelligence', { url: urlOrDomain, ...options });
    return res.data;
  },

  getInfrastructure: async (urlOrDomain) => {
    const res = await client.post('/infrastructure', { url: urlOrDomain });
    return res.data;
  },

  getClassification: async (urlOrDomain) => {
    const res = await client.post('/classification', { url: urlOrDomain });
    return res.data;
  },

  getRiskScore: async (payload) => {
    const res = await client.post('/risk-score', payload);
    return res.data;
  },

  // Existing Scans
  scanUrl: async (url) => {
    const res = await client.post('/scan', { url });
    return res.data;
  },

  scanBulk: async (urls) => {
    const res = await client.post('/scan/bulk', { urls });
    return res.data;
  },

  getScans: async () => {
    const res = await client.get('/scans');
    return res.data;
  },

  getScanById: async (id) => {
    const res = await client.get(`/scans/${id}`);
    return res.data;
  },

  // Watchlist
  getWatchlist: async () => {
    const res = await client.get('/watchlist');
    return res.data;
  },

  addToWatchlist: async (data) => {
    const res = await client.post('/watchlist', data);
    return res.data;
  },

  removeFromWatchlist: async (id) => {
    const res = await client.delete(`/watchlist/${id}`);
    return res.data;
  },

  rescanWatchlist: async (id) => {
    const res = await client.post(`/watchlist/${id}/rescan`);
    return res.data;
  },

  // Reports
  getReports: async () => {
    const res = await client.get('/reports');
    return res.data;
  },

  getReportById: async (id) => {
    const res = await client.get(`/reports/${id}`);
    return res.data;
  },

  // SOC Stats & Incidents
  getStats: async () => {
    const res = await client.get('/soc/stats');
    return res.data;
  },

  getQueue: async () => {
    const res = await client.get('/soc/queue');
    return res.data;
  },

  updateQueueItem: async (id, payload) => {
    const res = await client.patch(`/soc/queue/${id}`, payload);
    return res.data;
  },

  // API Keys
  getApiKeys: async () => {
    const res = await client.get('/soc/keys');
    return res.data;
  },

  createApiKey: async (name) => {
    const res = await client.post('/soc/keys', { name });
    return res.data;
  }
};
