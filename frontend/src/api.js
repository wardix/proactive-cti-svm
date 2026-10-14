const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api';

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `HTTP Error ${res.status}`);
  }
  return data;
}

export const api = {
  getOverview: () => request('/overview'),
  getSources: () => request('/sources'),
  updateSourceConfig: (payload) =>
    request('/sources/config', { method: 'POST', body: JSON.stringify(payload) }),
  pullFromSource: (payload) =>
    request('/sources/pull', { method: 'POST', body: JSON.stringify(payload) }),
  uploadLogs: (payload) =>
    request('/sources/upload', { method: 'POST', body: JSON.stringify(payload) }),

  getDataset: (params = {}) => {
    const qs = new URLSearchParams(params).toString();
    return request(`/dataset${qs ? `?${qs}` : ''}`);
  },
  seedDataset: (payload) =>
    request('/dataset/seed', { method: 'POST', body: JSON.stringify(payload) }),
  runPreprocessing: (payload = {}) =>
    request('/dataset/preprocess', { method: 'POST', body: JSON.stringify(payload) }),

  getSvmHistory: () => request('/svm/history'),
  trainSvm: (payload) =>
    request('/svm/train', { method: 'POST', body: JSON.stringify(payload) }),

  getPredictions: () => request('/svm/predictions'),
  predictUnseen: (payload) =>
    request('/svm/predict', { method: 'POST', body: JSON.stringify(payload) }),
  predictHoneypotBatch: (payload = { count: 12 }) =>
    request('/svm/predict-honeypot-batch', { method: 'POST', body: JSON.stringify(payload) }),

  exportWazuhRules: () => request('/export/wazuh-rules'),
  exportMispFeed: () => request('/export/misp-feed'),
};
