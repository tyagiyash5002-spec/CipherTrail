import axios from 'axios';
// Connect to the enclave API when available. Demo workflows never call these endpoints.
export const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || '/v1', timeout: 15000 });
export const backend = { documents: () => api.get('/documents'), createSession: body => api.post('/decryption-sessions', body), submitSignature: (id, body) => api.post(`/decryption-sessions/${id}/signature`, body), session: id => api.get(`/decryption-sessions/${id}`), evidence: id => api.get(`/forensic-cases/${id}/evidence`) };
