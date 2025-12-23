const API_BASE_KEY = 'api_base';
export const DEFAULT_API_BASE = import.meta.env.VITE_API_BASE || 'https://arouter.199028.xyz';

export const getApiBase = () => localStorage.getItem(API_BASE_KEY) || DEFAULT_API_BASE;

export const setApiBase = (base) => {
  if (!base) {
    localStorage.removeItem(API_BASE_KEY);
    return;
  }
  localStorage.setItem(API_BASE_KEY, base);
};

export const joinUrl = (base, path) => {
  if (!base) return path;
  const cleaned = base.replace(/\/+$/, '');
  return `${cleaned}${path}`;
};

export async function api(method, url, body) {
  const token = localStorage.getItem('jwt') || '';
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(joinUrl(getApiBase(), url), {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  if (res.status === 401) {
    localStorage.removeItem('jwt');
    window.location.reload();
    return;
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }
  if (res.status === 204) return null;
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (_) {
    return text;
  }
}
