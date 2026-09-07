const configuredApiUrl = import.meta.env.VITE_API_URL?.trim() || '';
export const API_BASE_URL = configuredApiUrl.replace(/\/$/, '');

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path.startsWith('/') ? path : `/${path}`}`;
}