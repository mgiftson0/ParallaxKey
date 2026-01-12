import { Severity } from '../types';

export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

export function maskSecret(secret: string, visibleChars = 4): string {
  if (secret.length <= visibleChars * 2) return '*'.repeat(secret.length);
  const start = secret.substring(0, visibleChars);
  const end = secret.substring(secret.length - visibleChars);
  const middle = '*'.repeat(Math.min(secret.length - visibleChars * 2, 20));
  return `${start}${middle}${end}`;
}

export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;
  const freq: Record<string, number> = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function decodeJWT(token: string): { header: unknown; payload: unknown } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    return { header: decode(parts[0]), payload: decode(parts[1]) };
  } catch { return null; }
}

export function isValidJWT(str: string): boolean {
  const parts = str.split('.');
  if (parts.length !== 3) return false;
  try {
    const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    return typeof decode(parts[0]) === 'object' && typeof decode(parts[1]) === 'object';
  } catch { return false; }
}

export function getDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return ''; }
}

export function isLocalhost(url: string): boolean {
  const domain = getDomain(url);
  return domain === 'localhost' || domain === '127.0.0.1' || domain.startsWith('192.168.') || domain.startsWith('10.');
}

export function sanitizeURL(url: string): string {
  try {
    const parsed = new URL(url);
    const sensitiveParams = ['key', 'token', 'secret', 'password', 'auth', 'api_key', 'apikey'];
    sensitiveParams.forEach(param => {
      if (parsed.searchParams.has(param)) parsed.searchParams.set(param, '[REDACTED]');
    });
    return parsed.toString();
  } catch { return url; }
}

export function severityToScore(severity: Severity): number {
  const map: Record<Severity, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 1.0 };
  return map[severity];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityToScore(b) - severityToScore(a);
}

export function detectEnvironment(url: string, html?: string): 'development' | 'production' | 'staging' | 'unknown' {
  if (isLocalhost(url)) return 'development';
  const devIndicators = ['dev.', 'development.', 'staging.', 'stage.', 'test.', 'qa.', '-dev.', '-staging.'];
  const urlLower = url.toLowerCase();
  if (devIndicators.some(i => urlLower.includes(i))) {
    return urlLower.includes('staging') ? 'staging' : 'development';
  }
  if (html && [/<!--\s*DEBUG/i, /window\.__DEV__\s*=\s*true/i].some(p => p.test(html))) {
    return 'development';
  }
  return 'production';
}