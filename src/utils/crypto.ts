export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
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

export function base64Decode(str: string): string {
  try { return atob(str); } catch { return ''; }
}

export function decodeJWT(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = parts[1];
    if (!payload) return null;
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(base64Decode(base64));
  } catch { return null; }
}

export function isJWT(str: string): boolean {
  return /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/.test(str);
}

export function maskSecret(secret: string, visible = 4): string {
  if (!secret) return '';
  if (secret.length <= visible * 2) return '*'.repeat(secret.length);
  return `${secret.substring(0, visible)}${'*'.repeat(Math.min(secret.length - visible * 2, 16))}${secret.substring(secret.length - visible)}`;
}