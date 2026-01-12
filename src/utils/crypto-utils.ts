export function generateId(): string {
  return `${Date.now()}-${Math.random().toString(36).substring(2, 11)}`;
}

export function hashString(str: string): string {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16);
}

export function maskSecret(secret: string, visibleChars: number = 4): string {
  if (secret.length <= visibleChars * 2) return '*'.repeat(secret.length);
  return `${secret.substring(0, visibleChars)}${'*'.repeat(Math.min(secret.length - visibleChars * 2, 20))}${secret.substring(secret.length - visibleChars)}`;
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

export function isHighEntropy(str: string, threshold: number = 4.5): boolean {
  return calculateEntropy(str) >= threshold;
}

export function decodeJWT(token: string): { header: unknown; payload: unknown } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const decode = (s: string) => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
    return { header: decode(parts[0]), payload: decode(parts[1]) };
  } catch { return null; }
}