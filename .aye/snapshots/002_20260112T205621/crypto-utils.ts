/**
 * VaultGuard Crypto Utilities
 * Provides hashing, encoding, and entropy analysis functions
 */

/**
 * Calculate Shannon entropy of a string
 * Higher entropy = more random = potentially a secret
 */
export function calculateEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const char of str) {
    freq[char] = (freq[char] || 0) + 1;
  }

  let entropy = 0;
  const len = str.length;

  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Check if a string has high entropy (potential secret)
 */
export function isHighEntropy(str: string, threshold = 4.5): boolean {
  return str.length >= 16 && calculateEntropy(str) > threshold;
}

/**
 * Mask a sensitive value for display
 */
export function maskValue(value: string, visibleChars = 4): string {
  if (value.length <= visibleChars * 2) {
    return '*'.repeat(value.length);
  }
  
  const start = value.slice(0, visibleChars);
  const end = value.slice(-visibleChars);
  const masked = '*'.repeat(Math.min(value.length - visibleChars * 2, 20));
  
  return `${start}${masked}${end}`;
}

/**
 * Generate a unique ID
 */
export function generateId(): string {
  const timestamp = Date.now().toString(36);
  const randomPart = Math.random().toString(36).substring(2, 15);
  return `${timestamp}-${randomPart}`;
}

/**
 * Hash a string using SHA-256
 */
export async function sha256(str: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Encode string to base64
 */
export function toBase64(str: string): string {
  return btoa(unescape(encodeURIComponent(str)));
}

/**
 * Decode base64 to string
 */
export function fromBase64(str: string): string {
  try {
    return decodeURIComponent(escape(atob(str)));
  } catch {
    return '';
  }
}

/**
 * Check if string is valid base64
 */
export function isBase64(str: string): boolean {
  if (!str || str.length === 0) return false;
  
  const base64Regex = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  return base64Regex.test(str);
}

/**
 * Decode JWT and return payload (without verification)
 */
export function decodeJWT(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const payload = parts[1];
    if (!payload) return null;
    
    const decoded = fromBase64(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Check if JWT is expired
 */
export function isJWTExpired(token: string): boolean {
  const payload = decodeJWT(token);
  if (!payload || typeof payload.exp !== 'number') return false;
  
  return payload.exp * 1000 < Date.now();
}

/**
 * Extract JWT claims
 */
export function getJWTClaims(token: string): {
  issuer?: string;
  subject?: string;
  audience?: string;
  expiration?: Date;
  issuedAt?: Date;
  role?: string;
} {
  const payload = decodeJWT(token);
  if (!payload) return {};
  
  return {
    issuer: payload.iss as string | undefined,
    subject: payload.sub as string | undefined,
    audience: payload.aud as string | undefined,
    expiration: typeof payload.exp === 'number' ? new Date(payload.exp * 1000) : undefined,
    issuedAt: typeof payload.iat === 'number' ? new Date(payload.iat * 1000) : undefined,
    role: payload.role as string | undefined,
  };
}