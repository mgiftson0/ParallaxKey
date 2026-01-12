export function extractDomain(url: string): string {
  try { return new URL(url).hostname; } catch { return ''; }
}

export function isHTTPS(url: string): boolean {
  try { return new URL(url).protocol === 'https:'; } catch { return false; }
}

export function isLocalURL(url: string): boolean {
  try {
    const hostname = new URL(url).hostname;
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname.endsWith('.local');
  } catch { return false; }
}

export function hasSensitiveParams(url: string): { hasSensitive: boolean; params: string[] } {
  const sensitive = ['key', 'token', 'secret', 'password', 'api_key', 'apikey', 'access_token', 'auth'];
  try {
    const parsed = new URL(url);
    const found: string[] = [];
    parsed.searchParams.forEach((_, key) => {
      if (sensitive.some(p => key.toLowerCase().includes(p))) found.push(key);
    });
    return { hasSensitive: found.length > 0, params: found };
  } catch { return { hasSensitive: false, params: [] }; }
}