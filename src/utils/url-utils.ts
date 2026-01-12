export function parseURL(url: string): URL | null {
  try { return new URL(url); } catch { return null; }
}

export function getDomain(url: string): string {
  return parseURL(url)?.hostname ?? '';
}

export function getOrigin(url: string): string {
  return parseURL(url)?.origin ?? '';
}

export function getBaseDomain(url: string): string {
  const domain = getDomain(url);
  const parts = domain.split('.');
  return parts.length <= 2 ? domain : parts.slice(-2).join('.');
}

export function isSecureProtocol(url: string): boolean {
  return parseURL(url)?.protocol === 'https:';
}

export function isLocalhost(url: string): boolean {
  const domain = getDomain(url);
  return domain === 'localhost' || domain === '127.0.0.1' || domain === '0.0.0.0' || domain.endsWith('.localhost') || domain.startsWith('192.168.') || domain.startsWith('10.') || domain.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./) !== null;
}

export function extractQueryParams(url: string): Record<string, string> {
  const parsed = parseURL(url);
  if (!parsed) return {};
  const params: Record<string, string> = {};
  parsed.searchParams.forEach((value, key) => { params[key] = value; });
  return params;
}

export function isSensitiveQueryParam(paramName: string): boolean {
  return [/key/i, /token/i, /secret/i, /password/i, /auth/i, /api[_-]?key/i, /access[_-]?token/i, /private/i, /credential/i].some(p => p.test(paramName));
}

export function sanitizeURL(url: string, sensitiveParams: string[] = []): string {
  const parsed = parseURL(url);
  if (!parsed) return url;
  parsed.searchParams.forEach((_, key) => {
    if (isSensitiveQueryParam(key) || sensitiveParams.includes(key)) parsed.searchParams.set(key, '[REDACTED]');
  });
  return parsed.toString();
}

export function isAPIEndpoint(url: string): boolean {
  const parsed = parseURL(url);
  if (!parsed) return false;
  return [/\/api\//i, /\/v[0-9]+\//i, /\/graphql/i, /\/rest\//i, /\.json$/i, /\/webhook/i].some(p => p.test(parsed.pathname));
}