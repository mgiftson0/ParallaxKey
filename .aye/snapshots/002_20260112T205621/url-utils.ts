/**
 * VaultGuard URL Utilities
 * URL parsing, validation, and analysis functions
 */

/**
 * Parse URL and extract components
 */
export function parseUrl(url: string): URL | null {
  try {
    return new URL(url);
  } catch {
    return null;
  }
}

/**
 * Get the origin from a URL string
 */
export function getOrigin(url: string): string {
  const parsed = parseUrl(url);
  return parsed?.origin ?? '';
}

/**
 * Get the domain from a URL string
 */
export function getDomain(url: string): string {
  const parsed = parseUrl(url);
  return parsed?.hostname ?? '';
}

/**
 * Check if URL uses HTTPS
 */
export function isSecureUrl(url: string): boolean {
  const parsed = parseUrl(url);
  return parsed?.protocol === 'https:';
}

/**
 * Check if URL is localhost or local network
 */
export function isLocalUrl(url: string): boolean {
  const parsed = parseUrl(url);
  if (!parsed) return false;
  
  const hostname = parsed.hostname.toLowerCase();
  
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '0.0.0.0' ||
    hostname.startsWith('192.168.') ||
    hostname.startsWith('10.') ||
    hostname.startsWith('172.16.') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.localhost')
  );
}

/**
 * Extract query parameters from URL
 */
export function getQueryParams(url: string): Map<string, string> {
  const parsed = parseUrl(url);
  if (!parsed) return new Map();
  
  const params = new Map<string, string>();
  parsed.searchParams.forEach((value, key) => {
    params.set(key, value);
  });
  
  return params;
}

/**
 * Check if URL parameter name looks sensitive
 */
export function isSensitiveParam(paramName: string): boolean {
  const sensitivePatterns = [
    'key',
    'token',
    'secret',
    'password',
    'pass',
    'pwd',
    'auth',
    'api_key',
    'apikey',
    'access_token',
    'refresh_token',
    'bearer',
    'credential',
    'private',
    'session',
    'jwt',
  ];
  
  const lowerName = paramName.toLowerCase();
  return sensitivePatterns.some((pattern) => lowerName.includes(pattern));
}

/**
 * Check if value looks like an email
 */
export function looksLikeEmail(value: string): boolean {
  const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
  return emailRegex.test(value);
}

/**
 * Check if value looks like a phone number
 */
export function looksLikePhone(value: string): boolean {
  const phoneRegex = /^[+]?[0-9]{10,15}$/;
  const cleaned = value.replace(/[\s()-]/g, '');
  return phoneRegex.test(cleaned);
}

/**
 * Check if value looks like a credit card number
 */
export function looksLikeCreditCard(value: string): boolean {
  const cleaned = value.replace(/[\s-]/g, '');
  if (!/^\d{13,19}$/.test(cleaned)) return false;
  
  // Luhn algorithm check
  let sum = 0;
  let isEven = false;
  
  for (let i = cleaned.length - 1; i >= 0; i--) {
    let digit = parseInt(cleaned[i]!, 10);
    
    if (isEven) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    
    sum += digit;
    isEven = !isEven;
  }
  
  return sum % 10 === 0;
}

/**
 * Check if value looks like a Social Security Number
 */
export function looksLikeSSN(value: string): boolean {
  const ssnRegex = /^\d{3}-?\d{2}-?\d{4}$/;
  return ssnRegex.test(value);
}

/**
 * Normalize URL for comparison
 */
export function normalizeUrl(url: string): string {
  const parsed = parseUrl(url);
  if (!parsed) return url;
  
  // Remove trailing slash, lowercase hostname
  let normalized = `${parsed.protocol}//${parsed.hostname.toLowerCase()}`;
  
  if (parsed.port && parsed.port !== '80' && parsed.port !== '443') {
    normalized += `:${parsed.port}`;
  }
  
  normalized += parsed.pathname.replace(/\/$/, '') || '/';
  
  return normalized;
}

/**
 * Check if URL matches a pattern (supports wildcards)
 */
export function matchesPattern(url: string, pattern: string): boolean {
  const regexPattern = pattern
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*');
  
  const regex = new RegExp(`^${regexPattern}$`, 'i');
  return regex.test(url);
}

/**
 * Extract file extension from URL
 */
export function getFileExtension(url: string): string {
  const parsed = parseUrl(url);
  if (!parsed) return '';
  
  const pathname = parsed.pathname;
  const lastDot = pathname.lastIndexOf('.');
  
  if (lastDot === -1 || lastDot === pathname.length - 1) return '';
  
  return pathname.slice(lastDot + 1).toLowerCase();
}

/**
 * Check if URL points to a JavaScript file
 */
export function isJavaScriptUrl(url: string): boolean {
  return getFileExtension(url) === 'js';
}

/**
 * Check if URL points to a source map
 */
export function isSourceMapUrl(url: string): boolean {
  const ext = getFileExtension(url);
  return ext === 'map' || url.endsWith('.js.map');
}