/**
 * VaultGuard Entropy Analyzer
 * Detects high-entropy strings that might be secrets
 */

import { calculateEntropy } from '../../utils/crypto-utils';

export interface EntropyResult {
  value: string;
  entropy: number;
  isPotentialSecret: boolean;
  type: 'hex' | 'base64' | 'alphanumeric' | 'mixed' | 'unknown';
}

const ENTROPY_THRESHOLDS = {
  hex: 3.0,
  base64: 4.0,
  alphanumeric: 4.5,
  mixed: 4.0,
  unknown: 4.5,
};

const MIN_LENGTH = 16;
const MAX_LENGTH = 256;

/**
 * Detect string encoding type
 */
export function detectStringType(str: string): EntropyResult['type'] {
  if (/^[0-9a-fA-F]+$/.test(str)) {
    return 'hex';
  }
  if (/^[A-Za-z0-9+/]+=*$/.test(str) && str.length % 4 === 0) {
    return 'base64';
  }
  if (/^[A-Za-z0-9]+$/.test(str)) {
    return 'alphanumeric';
  }
  if (/^[A-Za-z0-9_-]+$/.test(str)) {
    return 'mixed';
  }
  return 'unknown';
}

/**
 * Analyze a string for high entropy
 */
export function analyzeEntropy(str: string): EntropyResult {
  const type = detectStringType(str);
  const entropy = calculateEntropy(str);
  const threshold = ENTROPY_THRESHOLDS[type];
  
  const isPotentialSecret =
    str.length >= MIN_LENGTH &&
    str.length <= MAX_LENGTH &&
    entropy >= threshold;
  
  return {
    value: str,
    entropy,
    isPotentialSecret,
    type,
  };
}

/**
 * Extract potential secrets from text using entropy analysis
 */
export function extractHighEntropyStrings(text: string): EntropyResult[] {
  const results: EntropyResult[] = [];
  
  // Match potential tokens/keys (alphanumeric with common separators)
  const tokenPattern = /[A-Za-z0-9_-]{16,}/g;
  let match;
  
  while ((match = tokenPattern.exec(text)) !== null) {
    const value = match[0];
    const result = analyzeEntropy(value);
    
    if (result.isPotentialSecret) {
      results.push(result);
    }
  }
  
  return results;
}

/**
 * Check if a value passes common false positive checks
 */
export function isLikelyFalsePositive(value: string, context: string): boolean {
  const lowerValue = value.toLowerCase();
  const lowerContext = context.toLowerCase();
  
  // Check for common false positives
  const falsePositivePatterns = [
    // UUIDs
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    // MD5 hashes (often used for cache keys, not secrets)
    /^[0-9a-f]{32}$/i,
    // SHA hashes
    /^[0-9a-f]{40}$/i,
    /^[0-9a-f]{64}$/i,
    // Common libraries/frameworks
    /^(jquery|react|angular|vue|lodash|moment|axios)/i,
  ];
  
  if (falsePositivePatterns.some((p) => p.test(value))) {
    return true;
  }
  
  // Check context for example/placeholder indicators
  const placeholderIndicators = [
    'example',
    'sample',
    'test',
    'demo',
    'placeholder',
    'your-',
    'your_',
    'xxx',
    'replace',
    'changeme',
    'fixme',
    'todo',
  ];
  
  if (placeholderIndicators.some((p) => lowerValue.includes(p) || lowerContext.includes(p))) {
    return true;
  }
  
  // Check if in comment
  const commentPatterns = [
    /\/\/.*$/m,
    /\/\*[\s\S]*?\*\//,
    /#.*$/m,
    /<!--[\s\S]*?-->/,
  ];
  
  for (const pattern of commentPatterns) {
    const matches = context.match(pattern);
    if (matches && matches.some((m) => m.includes(value))) {
      // Being in a comment makes it less likely to be a real secret
      // but not impossible (commented out code)
      return false;
    }
  }
  
  return false;
}

/**
 * Calculate confidence score for entropy-based detection
 */
export function calculateConfidence(result: EntropyResult, context: string): number {
  let confidence = 0.5;
  
  // Higher entropy = higher confidence
  if (result.entropy > 5.5) confidence += 0.2;
  else if (result.entropy > 5.0) confidence += 0.1;
  
  // Certain types are more likely to be secrets
  if (result.type === 'base64') confidence += 0.1;
  if (result.type === 'hex' && result.value.length === 64) confidence += 0.15;
  
  // Check for false positive indicators
  if (isLikelyFalsePositive(result.value, context)) {
    confidence -= 0.3;
  }
  
  // Check for secret-related keywords in context
  const secretKeywords = ['key', 'token', 'secret', 'password', 'credential', 'auth'];
  if (secretKeywords.some((k) => context.toLowerCase().includes(k))) {
    confidence += 0.15;
  }
  
  return Math.max(0, Math.min(1, confidence));
}