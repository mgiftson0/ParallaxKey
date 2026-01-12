/**
 * VaultGuard Environment Detector
 * Detects whether the current page is development or production
 */

import type { Environment } from '../types';
import { isLocalUrl, getDomain } from '../utils/url-utils';

interface EnvironmentSignals {
  url: string;
  hostname?: string;
  headers?: Record<string, string>;
  sourceMapPresent?: boolean;
  consoleLogs?: boolean;
  debugMode?: boolean;
}

const DEV_INDICATORS = [
  // URL patterns
  'localhost',
  '127.0.0.1',
  '0.0.0.0',
  '.local',
  '.dev',
  '.test',
  '.example',
  ':3000',
  ':4200',
  ':5000',
  ':5173',
  ':8000',
  ':8080',
  ':8888',
  
  // Subdomain patterns
  'dev.',
  'development.',
  'local.',
  'test.',
  'sandbox.',
  'preview.',
];

const STAGING_INDICATORS = [
  'staging.',
  'stage.',
  'stg.',
  'uat.',
  'qa.',
  'preprod.',
  'pre-prod.',
];

const PROD_INDICATORS = [
  'www.',
  'app.',
  'api.',
  'prod.',
  'production.',
];

/**
 * Detect environment from URL
 */
function detectFromUrl(url: string): Environment | null {
  const lowerUrl = url.toLowerCase();
  
  // Check for local development
  if (isLocalUrl(url)) {
    return 'development';
  }
  
  // Check for staging indicators
  for (const indicator of STAGING_INDICATORS) {
    if (lowerUrl.includes(indicator)) {
      return 'staging';
    }
  }
  
  // Check for development indicators
  for (const indicator of DEV_INDICATORS) {
    if (lowerUrl.includes(indicator)) {
      return 'development';
    }
  }
  
  // Check for production indicators
  for (const indicator of PROD_INDICATORS) {
    if (lowerUrl.includes(indicator)) {
      return 'production';
    }
  }
  
  return null;
}

/**
 * Detect environment from headers
 */
function detectFromHeaders(headers: Record<string, string>): Environment | null {
  const envHeader = headers['x-environment'] ?? headers['x-env'];
  
  if (envHeader) {
    const lowerEnv = envHeader.toLowerCase();
    
    if (lowerEnv.includes('prod')) return 'production';
    if (lowerEnv.includes('stag') || lowerEnv.includes('uat')) return 'staging';
    if (lowerEnv.includes('dev') || lowerEnv.includes('local')) return 'development';
  }
  
  // Check for debug headers
  if (headers['x-debug'] || headers['x-debug-mode']) {
    return 'development';
  }
  
  return null;
}

/**
 * Calculate confidence score for environment detection
 */
function calculateConfidence(signals: EnvironmentSignals, detected: Environment): number {
  let confidence = 0.5; // Base confidence
  
  // URL-based detection is fairly reliable
  if (isLocalUrl(signals.url)) {
    confidence += 0.4;
  }
  
  // Source maps in production is unusual
  if (signals.sourceMapPresent) {
    if (detected === 'production') {
      confidence -= 0.2;
    } else {
      confidence += 0.1;
    }
  }
  
  // Console logs in production is unusual
  if (signals.consoleLogs) {
    if (detected === 'production') {
      confidence -= 0.1;
    }
  }
  
  // Debug mode strongly indicates development
  if (signals.debugMode) {
    if (detected === 'development') {
      confidence += 0.3;
    } else {
      confidence -= 0.3;
    }
  }
  
  return Math.min(1, Math.max(0, confidence));
}

/**
 * Main environment detection function
 */
export function detectEnvironment(signals: EnvironmentSignals): {
  environment: Environment;
  confidence: number;
} {
  // Try URL detection first
  let detected = detectFromUrl(signals.url);
  
  // Try headers if URL didn't give definitive answer
  if (!detected && signals.headers) {
    detected = detectFromHeaders(signals.headers);
  }
  
  // Default to production if uncertain (safer assumption)
  if (!detected) {
    const domain = getDomain(signals.url);
    
    // If it has a proper TLD and isn't local, assume production
    if (domain && domain.includes('.') && !isLocalUrl(signals.url)) {
      detected = 'production';
    } else {
      detected = 'unknown';
    }
  }
  
  const confidence = calculateConfidence(signals, detected);
  
  return {
    environment: detected,
    confidence,
  };
}

/**
 * Quick environment check from URL only
 */
export function quickEnvironmentCheck(url: string): Environment {
  return detectFromUrl(url) ?? 'unknown';
}

/**
 * Check if this is a production environment
 */
export function isProduction(environment: Environment): boolean {
  return environment === 'production';
}

/**
 * Check if this is a development environment
 */
export function isDevelopment(environment: Environment): boolean {
  return environment === 'development';
}

/**
 * Get severity modifier based on environment
 * Production issues are more severe
 */
export function getEnvironmentSeverityModifier(environment: Environment): number {
  switch (environment) {
    case 'production':
      return 1.0;
    case 'staging':
      return 0.8;
    case 'development':
      return 0.5;
    case 'unknown':
      return 0.7;
  }
}