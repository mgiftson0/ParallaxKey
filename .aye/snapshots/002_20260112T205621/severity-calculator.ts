/**
 * VaultGuard Severity Calculator
 * CVSS-like scoring for vulnerabilities
 */

import type { Severity, Environment } from '../types';

export interface SeverityFactors {
  // Exploitability metrics
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  attackComplexity: 'low' | 'high';
  privilegesRequired: 'none' | 'low' | 'high';
  userInteraction: 'none' | 'required';
  
  // Impact metrics
  confidentialityImpact: 'none' | 'low' | 'high';
  integrityImpact: 'none' | 'low' | 'high';
  availabilityImpact: 'none' | 'low' | 'high';
  
  // Context modifiers
  environment: Environment;
  dataClassification: 'public' | 'internal' | 'confidential' | 'restricted';
}

const ATTACK_VECTOR_SCORES = {
  network: 0.85,
  adjacent: 0.62,
  local: 0.55,
  physical: 0.2,
};

const ATTACK_COMPLEXITY_SCORES = {
  low: 0.77,
  high: 0.44,
};

const PRIVILEGES_REQUIRED_SCORES = {
  none: 0.85,
  low: 0.62,
  high: 0.27,
};

const USER_INTERACTION_SCORES = {
  none: 0.85,
  required: 0.62,
};

const IMPACT_SCORES = {
  none: 0,
  low: 0.22,
  high: 0.56,
};

const ENVIRONMENT_MODIFIERS: Record<Environment, number> = {
  production: 1.0,
  staging: 0.8,
  development: 0.5,
  unknown: 0.7,
};

const DATA_CLASSIFICATION_MODIFIERS = {
  public: 0.5,
  internal: 0.7,
  confidential: 0.9,
  restricted: 1.0,
};

/**
 * Calculate exploitability sub-score
 */
function calculateExploitability(factors: SeverityFactors): number {
  return (
    8.22 *
    ATTACK_VECTOR_SCORES[factors.attackVector] *
    ATTACK_COMPLEXITY_SCORES[factors.attackComplexity] *
    PRIVILEGES_REQUIRED_SCORES[factors.privilegesRequired] *
    USER_INTERACTION_SCORES[factors.userInteraction]
  );
}

/**
 * Calculate impact sub-score
 */
function calculateImpact(factors: SeverityFactors): number {
  const iscBase =
    1 -
    (1 - IMPACT_SCORES[factors.confidentialityImpact]) *
    (1 - IMPACT_SCORES[factors.integrityImpact]) *
    (1 - IMPACT_SCORES[factors.availabilityImpact]);
  
  return 6.42 * iscBase;
}

/**
 * Calculate base CVSS-like score
 */
export function calculateBaseScore(factors: SeverityFactors): number {
  const exploitability = calculateExploitability(factors);
  const impact = calculateImpact(factors);
  
  if (impact <= 0) return 0;
  
  let baseScore = Math.min(1.08 * (impact + exploitability), 10);
  
  // Apply environment and data classification modifiers
  baseScore *= ENVIRONMENT_MODIFIERS[factors.environment];
  baseScore *= DATA_CLASSIFICATION_MODIFIERS[factors.dataClassification];
  
  return Math.round(baseScore * 10) / 10;
}

/**
 * Convert numeric score to severity level
 */
export function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}

/**
 * Calculate severity from factors
 */
export function calculateSeverity(factors: SeverityFactors): Severity {
  const score = calculateBaseScore(factors);
  return scoreToSeverity(score);
}

/**
 * Get default factors for common vulnerability types
 */
export function getDefaultFactors(type: string): Partial<SeverityFactors> {
  const defaults: Record<string, Partial<SeverityFactors>> = {
    api_key_exposure: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      confidentialityImpact: 'high',
      integrityImpact: 'high',
      availabilityImpact: 'low',
      dataClassification: 'restricted',
    },
    missing_security_header: {
      attackVector: 'network',
      attackComplexity: 'high',
      privilegesRequired: 'none',
      userInteraction: 'required',
      confidentialityImpact: 'low',
      integrityImpact: 'low',
      availabilityImpact: 'none',
      dataClassification: 'internal',
    },
    insecure_cookie: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      confidentialityImpact: 'low',
      integrityImpact: 'low',
      availabilityImpact: 'none',
      dataClassification: 'confidential',
    },
    pii_exposure: {
      attackVector: 'network',
      attackComplexity: 'low',
      privilegesRequired: 'none',
      userInteraction: 'none',
      confidentialityImpact: 'high',
      integrityImpact: 'none',
      availabilityImpact: 'none',
      dataClassification: 'confidential',
    },
  };
  
  return defaults[type] ?? {};
}