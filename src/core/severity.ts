import { Severity, Vulnerability } from '../types';

export function severityToScore(severity: Severity): number {
  const scores: Record<Severity, number> = { critical: 9.5, high: 8.0, medium: 5.5, low: 2.5, info: 0.5 };
  return scores[severity] || 0;
}

export function calculateRiskScore(vulnerabilities: Vulnerability[]): number {
  if (vulnerabilities.length === 0) return 0;
  let total = 0;
  for (const v of vulnerabilities) total += severityToScore(v.severity) * v.confidence;
  return Math.min(100, Math.round((total / vulnerabilities.length) * 10));
}

export function getGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
  if (score <= 10) return 'A';
  if (score <= 30) return 'B';
  if (score <= 50) return 'C';
  if (score <= 70) return 'D';
  return 'F';
}