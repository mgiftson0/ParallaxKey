import { Severity, VulnerabilityType, Environment } from '../types/vulnerability';
import { getEnvironmentRiskMultiplier } from './environment-detector';

const BASE_SEVERITY: Record<VulnerabilityType, number> = {
  secret_exposure: 9.0, api_key_exposed: 8.5, insecure_header: 5.0, cors_misconfiguration: 6.5,
  pii_exposure: 8.0, insecure_storage: 6.0, jwt_vulnerability: 7.5, session_vulnerability: 7.0,
  debug_exposure: 5.5, version_disclosure: 3.0, sql_injection: 9.5, xss_vulnerability: 7.0,
  csrf_vulnerability: 6.5, insecure_cookie: 5.5, source_map_exposure: 4.0, dependency_vulnerability: 6.0,
  graphql_introspection: 4.5, subdomain_takeover: 8.0, git_exposure: 7.5, backup_exposure: 7.0, cloud_misconfiguration: 8.0,
};

export function calculateSeverityScore(factors: { type: VulnerabilityType; environment: Environment; dataExposed?: boolean; publiclyAccessible?: boolean }): number {
  let score = BASE_SEVERITY[factors.type] || 5.0;
  score *= getEnvironmentRiskMultiplier(factors.environment);
  if (factors.dataExposed) score += 1.0;
  if (factors.publiclyAccessible) score += 0.5;
  return Math.min(10, Math.max(0, score));
}

export function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 2.0) return 'low';
  return 'info';
}

export function severityToScore(severity: Severity): number {
  const map: Record<Severity, number> = { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 1.0 };
  return map[severity];
}

export function compareSeverity(a: Severity, b: Severity): number {
  return severityToScore(b) - severityToScore(a);
}

export function getSeverityColor(severity: Severity): string {
  const colors: Record<Severity, string> = { critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#6B7280' };
  return colors[severity];
}