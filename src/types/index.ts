export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanType = 'quick' | 'standard' | 'deep';

export interface ScanOptions {
  type: ScanType;
  categories?: string[];
}

export interface ScanContext {
  url: string;
  domain: string;
  tabId: number;
  options: ScanOptions;
  domAnalysis?: DOMData;
  networkRequests?: any[];
  networkResponses?: any[];
}

export interface SecretPattern {
  name: string;
  service: string;
  pattern: RegExp;
  severity: Severity;
  context: { mustInclude?: string[]; mustExclude?: string[] };
  description: string;
}

export type Environment = 'development' | 'production' | 'staging' | 'unknown';
export type LocationType = 'script' | 'storage' | 'network' | 'html' | 'cookie' | 'header' | 'url';

export interface Location {
  type: LocationType;
  url?: string;
  storageKey?: string;
  line?: number;
  column?: number;
}

export interface Impact {
  description: string;
  exploitScenario: string;
  dataAtRisk: string[];
  businessImpact: string;
}

export interface Remediation {
  steps: string[];
  references: string[];
  priority: 'immediate' | 'short-term' | 'long-term';
  effort: 'low' | 'medium' | 'high';
}

export interface Vulnerability {
  id: string;
  type: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  location: Location;
  evidence: string;
  impact: Impact;
  remediation: Remediation;
  timestamp: number;
  tags: string[];
  confidence: number;
  environment: Environment;
  falsePositive: boolean;
  context?: string;
  cweId?: string;
}

export interface ScanSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  riskScore: number;
  grade: string;
}

export interface ScanResult {
  id: string;
  url: string;
  domain: string;
  timestamp: number;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  environment?: Environment;
}

export interface ScannerResult {
  vulnerabilities: Vulnerability[];
}

export interface DOMData {
  scripts: { src?: string; content?: string }[];
  forms: { action: string; method: string; hasPassword: boolean }[];
  localStorage: { key: string; value: string }[];
  sessionStorage: { key: string; value: string }[];
  cookies: { name: string; value: string }[];
  meta: Record<string, string>;
}