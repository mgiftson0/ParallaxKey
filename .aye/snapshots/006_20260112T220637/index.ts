export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Environment = 'development' | 'production' | 'staging' | 'unknown';
export type ScanStatus = 'idle' | 'scanning' | 'completed' | 'error';
export type ScanType = 'quick' | 'standard' | 'deep';
export type VulnerabilityCategory = 'secret_exposure' | 'network_security' | 'storage_security' | 'authentication' | 'data_exposure' | 'misconfiguration';
export type LocationType = 'script' | 'storage' | 'network' | 'html' | 'cookie' | 'header' | 'url';

export interface Location {
  type: LocationType;
  url?: string;
  storageKey?: string;
}

export interface Vulnerability {
  id: string;
  type: string;
  category: VulnerabilityCategory;
  severity: Severity;
  title: string;
  description: string;
  location: Location;
  evidence: string;
  remediation: string[];
  timestamp: number;
  confidence: number;
  tags: string[];
}

export interface ScanSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  riskScore: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface ScanResult {
  id: string;
  url: string;
  domain: string;
  scanType: ScanType;
  status: ScanStatus;
  startTime: number;
  endTime?: number;
  environment: Environment;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
}

export interface ScanOptions {
  type: ScanType;
  categories?: VulnerabilityCategory[];
}

export interface Settings {
  general: { autoScan: boolean; showBadge: boolean; debugMode: boolean };
  scanning: { defaultScanType: ScanType; enabledCategories: VulnerabilityCategory[] };
  appearance: { theme: 'light' | 'dark' | 'system' };
}

export interface Message {
  type: string;
  payload?: any;
  tabId?: number;
}

export interface NetworkRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  timestamp: number;
  type: string;
}

export interface NetworkResponse {
  requestId: string;
  url: string;
  status: number;
  headers: Record<string, string>;
  timestamp: number;
}

export interface DOMAnalysisResult {
  scripts: { src?: string; content?: string }[];
  forms: { action: string; method: string; hasPassword: boolean }[];
  localStorage: { key: string; value: string }[];
  sessionStorage: { key: string; value: string }[];
  cookies: { name: string; value: string; secure: boolean; httpOnly: boolean; sameSite: string }[];
  meta: Record<string, string>;
  error?: string;
}

export interface ScanContext {
  url: string;
  domain: string;
  tabId: number;
  options: ScanOptions;
  domAnalysis?: DOMAnalysisResult;
  networkRequests?: NetworkRequest[];
  networkResponses?: NetworkResponse[];
}

export interface ScannerResult {
  scanner: string;
  vulnerabilities: Vulnerability[];
  duration: number;
  error?: string;
}

export interface SecretPattern {
  name: string;
  service: string;
  pattern: RegExp;
  severity: Severity;
  description: string;
}