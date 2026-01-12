// ============================================
// VaultGuard Type Definitions
// ============================================

// Severity Levels
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// Environment Types
export type Environment = 'development' | 'production' | 'staging' | 'unknown';

// Scanner Types
export type ScannerType =
  | 'secrets'
  | 'network'
  | 'storage'
  | 'javascript'
  | 'authentication'
  | 'headers'
  | 'data-exposure'
  | 'database'
  | 'infrastructure'
  | 'third-party';

// Location Types
export type LocationType =
  | 'script'
  | 'storage'
  | 'network'
  | 'html'
  | 'cookie'
  | 'header'
  | 'url'
  | 'websocket';

// ============================================
// Vulnerability Interfaces
// ============================================

export interface VulnerabilityLocation {
  type: LocationType;
  url?: string;
  line?: number;
  column?: number;
  storageKey?: string;
  requestId?: string;
  selector?: string;
}

export interface VulnerabilityImpact {
  description: string;
  exploitScenario: string;
  dataAtRisk: string[];
  cvssScore?: number;
}

export interface CodeExample {
  vulnerable: string;
  secure: string;
  language: string;
}

export interface VulnerabilityRemediation {
  steps: string[];
  codeExample?: CodeExample;
  references: string[];
  estimatedEffort: 'low' | 'medium' | 'high';
}

export interface Vulnerability {
  id: string;
  type: string;
  scannerType: ScannerType;
  severity: Severity;
  title: string;
  description: string;
  location: VulnerabilityLocation;
  impact: VulnerabilityImpact;
  remediation: VulnerabilityRemediation;
  timestamp: number;
  environment: Environment;
  falsePositiveProbability?: number;
  cweId?: string;
  owaspCategory?: string;
  metadata?: Record<string, unknown>;
}

// ============================================
// Secret Detection Interfaces
// ============================================

export interface SecretPattern {
  name: string;
  service: string;
  pattern: RegExp;
  severity: Severity;
  context: {
    mustInclude?: string[];
    mustExclude?: string[];
  };
  validator?: (match: string) => Promise<boolean>;
}

export interface SecretFinding extends Vulnerability {
  secret: {
    type: string;
    service: string;
    pattern: string;
    maskedValue: string;
    fullValue?: string; // Only stored temporarily, never persisted
    entropy?: number;
  };
}

// ============================================
// Network Analysis Interfaces
// ============================================

export interface NetworkRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
  tabId: number;
  frameId: number;
  type: chrome.webRequest.ResourceType;
}

export interface NetworkResponse {
  id: string;
  requestId: string;
  url: string;
  statusCode: number;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
}

export interface SecurityHeader {
  name: string;
  required: boolean;
  severity: Severity;
  validator: (value: string) => boolean;
  recommendation: string;
}

// ============================================
// Storage Analysis Interfaces
// ============================================

export interface StorageItem {
  key: string;
  value: string;
  type: 'localStorage' | 'sessionStorage' | 'cookie' | 'indexedDB';
  size: number;
  domain: string;
}

export interface CookieAnalysis {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: 'strict' | 'lax' | 'none' | undefined;
  expires?: Date;
  issues: string[];
}

// ============================================
// Scanner Interfaces
// ============================================

export interface ScannerConfig {
  enabled: boolean;
  severity: Severity;
  customPatterns?: SecretPattern[];
  excludePatterns?: string[];
  timeout?: number;
}

export interface ScanContext {
  url: string;
  tabId: number;
  origin: string;
  environment: Environment;
  timestamp: number;
  config: ScannerConfig;
}

export interface ScanResult {
  scannerId: string;
  scannerType: ScannerType;
  vulnerabilities: Vulnerability[];
  duration: number;
  itemsScanned: number;
  timestamp: number;
  error?: string;
}

export interface ScanSummary {
  id: string;
  url: string;
  timestamp: number;
  duration: number;
  environment: Environment;
  results: ScanResult[];
  totalVulnerabilities: number;
  bySeverity: Record<Severity, number>;
  byType: Record<ScannerType, number>;
}

// ============================================
// Message Interfaces
// ============================================

export type MessageType =
  | 'START_SCAN'
  | 'STOP_SCAN'
  | 'SCAN_PROGRESS'
  | 'SCAN_COMPLETE'
  | 'SCAN_ERROR'
  | 'GET_FINDINGS'
  | 'CLEAR_FINDINGS'
  | 'GET_SETTINGS'
  | 'UPDATE_SETTINGS'
  | 'CONTENT_READY'
  | 'DOM_ANALYSIS'
  | 'STORAGE_ANALYSIS'
  | 'NETWORK_REQUEST'
  | 'NETWORK_RESPONSE';

export interface Message<T = unknown> {
  type: MessageType;
  payload?: T;
  tabId?: number;
  timestamp: number;
}

export interface StartScanPayload {
  scanTypes?: ScannerType[];
  quickScan?: boolean;
}

export interface ScanProgressPayload {
  scanId: string;
  progress: number;
  currentScanner: string;
  findingsCount: number;
}

// ============================================
// Settings Interfaces
// ============================================

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  scanners: ScannerType[];
  config: Partial<ScannerConfig>;
}

export interface DomainSettings {
  domain: string;
  authorized: boolean;
  autoScan: boolean;
  profile?: string;
  lastScanned?: number;
}

export interface VaultGuardSettings {
  version: string;
  theme: 'light' | 'dark' | 'system';
  notifications: boolean;
  autoScan: boolean;
  scanOnLoad: boolean;
  defaultProfile: string;
  profiles: ScanProfile[];
  authorizedDomains: DomainSettings[];
  excludedPaths: string[];
  maxFindings: number;
  retentionDays: number;
  developerMode: boolean;
}

// ============================================
// Report Interfaces
// ============================================

export type ReportFormat = 'json' | 'csv' | 'html' | 'markdown' | 'pdf';

export interface ReportOptions {
  format: ReportFormat;
  includeRemediation: boolean;
  includeTechnicalDetails: boolean;
  groupBy: 'severity' | 'type' | 'location';
  template: 'executive' | 'technical' | 'developer';
}

export interface Report {
  id: string;
  title: string;
  summary: ScanSummary;
  findings: Vulnerability[];
  generatedAt: number;
  format: ReportFormat;
  options: ReportOptions;
}

// ============================================
// Tab Management Interfaces
// ============================================

export interface TabState {
  id: number;
  url: string;
  origin: string;
  title: string;
  isScanning: boolean;
  lastScan?: ScanSummary;
  findings: Vulnerability[];
  environment: Environment;
}

// ============================================
// Utility Types
// ============================================

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};

export interface AsyncResult<T, E = Error> {
  success: boolean;
  data?: T;
  error?: E;
}

export interface PaginatedResult<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  hasMore: boolean;
}