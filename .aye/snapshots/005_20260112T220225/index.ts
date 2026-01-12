// ============================================================================
// VaultGuard - Complete Type Definitions
// ============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Environment = 'development' | 'production' | 'staging' | 'unknown';
export type ScanStatus = 'idle' | 'scanning' | 'completed' | 'error';
export type ScanType = 'quick' | 'standard' | 'deep';
export type LocationType = 'script' | 'storage' | 'network' | 'html' | 'cookie' | 'header' | 'url';

export type VulnerabilityCategory =
  | 'secret_exposure'
  | 'network_security'
  | 'storage_security'
  | 'authentication'
  | 'data_exposure'
  | 'misconfiguration'
  | 'privacy'
  | 'injection'
  | 'broken_access_control'
  | 'insecure_communication';

export type ScannerCategory = VulnerabilityCategory;

export interface Location {
  type: LocationType;
  url?: string;
  storageKey?: string;
  line?: number;
  column?: number;
  element?: string;
  snippet?: string;
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
  category: VulnerabilityCategory;
  severity: Severity;
  title: string;
  description: string;
  location: Location;
  context: string;
  evidence: string;
  impact: Impact;
  remediation: Remediation;
  timestamp: number;
  environment: Environment;
  confidence: number;
  falsePositive: boolean;
  cweId?: string;
  owaspCategory?: string;
  tags: string[];
  metadata?: Record<string, any>;
}

export interface SecretPattern {
  name: string;
  service: string;
  pattern: RegExp;
  severity: Severity;
  context: { mustInclude?: string[]; mustExclude?: string[] };
  description: string;
}

export interface ScanSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Partial<Record<VulnerabilityCategory, number>>;
  riskScore: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
}

export interface ScanMetadata {
  userAgent: string;
  pageTitle: string;
  scriptsAnalyzed: number;
  requestsAnalyzed: number;
  storageItemsAnalyzed: number;
  cookiesAnalyzed: number;
}

export interface ScanResult {
  id: string;
  url: string;
  domain: string;
  scanType: ScanType;
  status: ScanStatus;
  startTime: number;
  endTime?: number;
  duration?: number;
  environment: Environment;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  metadata: ScanMetadata;
}

export interface ScanOptions {
  type: ScanType;
  categories?: VulnerabilityCategory[];
  depth?: 'quick' | 'standard' | 'deep';
}

export interface Settings {
  general: { autoScan: boolean; scanOnNavigation: boolean; showBadge: boolean; debugMode: boolean };
  scanning: {
    defaultScanType: ScanType;
    enabledCategories: VulnerabilityCategory[];
    customPatterns: any[];
    whitelistedDomains: string[];
    blacklistedDomains: string[];
    maxConcurrentScans: number;
    scanTimeout: number;
  };
  notifications: { enabled: boolean; minSeverity: Severity; sound: boolean; desktop: boolean };
  privacy: { collectAnonymousStats: boolean; sharePatterns: boolean; localStorageOnly: boolean };
  appearance: { theme: 'light' | 'dark' | 'system'; compactMode: boolean; showConfidenceScores: boolean };
}

export type VaultGuardSettings = Settings;

export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends (infer U)[]
  ? DeepPartial<U>[]
  : T[P] extends object
  ? DeepPartial<T[P]>
  : T[P];
};

export * from './messages';

export interface NetworkRequest {
  id: string;
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
  type: string;
  tabId?: number;
}

export interface NetworkResponse {
  requestId: string;
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
  size: number;
}

export interface TabState {
  id: number;
  url: string;
  origin: string;
  title?: string;
  status: 'idle' | 'scanning' | 'complete';
  lastScan?: ScanResult;
  vulnerabilities: Vulnerability[];
  environment: Environment;
  isRestricted: boolean;
}

export interface ScriptInfo {
  src?: string;
  inline: boolean;
  content?: string;
  hash: string;
  async: boolean;
  defer: boolean;
  type?: string;
}

export interface FormInfo {
  action: string;
  method: string;
  hasPasswordField: boolean;
  hasFileUpload: boolean;
  autocomplete: string;
  inputs: { type: string; name: string; autocomplete: string; hasPattern: boolean; required: boolean }[];
}

export interface StorageItem {
  key: string;
  value: string;
  size: number;
  type?: 'localStorage' | 'sessionStorage';
  domain?: string;
}

export interface CookieInfo {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  expires?: number;
}

export interface LinkInfo {
  href: string;
  rel: string;
  type?: string;
}

export interface DOMAnalysisResult {
  scripts: ScriptInfo[];
  forms: FormInfo[];
  localStorage: StorageItem[];
  sessionStorage: StorageItem[];
  cookies: CookieInfo[];
  meta: Record<string, string>;
  links: LinkInfo[];
}

export interface ScanContext {
  url: string;
  domain: string;
  origin: string;
  tabId: number;
  options: ScanOptions;
  domAnalysis?: DOMAnalysisResult;
  networkRequests?: NetworkRequest[];
  networkResponses?: NetworkResponse[];
  environment?: Environment;
  timestamp?: number;
  config?: {
    enabled?: boolean;
    severity?: Severity;
    timeout?: number;
  };
}

export interface ScannerResult {
  scanner: string;
  vulnerabilities: Vulnerability[];
  duration: number;
  error?: string;
}

export interface ScannerConfig {
  name: string;
  category: ScannerCategory;
  enabled: boolean;
  priority: number;
  timeout: number;
}
