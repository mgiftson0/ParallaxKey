export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type VulnerabilityType =
  | 'secret_exposure'
  | 'api_key_exposed'
  | 'insecure_header'
  | 'cors_misconfiguration'
  | 'pii_exposure'
  | 'insecure_storage'
  | 'jwt_vulnerability'
  | 'session_vulnerability'
  | 'debug_exposure'
  | 'version_disclosure'
  | 'insecure_cookie';

export type LocationType = 'script' | 'storage' | 'network' | 'html' | 'cookie' | 'header' | 'url';
export type Environment = 'development' | 'production' | 'staging' | 'unknown';
export type ScanStatus = 'idle' | 'running' | 'completed' | 'failed' | 'cancelled';
export type ScannerCategory = 'secrets' | 'network' | 'storage' | 'authentication' | 'headers' | 'data-exposure';

export interface VulnerabilityLocation {
  type: LocationType;
  url?: string;
  line?: number;
  column?: number;
  storageKey?: string;
}

export interface RemediationStep {
  order: number;
  title: string;
  description: string;
  codeExample?: { vulnerable: string; secure: string; language: string };
}

export interface Remediation {
  summary: string;
  steps: RemediationStep[];
  references: string[];
  timeEstimate: string;
  difficulty: 'easy' | 'medium' | 'hard';
}

export interface Impact {
  description: string;
  exploitScenario: string;
  dataAtRisk: string[];
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  location: VulnerabilityLocation;
  impact: Impact;
  remediation: Remediation;
  evidence: string;
  maskedEvidence: string;
  context: string;
  timestamp: number;
  environment: Environment;
  falsePositive: boolean;
  confirmed: boolean;
  tags: string[];
  metadata: Record<string, unknown>;
}

export interface ScannerConfig {
  enabled: boolean;
  severity: Severity[];
  timeout: number;
  maxFindings: number;
}

export interface ScanContext {
  url: string;
  domain: string;
  protocol: string;
  tabId: number;
  environment: Environment;
  timestamp: number;
  scanId: string;
  domData?: DOMData;
}

export interface ScanResult {
  scannerId: string;
  scannerName: string;
  category: ScannerCategory;
  status: ScanStatus;
  findings: Vulnerability[];
  scanDuration: number;
  startTime: number;
  endTime: number;
  error?: string;
  metadata: Record<string, unknown>;
}

export interface ScanProgress {
  scanId: string;
  currentScanner: string;
  completedScanners: string[];
  totalScanners: number;
  findingsCount: number;
  progress: number;
  status: ScanStatus;
}

export interface ScanOptions {
  scanners?: string[];
  depth?: 'quick' | 'standard' | 'deep';
  includeInfo?: boolean;
  timeout?: number;
}

export interface DOMData {
  scripts: { src?: string; content: string }[];
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  cookies: string;
  html: string;
}

export interface Settings {
  appearance: { theme: 'light' | 'dark' | 'system'; compactMode: boolean; showBadgeCount: boolean };
  notifications: { enabled: boolean; minSeverity: Severity };
  autoScanOnNavigation: boolean;
  activeProfileId: string;
  findingsRetentionDays: number;
}

export const DEFAULT_SETTINGS: Settings = {
  appearance: { theme: 'system', compactMode: false, showBadgeCount: true },
  notifications: { enabled: true, minSeverity: 'high' },
  autoScanOnNavigation: false,
  activeProfileId: 'standard',
  findingsRetentionDays: 30,
};

export interface IScannerModule {
  id: string;
  name: string;
  description: string;
  category: ScannerCategory;
  version: string;
  enabled: boolean;
  scan(context: ScanContext): Promise<ScanResult>;
  cleanup(): Promise<void>;
}