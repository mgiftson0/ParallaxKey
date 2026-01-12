import { Vulnerability, Severity, Environment } from './vulnerability';

export type ScannerCategory =
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

export type ScanStatus = 'idle' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScannerConfig {
  enabled: boolean;
  severity: Severity[];
  customPatterns?: RegExp[];
  excludePatterns?: RegExp[];
  timeout: number;
  maxFindings: number;
}

export interface ScanContext {
  url: string;
  domain: string;
  protocol: string;
  tabId: number;
  frameId?: number;
  environment: Environment;
  timestamp: number;
  scanId: string;
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

export interface ScanOptions {
  scanners?: string[];
  depth?: 'quick' | 'standard' | 'deep';
  includeInfo?: boolean;
  timeout?: number;
  context?: Partial<ScanContext>;
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

export interface IScannerModule {
  id: string;
  name: string;
  description: string;
  category: ScannerCategory;
  version: string;
  enabled: boolean;
  initialize(config: ScannerConfig): Promise<void>;
  scan(context: ScanContext): Promise<ScanResult>;
  cleanup(): Promise<void>;
  getConfig(): ScannerConfig;
  setConfig(config: Partial<ScannerConfig>): void;
}