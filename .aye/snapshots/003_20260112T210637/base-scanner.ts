import { IScannerModule, ScannerCategory, ScannerConfig, ScanContext, ScanResult } from '../types/scanner';
import { Vulnerability, Severity } from '../types/vulnerability';
import { generateId } from '../utils/crypto-utils';
import logger from '../utils/logger';

export abstract class BaseScanner implements IScannerModule {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly category: ScannerCategory;
  abstract readonly version: string;

  protected config: ScannerConfig = { enabled: true, severity: ['critical', 'high', 'medium', 'low', 'info'], timeout: 30000, maxFindings: 100 };
  protected findings: Vulnerability[] = [];
  protected abortController: AbortController | null = null;

  get enabled(): boolean { return this.config.enabled; }

  async initialize(config: ScannerConfig): Promise<void> {
    this.config = { ...this.config, ...config };
    logger.debug(this.id, 'Initialized', this.config);
  }

  async scan(context: ScanContext): Promise<ScanResult> {
    this.findings = [];
    this.abortController = new AbortController();
    const startTime = Date.now();
    let status: 'completed' | 'failed' | 'cancelled' = 'completed';
    let error: string | undefined;

    try {
      logger.info(this.id, `Scanning ${context.url}`);
      await Promise.race([
        this.performScan(context),
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('Timeout')), this.config.timeout))
      ]);
      this.findings = this.findings.filter(f => this.config.severity.includes(f.severity)).slice(0, this.config.maxFindings);
      logger.info(this.id, `Found ${this.findings.length} issues`);
    } catch (err) {
      if (err instanceof Error) {
        status = err.name === 'AbortError' ? 'cancelled' : 'failed';
        error = err.message;
      }
      logger.error(this.id, `Failed: ${error}`);
    }

    return {
      scannerId: this.id, scannerName: this.name, category: this.category, status,
      findings: this.findings, scanDuration: Date.now() - startTime, startTime, endTime: Date.now(), error, metadata: { scannerId: this.id, version: this.version }
    };
  }

  protected abstract performScan(context: ScanContext): Promise<void>;

  protected addFinding(finding: Omit<Vulnerability, 'id' | 'timestamp'>): void {
    this.findings.push({ ...finding, id: generateId(), timestamp: Date.now() });
  }

  protected createFinding(partial: Partial<Vulnerability> & { type: Vulnerability['type']; severity: Severity; title: string }): Vulnerability {
    return {
      id: generateId(), timestamp: Date.now(), description: '', location: { type: 'script' },
      impact: { description: '', exploitScenario: '', dataAtRisk: [] },
      remediation: { summary: '', steps: [], references: [], timeEstimate: '30 minutes', difficulty: 'medium' },
      evidence: '', maskedEvidence: '', context: '', environment: 'unknown',
      falsePositive: false, confirmed: false, tags: [], metadata: {}, ...partial
    };
  }

  async cleanup(): Promise<void> {
    this.abortController?.abort();
    this.abortController = null;
    this.findings = [];
  }

  getConfig(): ScannerConfig { return { ...this.config }; }
  setConfig(config: Partial<ScannerConfig>): void { this.config = { ...this.config, ...config }; }
  protected isAborted(): boolean { return this.abortController?.signal.aborted ?? false; }
}