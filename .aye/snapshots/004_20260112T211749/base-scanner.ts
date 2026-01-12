import { IScannerModule, ScannerCategory, ScanContext, ScanResult, Vulnerability, Severity } from '../types';
import { generateId } from '../utils/helpers';
import logger from '../utils/logger';

export abstract class BaseScanner implements IScannerModule {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly description: string;
  abstract readonly category: ScannerCategory;
  abstract readonly version: string;

  enabled = true;
  protected findings: Vulnerability[] = [];
  protected timeout = 30000;

  async scan(context: ScanContext): Promise<ScanResult> {
    this.findings = [];
    const startTime = Date.now();
    let status: 'completed' | 'failed' = 'completed';
    let error: string | undefined;

    try {
      logger.info(this.id, `Scanning ${context.url}`);
      await Promise.race([
        this.performScan(context),
        new Promise<void>((_, reject) => setTimeout(() => reject(new Error('Timeout')), this.timeout))
      ]);
      logger.info(this.id, `Found ${this.findings.length} issues`);
    } catch (err) {
      status = 'failed';
      error = err instanceof Error ? err.message : 'Unknown error';
      logger.error(this.id, `Failed: ${error}`);
    }

    return {
      scannerId: this.id,
      scannerName: this.name,
      category: this.category,
      status,
      findings: this.findings,
      scanDuration: Date.now() - startTime,
      startTime,
      endTime: Date.now(),
      error,
      metadata: { version: this.version }
    };
  }

  protected abstract performScan(context: ScanContext): Promise<void>;

  protected addFinding(finding: Omit<Vulnerability, 'id' | 'timestamp'>): void {
    this.findings.push({ ...finding, id: generateId(), timestamp: Date.now() });
  }

  protected createFinding(partial: Partial<Vulnerability> & { type: Vulnerability['type']; severity: Severity; title: string }): Vulnerability {
    return {
      id: generateId(),
      timestamp: Date.now(),
      description: '',
      location: { type: 'script' },
      impact: { description: '', exploitScenario: '', dataAtRisk: [] },
      remediation: { summary: '', steps: [], references: [], timeEstimate: '30 min', difficulty: 'medium' },
      evidence: '',
      maskedEvidence: '',
      context: '',
      environment: 'unknown',
      falsePositive: false,
      confirmed: false,
      tags: [],
      metadata: {},
      ...partial
    };
  }

  async cleanup(): Promise<void> {
    this.findings = [];
  }
}