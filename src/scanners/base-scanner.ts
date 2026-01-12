import { Vulnerability, ScannerCategory, ScannerConfig, ScanContext, ScannerResult } from '../types';
import { logger } from '../utils/logger';

export abstract class BaseScanner {
  abstract readonly name: string;
  abstract readonly category: ScannerCategory;

  protected enabled = true;
  protected timeout = 30000;
  protected priority = 50;

  get config(): ScannerConfig {
    return { name: this.name, category: this.category, enabled: this.enabled, priority: this.priority, timeout: this.timeout };
  }

  async initialize(): Promise<void> { logger.debug(this.name, 'Initialized'); }
  abstract scan(context: ScanContext): Promise<ScannerResult>;
  async cleanup(): Promise<void> { logger.debug(this.name, 'Cleanup'); }
  isEnabled(): boolean { return this.enabled; }
  setEnabled(val: boolean) { this.enabled = val; }

  protected createResult(vulns: Vulnerability[], startTime: number, error?: string): ScannerResult {
    return { scanner: this.name, vulnerabilities: vulns, duration: Date.now() - startTime, error };
  }

  protected async executeScan(context: ScanContext, fn: () => Promise<Vulnerability[]>): Promise<ScannerResult> {
    const start = Date.now();
    if (!this.enabled) return this.createResult([], start);
    try {
      const vulns = await fn();
      logger.debug(this.name, `Found ${vulns.length} issues`);
      return this.createResult(vulns, start);
    } catch (e: any) {
      logger.error(this.name, `Error: ${e.message}`);
      return this.createResult([], start, e.message);
    }
  }
}