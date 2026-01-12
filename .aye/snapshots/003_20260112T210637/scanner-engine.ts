import { IScannerModule, ScanContext, ScanResult, ScanOptions, ScanProgress } from '../types/scanner';
import { Vulnerability } from '../types/vulnerability';
import { generateId } from '../utils/crypto-utils';
import { getDomain } from '../utils/url-utils';
import { detectEnvironment } from '../core/environment-detector';
import logger from '../utils/logger';
import { APIKeyScanner } from './secrets/api-key-scanner';
import { HeaderScanner } from './headers/header-scanner';
import { LocalStorageScanner } from './storage/local-storage-scanner';
import { CookieScanner } from './storage/cookie-scanner';
import { JWTAnalyzer } from './authentication/jwt-analyzer';
import { PIIDetector } from './data-exposure/pii-detector';

export class ScannerEngine {
  private scanners: Map<string, IScannerModule> = new Map();
  private activeScan: { id: string; context: ScanContext; progress: ScanProgress } | null = null;
  private progressCallback?: (progress: ScanProgress) => void;

  constructor() {
    [new APIKeyScanner(), new HeaderScanner(), new LocalStorageScanner(), new CookieScanner(), new JWTAnalyzer(), new PIIDetector()]
      .forEach(s => this.scanners.set(s.id, s));
    logger.info('ScannerEngine', `Initialized with ${this.scanners.size} scanners`);
  }

  registerScanner(scanner: IScannerModule): void { this.scanners.set(scanner.id, scanner); }
  getScanner(id: string): IScannerModule | undefined { return this.scanners.get(id); }
  getAllScanners(): IScannerModule[] { return Array.from(this.scanners.values()); }
  getEnabledScanners(): IScannerModule[] { return this.getAllScanners().filter(s => s.enabled); }
  onProgress(callback: (progress: ScanProgress) => void): void { this.progressCallback = callback; }

  async scan(url: string, tabId: number, options: ScanOptions = {}, domData?: { scripts?: { src?: string; content: string }[]; localStorage?: Record<string, string>; sessionStorage?: Record<string, string>; cookies?: string; html?: string }): Promise<{ results: ScanResult[]; findings: Vulnerability[] }> {
    const scanId = generateId();
    const context: ScanContext = {
      url, domain: getDomain(url), protocol: new URL(url).protocol, tabId, scanId, timestamp: Date.now(),
      environment: detectEnvironment({ url, html: domData?.html, scripts: domData?.scripts?.map(s => s.src || '') }),
      ...options.context
    };

    let scannersToRun = this.getEnabledScanners();
    if (options.scanners?.length) scannersToRun = scannersToRun.filter(s => options.scanners!.includes(s.id));

    this.activeScan = {
      id: scanId, context,
      progress: { scanId, currentScanner: '', completedScanners: [], totalScanners: scannersToRun.length, findingsCount: 0, progress: 0, status: 'running' }
    };

    logger.info('ScannerEngine', `Starting scan ${scanId} for ${url}`);
    const results: ScanResult[] = [];
    const allFindings: Vulnerability[] = [];

    for (let i = 0; i < scannersToRun.length; i++) {
      const scanner = scannersToRun[i];
      if (!this.activeScan || this.activeScan.progress.status === 'cancelled') break;

      this.activeScan.progress.currentScanner = scanner.name;
      this.activeScan.progress.progress = (i / scannersToRun.length) * 100;
      this.emitProgress();

      try {
        const result = await scanner.scan({ ...context, domData } as ScanContext & { domData?: typeof domData });
        results.push(result);
        allFindings.push(...result.findings);
        this.activeScan.progress.completedScanners.push(scanner.id);
        this.activeScan.progress.findingsCount = allFindings.length;
      } catch (error) {
        logger.error('ScannerEngine', `Scanner ${scanner.id} failed`, error);
        results.push({ scannerId: scanner.id, scannerName: scanner.name, category: scanner.category, status: 'failed', findings: [], scanDuration: 0, startTime: Date.now(), endTime: Date.now(), error: error instanceof Error ? error.message : 'Unknown error', metadata: {} });
      }
    }

    if (this.activeScan) {
      this.activeScan.progress.status = 'completed';
      this.activeScan.progress.progress = 100;
      this.emitProgress();
    }
    this.activeScan = null;
    logger.info('ScannerEngine', `Scan ${scanId} completed with ${allFindings.length} findings`);
    return { results, findings: allFindings };
  }

  cancelScan(): void {
    if (this.activeScan) {
      this.activeScan.progress.status = 'cancelled';
      logger.info('ScannerEngine', `Scan ${this.activeScan.id} cancelled`);
    }
  }

  getProgress(): ScanProgress | null { return this.activeScan?.progress ?? null; }
  private emitProgress(): void { if (this.progressCallback && this.activeScan) this.progressCallback({ ...this.activeScan.progress }); }

  async cleanup(): Promise<void> {
    this.cancelScan();
    for (const scanner of this.scanners.values()) await scanner.cleanup();
  }
}

export const scannerEngine = new ScannerEngine();