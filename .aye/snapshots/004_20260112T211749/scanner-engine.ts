import { IScannerModule, ScanContext, ScanResult, ScanOptions, ScanProgress, Vulnerability, DOMData } from '../types';
import { generateId, getDomain, detectEnvironment } from '../utils/helpers';
import logger from '../utils/logger';
import { APIKeyScanner } from './api-key-scanner';
import { HeaderScanner } from './header-scanner';
import { StorageScanner } from './storage-scanner';
import { CookieScanner } from './cookie-scanner';
import { PIIScanner } from './pii-scanner';

export class ScannerEngine {
  private scanners: Map<string, IScannerModule> = new Map();
  private activeScan: { id: string; context: ScanContext; progress: ScanProgress } | null = null;
  private progressCallback?: (progress: ScanProgress) => void;

  constructor() {
    const defaultScanners: IScannerModule[] = [
      new APIKeyScanner(),
      new HeaderScanner(),
      new StorageScanner(),
      new CookieScanner(),
      new PIIScanner(),
    ];
    defaultScanners.forEach(s => this.scanners.set(s.id, s));
    logger.info('ScannerEngine', `Initialized with ${this.scanners.size} scanners`);
  }

  getAllScanners(): IScannerModule[] { return Array.from(this.scanners.values()); }
  getEnabledScanners(): IScannerModule[] { return this.getAllScanners().filter(s => s.enabled); }
  onProgress(callback: (progress: ScanProgress) => void): void { this.progressCallback = callback; }

  async scan(url: string, tabId: number, options: ScanOptions = {}, domData?: DOMData): Promise<{ results: ScanResult[]; findings: Vulnerability[] }> {
    const scanId = generateId();
    const context: ScanContext = {
      url,
      domain: getDomain(url),
      protocol: new URL(url).protocol,
      tabId,
      scanId,
      timestamp: Date.now(),
      environment: detectEnvironment(url, domData?.html),
      domData,
    };

    let scannersToRun = this.getEnabledScanners();
    if (options.scanners?.length) {
      scannersToRun = scannersToRun.filter(s => options.scanners!.includes(s.id));
    }

    this.activeScan = {
      id: scanId,
      context,
      progress: {
        scanId,
        currentScanner: '',
        completedScanners: [],
        totalScanners: scannersToRun.length,
        findingsCount: 0,
        progress: 0,
        status: 'running',
      },
    };

    logger.info('ScannerEngine', `Starting scan ${scanId} with ${scannersToRun.length} scanners`);
    const results: ScanResult[] = [];
    const allFindings: Vulnerability[] = [];

    for (let i = 0; i < scannersToRun.length; i++) {
      const scanner = scannersToRun[i];
      if (!this.activeScan || this.activeScan.progress.status === 'cancelled') break;

      this.activeScan.progress.currentScanner = scanner.name;
      this.activeScan.progress.progress = (i / scannersToRun.length) * 100;
      this.emitProgress();

      try {
        const result = await scanner.scan(context);
        results.push(result);
        allFindings.push(...result.findings);
        this.activeScan.progress.completedScanners.push(scanner.id);
        this.activeScan.progress.findingsCount = allFindings.length;
      } catch (error) {
        logger.error('ScannerEngine', `Scanner ${scanner.id} failed`, error);
        results.push({
          scannerId: scanner.id,
          scannerName: scanner.name,
          category: scanner.category,
          status: 'failed',
          findings: [],
          scanDuration: 0,
          startTime: Date.now(),
          endTime: Date.now(),
          error: error instanceof Error ? error.message : 'Unknown',
          metadata: {},
        });
      }
    }

    if (this.activeScan) {
      this.activeScan.progress.status = 'completed';
      this.activeScan.progress.progress = 100;
      this.emitProgress();
    }
    this.activeScan = null;

    logger.info('ScannerEngine', `Scan completed with ${allFindings.length} findings`);
    return { results, findings: allFindings };
  }

  cancelScan(): void {
    if (this.activeScan) {
      this.activeScan.progress.status = 'cancelled';
      logger.info('ScannerEngine', 'Scan cancelled');
    }
  }

  getProgress(): ScanProgress | null { return this.activeScan?.progress ?? null; }

  private emitProgress(): void {
    if (this.progressCallback && this.activeScan) {
      this.progressCallback({ ...this.activeScan.progress });
    }
  }

  async cleanup(): Promise<void> {
    this.cancelScan();
    for (const scanner of this.scanners.values()) await scanner.cleanup();
  }
}

export const scannerEngine = new ScannerEngine();