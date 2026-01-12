/**
 * VaultGuard Scanner Engine
 * Orchestrates all scanners and manages scan workflows
 */

import type {
  ScanContext,
  ScanResult,
  ScanSummary,
  ScannerType,
  Severity,
  Vulnerability,
  Environment,
} from '../types';
import { BaseScanner } from './base-scanner';
import { APIKeyScanner } from './secrets/api-key-scanner';
import { HeaderScanner } from './network/header-scanner';
import { RequestAnalyzer } from './network/request-analyzer';
import { LocalStorageScanner } from './storage/local-storage-scanner';
import { CookieScanner } from './storage/cookie-scanner';
import { logger } from '../utils/logger';
import { generateId } from '../utils/crypto-utils';
import { countBySeverity } from '../core/vulnerability';

export class ScannerEngine {
  private scanners: Map<string, BaseScanner> = new Map();
  private activeScan: string | null = null;
  private scanHistory: ScanSummary[] = [];
  
  constructor() {
    this.registerDefaultScanners();
  }
  
  /**
   * Register default scanners
   */
  private registerDefaultScanners(): void {
    this.registerScanner(new APIKeyScanner());
    this.registerScanner(new HeaderScanner());
    this.registerScanner(new RequestAnalyzer());
    this.registerScanner(new LocalStorageScanner());
    this.registerScanner(new CookieScanner());
  }
  
  /**
   * Register a scanner
   */
  registerScanner(scanner: BaseScanner): void {
    this.scanners.set(scanner.id, scanner);
    logger.info('ScannerEngine', `Registered scanner: ${scanner.id}`);
  }
  
  /**
   * Unregister a scanner
   */
  unregisterScanner(id: string): boolean {
    return this.scanners.delete(id);
  }
  
  /**
   * Get all registered scanners
   */
  getScanners(): BaseScanner[] {
    return Array.from(this.scanners.values());
  }
  
  /**
   * Get scanner by ID
   */
  getScanner(id: string): BaseScanner | undefined {
    return this.scanners.get(id);
  }
  
  /**
   * Get scanners by type
   */
  getScannersByType(type: ScannerType): BaseScanner[] {
    return this.getScanners().filter((s) => s.type === type);
  }
  
  /**
   * Check if a scan is in progress
   */
  isScanning(): boolean {
    return this.activeScan !== null;
  }
  
  /**
   * Run a full scan
   */
  async runFullScan(context: ScanContext): Promise<ScanSummary> {
    const scanId = generateId();
    this.activeScan = scanId;
    
    logger.info('ScannerEngine', `Starting full scan: ${scanId}`, { url: context.url });
    
    const startTime = Date.now();
    const results: ScanResult[] = [];
    const enabledScanners = this.getScanners().filter((s) => s.isEnabled());
    
    for (const scanner of enabledScanners) {
      if (this.activeScan !== scanId) {
        logger.warn('ScannerEngine', 'Scan was cancelled');
        break;
      }
      
      try {
        const result = await scanner.execute(context);
        results.push(result);
      } catch (error) {
        logger.error('ScannerEngine', `Scanner ${scanner.id} failed`, error);
      }
    }
    
    const summary = this.createSummary(scanId, context, results, startTime);
    this.scanHistory.push(summary);
    this.activeScan = null;
    
    logger.info('ScannerEngine', `Scan complete: ${summary.totalVulnerabilities} findings`, {
      duration: summary.duration,
    });
    
    return summary;
  }
  
  /**
   * Run quick scan (critical scanners only)
   */
  async runQuickScan(context: ScanContext): Promise<ScanSummary> {
    const scanId = generateId();
    this.activeScan = scanId;
    
    logger.info('ScannerEngine', `Starting quick scan: ${scanId}`);
    
    const startTime = Date.now();
    const results: ScanResult[] = [];
    
    // Quick scan: only secrets and critical network checks
    const quickScanners = ['api-key-scanner', 'header-scanner'];
    
    for (const scannerId of quickScanners) {
      const scanner = this.scanners.get(scannerId);
      if (scanner && scanner.isEnabled()) {
        const result = await scanner.execute(context);
        results.push(result);
      }
    }
    
    const summary = this.createSummary(scanId, context, results, startTime);
    this.scanHistory.push(summary);
    this.activeScan = null;
    
    return summary;
  }
  
  /**
   * Run specific scanners
   */
  async runScanners(
    context: ScanContext,
    scannerIds: string[]
  ): Promise<ScanSummary> {
    const scanId = generateId();
    this.activeScan = scanId;
    
    const startTime = Date.now();
    const results: ScanResult[] = [];
    
    for (const scannerId of scannerIds) {
      const scanner = this.scanners.get(scannerId);
      if (scanner) {
        const result = await scanner.execute(context);
        results.push(result);
      }
    }
    
    const summary = this.createSummary(scanId, context, results, startTime);
    this.scanHistory.push(summary);
    this.activeScan = null;
    
    return summary;
  }
  
  /**
   * Cancel active scan
   */
  cancelScan(): void {
    if (this.activeScan) {
      logger.info('ScannerEngine', `Cancelling scan: ${this.activeScan}`);
      this.activeScan = null;
    }
  }
  
  /**
   * Get scan history
   */
  getHistory(): ScanSummary[] {
    return [...this.scanHistory];
  }
  
  /**
   * Clear scan history
   */
  clearHistory(): void {
    this.scanHistory = [];
  }
  
  /**
   * Create scan summary from results
   */
  private createSummary(
    scanId: string,
    context: ScanContext,
    results: ScanResult[],
    startTime: number
  ): ScanSummary {
    const allVulnerabilities: Vulnerability[] = [];
    const byType: Record<ScannerType, number> = {
      secrets: 0,
      network: 0,
      storage: 0,
      javascript: 0,
      authentication: 0,
      headers: 0,
      'data-exposure': 0,
      database: 0,
      infrastructure: 0,
      'third-party': 0,
    };
    
    for (const result of results) {
      allVulnerabilities.push(...result.vulnerabilities);
      byType[result.scannerType] += result.vulnerabilities.length;
    }
    
    const bySeverity = countBySeverity(allVulnerabilities);
    
    return {
      id: scanId,
      url: context.url,
      timestamp: startTime,
      duration: Date.now() - startTime,
      environment: context.environment,
      results,
      totalVulnerabilities: allVulnerabilities.length,
      bySeverity,
      byType,
    };
  }
}

// Singleton instance
export const scannerEngine = new ScannerEngine();