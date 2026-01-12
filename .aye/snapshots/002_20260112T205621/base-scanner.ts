/**
 * VaultGuard Base Scanner
 * Abstract base class for all scanners
 */

import type {
  Vulnerability,
  ScannerType,
  ScanContext,
  ScanResult,
  ScannerConfig,
} from '../types';
import { logger } from '../utils/logger';
import { generateId } from '../utils/crypto-utils';

export abstract class BaseScanner {
  abstract readonly id: string;
  abstract readonly name: string;
  abstract readonly type: ScannerType;
  abstract readonly description: string;
  
  protected config: ScannerConfig = {
    enabled: true,
    severity: 'medium',
    timeout: 30000,
  };
  
  protected vulnerabilities: Vulnerability[] = [];
  protected startTime: number = 0;
  protected itemsScanned: number = 0;
  
  /**
   * Main scan method - must be implemented by subclasses
   */
  abstract scan(context: ScanContext): Promise<void>;
  
  /**
   * Configure the scanner
   */
  configure(config: Partial<ScannerConfig>): void {
    this.config = { ...this.config, ...config };
  }
  
  /**
   * Check if scanner is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }
  
  /**
   * Run the scanner with timing and error handling
   */
  async execute(context: ScanContext): Promise<ScanResult> {
    this.reset();
    this.startTime = Date.now();
    
    logger.info(this.id, `Starting scan for ${context.url}`);
    
    try {
      // Create a timeout promise
      const timeout = this.config.timeout ?? 30000;
      const timeoutPromise = new Promise<void>((_, reject) => {
        setTimeout(() => reject(new Error('Scan timeout')), timeout);
      });
      
      // Race between scan and timeout
      await Promise.race([this.scan(context), timeoutPromise]);
      
      const result = this.getResult();
      logger.info(this.id, `Scan complete: ${result.vulnerabilities.length} findings`, {
        duration: result.duration,
        itemsScanned: result.itemsScanned,
      });
      
      return result;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      logger.error(this.id, `Scan failed: ${errorMessage}`);
      
      return {
        scannerId: this.id,
        scannerType: this.type,
        vulnerabilities: this.vulnerabilities,
        duration: Date.now() - this.startTime,
        itemsScanned: this.itemsScanned,
        timestamp: Date.now(),
        error: errorMessage,
      };
    }
  }
  
  /**
   * Add a vulnerability to the results
   */
  protected addVulnerability(vulnerability: Vulnerability): void {
    this.vulnerabilities.push(vulnerability);
  }
  
  /**
   * Increment items scanned counter
   */
  protected incrementScanned(count: number = 1): void {
    this.itemsScanned += count;
  }
  
  /**
   * Reset scanner state
   */
  protected reset(): void {
    this.vulnerabilities = [];
    this.itemsScanned = 0;
    this.startTime = 0;
  }
  
  /**
   * Get scan result
   */
  protected getResult(): ScanResult {
    return {
      scannerId: this.id,
      scannerType: this.type,
      vulnerabilities: this.vulnerabilities,
      duration: Date.now() - this.startTime,
      itemsScanned: this.itemsScanned,
      timestamp: Date.now(),
    };
  }
  
  /**
   * Check if pattern should be excluded
   */
  protected isExcluded(value: string): boolean {
    const excludePatterns = this.config.excludePatterns ?? [];
    return excludePatterns.some((pattern) => {
      const regex = new RegExp(pattern, 'i');
      return regex.test(value);
    });
  }
  
  /**
   * Generate unique finding ID
   */
  protected generateFindingId(): string {
    return `${this.id}-${generateId()}`;
  }
}