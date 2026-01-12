/**
 * VaultGuard Scanner Orchestrator
 * Coordinates scanning across content scripts and background
 */

import { scannerEngine } from '../scanners/scanner-engine';
import type {
  ScanContext,
  ScanSummary,
  ScanOptions as StartScanPayload,
  Vulnerability,
  StorageItem,
} from '../types';
import { logger } from '../utils/logger';
import { detectEnvironment } from '../core/environment-detector';
import { getOrigin } from '../utils/url-utils';

export class ScannerOrchestrator {
  private activeScanTabId: number | null = null;
  private scanResults: Map<number, ScanSummary> = new Map();

  /**
   * Start a scan for a tab
   */
  async startScan(tabId: number, options?: StartScanPayload): Promise<ScanSummary> {
    logger.info('ScannerOrchestrator', `Starting scan for tab ${tabId}`, options);

    this.activeScanTabId = tabId;

    // Get tab info
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url ?? '';

    // Detect environment
    const envResult = detectEnvironment({ url });

    // Create scan context
    const context: ScanContext = {
      url,
      domain: new URL(url).hostname,
      tabId,
      origin: getOrigin(url),
      options: { type: options?.depth || 'standard' },
      environment: envResult,
      timestamp: Date.now(),
      config: {
        enabled: true,
        severity: 'low',
        timeout: 60000,
      },
    };

    // Run scan
    let summary: ScanSummary;

    if (options?.type === 'quick') {
      summary = await scannerEngine.runQuickScan(context);
    } else {
      summary = await scannerEngine.runFullScan(context);
    }

    this.scanResults.set(tabId, summary);
    this.activeScanTabId = null;

    // Notify popup/devtools of completion
    this.notifyScanComplete(tabId, summary);

    return summary;
  }

  /**
   * Stop active scan
   */
  stopScan(): void {
    if (this.activeScanTabId !== null) {
      logger.info('ScannerOrchestrator', 'Stopping scan');
      scannerEngine.cancelScan();
      this.activeScanTabId = null;
    }
  }

  /**
   * Process DOM analysis from content script
   */
  async processDOMAnalysis(
    tabId: number,
    data: unknown
  ): Promise<Vulnerability[]> {
    logger.debug('ScannerOrchestrator', 'Processing DOM analysis', { tabId });

    if (!data || typeof data !== 'object') return [];

    const { scripts, html } = data as { scripts?: string[]; html?: string };
    const findings: Vulnerability[] = [];

    // Get tab info for context
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url ?? '';
    const envResult = detectEnvironment({ url });

    const context: ScanContext = {
      url,
      domain: new URL(url).hostname,
      tabId,
      origin: getOrigin(url),
      options: { type: 'standard' },
      environment: envResult,
      timestamp: Date.now(),
      config: {
        enabled: true,
        severity: 'low',
      },
    };

    // Scan inline scripts
    const apiKeyScanner = scannerEngine.getScanner('api-key-scanner');
    if (apiKeyScanner && scripts) {
      for (const script of scripts) {
        const scriptFindings = (apiKeyScanner as any).scanText(script, url, context);
        findings.push(...scriptFindings);
      }
    }

    // Scan HTML
    if (html && apiKeyScanner) {
      const htmlFindings = (apiKeyScanner as any).scanText(html, url, context);
      findings.push(...htmlFindings);
    }

    return findings;
  }

  /**
   * Process storage analysis from content script
   */
  async processStorageAnalysis(
    tabId: number,
    data: unknown
  ): Promise<Vulnerability[]> {
    logger.debug('ScannerOrchestrator', 'Processing storage analysis', { tabId });

    if (!data || typeof data !== 'object') return [];

    const { localStorage, sessionStorage, cookies } = data as {
      localStorage?: StorageItem[];
      sessionStorage?: StorageItem[];
      cookies?: string;
    };

    const findings: Vulnerability[] = [];

    // Get context
    const tab = await chrome.tabs.get(tabId);
    const url = tab.url ?? '';
    const envResult = detectEnvironment({ url });

    const context: ScanContext = {
      url,
      domain: new URL(url).hostname,
      tabId,
      origin: getOrigin(url),
      options: { type: 'standard' },
      environment: envResult,
      timestamp: Date.now(),
      config: {
        enabled: true,
        severity: 'low',
      },
    };

    // Scan localStorage
    const localStorageScanner = scannerEngine.getScanner('local-storage-scanner');
    if (localStorageScanner && localStorage) {
      const lsFindings = (localStorageScanner as any).analyzeStorage(localStorage, context);
      findings.push(...lsFindings);
    }

    // Scan sessionStorage
    if (localStorageScanner && sessionStorage) {
      const ssFindings = (localStorageScanner as any).analyzeStorage(sessionStorage, context);
      findings.push(...ssFindings);
    }

    // Scan cookies
    const cookieScanner = scannerEngine.getScanner('cookie-scanner');
    if (cookieScanner && cookies) {
      const cookieFindings = (cookieScanner as any).analyzeCookies(cookies, context);
      findings.push(...cookieFindings);
    }

    return findings;
  }

  /**
   * Get scan results for a tab
   */
  getResults(tabId: number): ScanSummary | undefined {
    return this.scanResults.get(tabId);
  }

  /**
   * Clear results for a tab
   */
  clearResults(tabId: number): void {
    this.scanResults.delete(tabId);
  }

  /**
   * Check if scan is in progress
   */
  isScanning(): boolean {
    return this.activeScanTabId !== null;
  }

  /**
   * Notify of scan completion
   */
  private notifyScanComplete(tabId: number, summary: ScanSummary): void {
    // Send message to popup/devtools
    chrome.runtime.sendMessage({
      type: 'SCAN_COMPLETE',
      payload: { tabId, summary },
      timestamp: Date.now(),
    }).catch(() => {
      // Ignore errors if no listener
    });
  }
}