/**
 * VaultGuard Tab Manager
 * Manages tab state and findings
 */

import type { TabState, Vulnerability, Environment } from '../types';
import { logger } from '../utils/logger';
import { detectEnvironment } from '../core/environment-detector';
import { getOrigin } from '../utils/url-utils';

export class TabManager {
  private tabs: Map<number, TabState> = new Map();
  private readyTabs: Set<number> = new Set();

  /**
   * Update tab information
   */
  updateTab(tabId: number, url: string, title: string): void {
    const environment = detectEnvironment({ url });

    const existing = this.tabs.get(tabId);

    const state: TabState = {
      id: tabId,
      url,
      origin: getOrigin(url),
      title,
      status: existing?.status ?? 'idle',
      lastScan: existing?.lastScan,
      vulnerabilities: existing?.vulnerabilities ?? [],
      environment,
      isRestricted: url.startsWith('chrome://') || url.startsWith('edge://'),
    };

    this.tabs.set(tabId, state);
    logger.debug('TabManager', `Tab ${tabId} updated`, { url, environment: state.environment });
  }

  /**
   * Remove a tab
   */
  removeTab(tabId: number): void {
    this.tabs.delete(tabId);
    this.readyTabs.delete(tabId);
    logger.debug('TabManager', `Tab ${tabId} removed`);
  }

  /**
   * Get tab state
   */
  getTab(tabId: number): TabState | undefined {
    return this.tabs.get(tabId);
  }

  /**
   * Get all tabs
   */
  getAllTabs(): TabState[] {
    return Array.from(this.tabs.values());
  }

  /**
   * Mark tab as ready (content script loaded)
   */
  markTabReady(tabId: number): void {
    this.readyTabs.add(tabId);
    logger.debug('TabManager', `Tab ${tabId} ready`);
  }

  /**
   * Check if tab is ready
   */
  isTabReady(tabId: number): boolean {
    return this.readyTabs.has(tabId);
  }

  /**
   * Set scanning status
   */
  setScanning(tabId: number, isScanning: boolean): void {
    const tab = this.tabs.get(tabId);
    if (tab) {
      tab.status = isScanning ? 'scanning' : 'complete';
    }
  }

  /**
   * Add findings to a tab
   */
  addFindings(tabId: number, findings: Vulnerability[]): void {
    const tab = this.tabs.get(tabId);
    if (tab) {
      tab.vulnerabilities.push(...findings);
      logger.debug('TabManager', `Added ${findings.length} findings to tab ${tabId}`);
    }
  }

  /**
   * Get findings for a tab
   */
  getTabFindings(tabId: number): Vulnerability[] {
    return this.tabs.get(tabId)?.vulnerabilities ?? [];
  }

  /**
   * Clear findings for a tab
   */
  clearTabFindings(tabId: number): void {
    const tab = this.tabs.get(tabId);
    if (tab) {
      tab.vulnerabilities = [];
    }
  }

  /**
   * Get tabs by environment
   */
  getTabsByEnvironment(environment: Environment): TabState[] {
    return Array.from(this.tabs.values()).filter(
      (tab) => tab.environment === environment
    );
  }

  /**
   * Get active scan count
   */
  getActiveScanCount(): number {
    return Array.from(this.tabs.values()).filter((tab) => tab.status === 'scanning').length;
  }

  /**
   * Get total findings count
   */
  getTotalFindingsCount(): number {
    return Array.from(this.tabs.values()).reduce(
      (sum, tab) => sum + tab.vulnerabilities.length,
      0
    );
  }
}