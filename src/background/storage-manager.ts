/**
 * VaultGuard Storage Manager
 * Manages extension settings and data persistence
 */

import type { Settings, VaultGuardSettings, Vulnerability, ScanSummary, DeepPartial } from '../types';
import { logger } from '../utils/logger';

const DEFAULT_SETTINGS: Settings = {
  general: { autoScan: false, scanOnNavigation: false, showBadge: true, debugMode: false },
  scanning: {
    defaultScanType: 'standard',
    enabledCategories: ['secret_exposure', 'network_security', 'storage_security', 'authentication', 'data_exposure', 'misconfiguration'],
    customPatterns: [],
    whitelistedDomains: [],
    blacklistedDomains: [],
    maxConcurrentScans: 3,
    scanTimeout: 300000,
  },
  notifications: { enabled: true, minSeverity: 'medium', sound: false, desktop: true },
  privacy: { collectAnonymousStats: false, sharePatterns: false, localStorageOnly: true },
  appearance: { theme: 'system', compactMode: false, showConfidenceScores: true },
};

export class StorageManager {
  private settingsKey = 'vaultguard_settings';
  private findingsKey = 'vaultguard_findings';
  private historyKey = 'vaultguard_history';

  /**
   * Initialize settings with defaults
   */
  async initializeSettings(): Promise<void> {
    const existing = await this.getSettings();

    if (!existing) {
      await this.saveSettings(DEFAULT_SETTINGS);
      logger.info('StorageManager', 'Initialized default settings');
    }
  }

  /**
   * Get current settings
   */
  async getSettings(): Promise<VaultGuardSettings> {
    const result = await chrome.storage.local.get(this.settingsKey);
    return result[this.settingsKey] ?? DEFAULT_SETTINGS;
  }

  /**
   * Save settings
   */
  async saveSettings(settings: VaultGuardSettings): Promise<void> {
    await chrome.storage.local.set({ [this.settingsKey]: settings });
    logger.debug('StorageManager', 'Settings saved');
  }

  /**
   * Update settings partially
   */
  async updateSettings(updates: DeepPartial<VaultGuardSettings>): Promise<void> {
    const current = await this.getSettings();
    const merged = this.deepMerge(current, updates);
    await this.saveSettings(merged as VaultGuardSettings);
  }

  /**
   * Save findings for a URL
   */
  async saveFindings(url: string, findings: Vulnerability[]): Promise<void> {
    const allFindings = await this.getAllFindings();
    allFindings[url] = findings;

    // Apply limit check (simplified for now)
    await chrome.storage.local.set({ [this.findingsKey]: allFindings });
  }

  /**
   * Get findings for a URL
   */
  async getFindings(url: string): Promise<Vulnerability[]> {
    const allFindings = await this.getAllFindings();
    return allFindings[url] ?? [];
  }

  /**
   * Get all findings
   */
  async getAllFindings(): Promise<Record<string, Vulnerability[]>> {
    const result = await chrome.storage.local.get(this.findingsKey);
    return result[this.findingsKey] ?? {};
  }

  /**
   * Clear findings for a URL
   */
  async clearFindings(url: string): Promise<void> {
    const allFindings = await this.getAllFindings();
    delete allFindings[url];
    await chrome.storage.local.set({ [this.findingsKey]: allFindings });
  }

  /**
   * Clear all findings
   */
  async clearAllFindings(): Promise<void> {
    await chrome.storage.local.set({ [this.findingsKey]: {} });
  }

  /**
   * Save scan history
   */
  async saveScanHistory(summary: ScanSummary): Promise<void> {
    const history = await this.getScanHistory();
    history.unshift(summary);

    // Keep last 100 scans
    const trimmed = history.slice(0, 100);
    await chrome.storage.local.set({ [this.historyKey]: trimmed });
  }

  /**
   * Get scan history
   */
  async getScanHistory(): Promise<ScanSummary[]> {
    const result = await chrome.storage.local.get(this.historyKey);
    return result[this.historyKey] ?? [];
  }

  /**
   * Clear scan history
   */
  async clearScanHistory(): Promise<void> {
    await chrome.storage.local.set({ [this.historyKey]: [] });
  }

  /**
   * Get storage usage
   */
  async getStorageUsage(): Promise<{ used: number; total: number }> {
    const bytes = await chrome.storage.local.getBytesInUse();
    return {
      used: bytes,
      total: chrome.storage.local.QUOTA_BYTES,
    };
  }

  /**
   * Deep merge objects
   */
  private deepMerge(target: any, source: any): any {
    const result = { ...target };
    for (const key of Object.keys(source)) {
      const sourceValue = source[key];
      const targetValue = target[key];
      if (sourceValue !== undefined && typeof sourceValue === 'object' && sourceValue !== null && !Array.isArray(sourceValue) && typeof targetValue === 'object' && targetValue !== null) {
        result[key] = this.deepMerge(targetValue, sourceValue);
      } else if (sourceValue !== undefined) {
        result[key] = sourceValue;
      }
    }
    return result;
  }
}