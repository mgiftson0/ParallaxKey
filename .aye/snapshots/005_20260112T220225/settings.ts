import { Settings, ScanType, VulnerabilityCategory } from '../types';
import { database } from './database';

const DEFAULT: Settings = {
  general: { autoScan: false, scanOnNavigation: false, showBadge: true, debugMode: false },
  scanning: {
    defaultScanType: 'standard',
    enabledCategories: ['secret_exposure', 'network_security', 'storage_security', 'authentication', 'data_exposure', 'misconfiguration'],
    customPatterns: [], whitelistedDomains: [], blacklistedDomains: [], maxConcurrentScans: 3, scanTimeout: 300000,
  },
  notifications: { enabled: true, minSeverity: 'medium', sound: false, desktop: true },
  privacy: { collectAnonymousStats: false, sharePatterns: false, localStorageOnly: true },
  appearance: { theme: 'system', compactMode: false, showConfidenceScores: true },
};

class SettingsStore {
  private settings: Settings | null = null;

  async load(): Promise<Settings> {
    if (this.settings) return this.settings;
    const stored = await database.getAllSettings();
    this.settings = stored ? { ...DEFAULT, ...stored } : { ...DEFAULT };
    return this.settings;
  }

  async get(): Promise<Settings> { return this.load(); }
  async save(settings: Settings): Promise<void> { this.settings = settings; await database.saveAllSettings(settings); }
  async update(partial: Partial<Settings>): Promise<void> { await this.save({ ...await this.get(), ...partial }); }
  async isAutoScanEnabled(): Promise<boolean> { return (await this.get()).general.autoScan; }
  async getEnabledCategories(): Promise<VulnerabilityCategory[]> { return (await this.get()).scanning.enabledCategories; }
  async getDefaultScanType(): Promise<ScanType> { return (await this.get()).scanning.defaultScanType; }
}

export const settingsStore = new SettingsStore();