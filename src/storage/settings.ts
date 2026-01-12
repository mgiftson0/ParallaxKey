import { Settings, ScanType, VulnerabilityCategory } from '../types';
import { database } from './database';

const DEFAULT_SETTINGS: Settings = {
  general: {
    autoScan: false,
    showBadge: true,
    debugMode: false
  },
  scanning: {
    defaultScanType: 'standard',
    enabledCategories: [
      'secret_exposure',
      'network_security',
      'storage_security',
      'authentication',
      'data_exposure',
      'misconfiguration'
    ]
  },
  appearance: {
    theme: 'system'
  }
};

class SettingsStore {
  private settings: Settings | null = null;
  private loadPromise: Promise<Settings> | null = null;

  async load(): Promise<Settings> {
    if (this.settings) return this.settings;
    if (this.loadPromise) return this.loadPromise;
    
    this.loadPromise = (async () => {
      try {
        const stored = await database.getSettings();
        this.settings = stored 
          ? { ...DEFAULT_SETTINGS, ...stored } 
          : { ...DEFAULT_SETTINGS };
      } catch (e) {
        console.error('[VaultGuard] Failed to load settings:', e);
        this.settings = { ...DEFAULT_SETTINGS };
      }
      return this.settings;
    })();
    
    return this.loadPromise;
  }

  async get(): Promise<Settings> {
    return this.load();
  }

  async save(settings: Settings): Promise<void> {
    this.settings = settings;
    try {
      await database.saveSettings(settings);
    } catch (e) {
      console.error('[VaultGuard] Failed to save settings:', e);
    }
  }

  async update(partial: Partial<Settings>): Promise<void> {
    const current = await this.get();
    await this.save({ ...current, ...partial });
  }

  async isAutoScan(): Promise<boolean> {
    const settings = await this.get();
    return settings.general.autoScan;
  }

  async getDefaultType(): Promise<ScanType> {
    const settings = await this.get();
    return settings.scanning.defaultScanType;
  }

  async getCategories(): Promise<VulnerabilityCategory[]> {
    const settings = await this.get();
    return settings.scanning.enabledCategories;
  }
}

export const settingsStore = new SettingsStore();