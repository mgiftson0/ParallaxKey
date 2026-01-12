import { Settings, DEFAULT_SETTINGS } from '../types';

class OptionsController {
  private settings: Settings = DEFAULT_SETTINGS;

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    await this.loadSettings();
    this.setupEventListeners();
  }

  private async loadSettings(): Promise<void> {
    const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS', timestamp: Date.now() }) as Settings | null;
    if (response) this.settings = response;
    this.populateForm();
  }

  private populateForm(): void {
    (document.getElementById('theme') as HTMLSelectElement).value = this.settings.appearance.theme;
    (document.getElementById('auto-scan') as HTMLInputElement).checked = this.settings.autoScanOnNavigation;
  }

  private setupEventListeners(): void {
    document.getElementById('theme')?.addEventListener('change', () => this.saveSettings());
    document.getElementById('auto-scan')?.addEventListener('change', () => this.saveSettings());
    document.getElementById('clear-all')?.addEventListener('click', async () => {
      if (confirm('Clear all VaultGuard data?')) {
        await chrome.runtime.sendMessage({ type: 'CLEAR_FINDINGS', timestamp: Date.now() });
        alert('Data cleared.');
      }
    });
  }

  private async saveSettings(): Promise<void> {
    this.settings.appearance.theme = (document.getElementById('theme') as HTMLSelectElement).value as 'light' | 'dark' | 'system';
    this.settings.autoScanOnNavigation = (document.getElementById('auto-scan') as HTMLInputElement).checked;
    await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', timestamp: Date.now(), settings: this.settings });
  }
}

new OptionsController();