import { Settings, DEFAULT_SETTINGS } from '../types/settings';

class OptionsController {
  private settings: Settings = DEFAULT_SETTINGS;

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    await this.loadSettings();
    this.setupTabs();
    this.setupEventListeners();
    this.renderScanners();
  }

  private async loadSettings(): Promise<void> {
    const response = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS', timestamp: Date.now() });
    if (response) this.settings = response;
    this.populateForm();
  }

  private populateForm(): void {
    (document.getElementById('theme') as HTMLSelectElement).value = this.settings.appearance.theme;
    (document.getElementById('compact-mode') as HTMLInputElement).checked = this.settings.appearance.compactMode;
    (document.getElementById('badge-count') as HTMLInputElement).checked = this.settings.appearance.showBadgeCount;
    (document.getElementById('auto-scan') as HTMLInputElement).checked = this.settings.autoScanOnNavigation;
    (document.getElementById('scan-profile') as HTMLSelectElement).value = this.settings.activeProfileId;
    (document.getElementById('retention') as HTMLSelectElement).value = String(this.settings.findingsRetentionDays);
    (document.getElementById('notifications-enabled') as HTMLInputElement).checked = this.settings.notifications.enabled;
    (document.getElementById('min-severity') as HTMLSelectElement).value = this.settings.notifications.minSeverity;
  }

  private setupTabs(): void {
    document.querySelectorAll('.tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('tab-active'));
        document.querySelectorAll('.tab-panel').forEach(p => p.classList.add('hidden'));
        tab.classList.add('tab-active');
        const panelId = `tab-${tab.getAttribute('data-tab')}`;
        document.getElementById(panelId)?.classList.remove('hidden');
      });
    });
  }

  private setupEventListeners(): void {
    ['theme', 'compact-mode', 'badge-count', 'auto-scan', 'scan-profile', 'retention', 'notifications-enabled', 'min-severity'].forEach(id => {
      document.getElementById(id)?.addEventListener('change', () => this.saveSettings());
    });

    document.getElementById('clear-all-data')?.addEventListener('click', async () => {
      if (confirm('Clear all VaultGuard data? This cannot be undone.')) {
        await chrome.runtime.sendMessage({ type: 'CLEAR_FINDINGS', timestamp: Date.now() });
        alert('All data cleared.');
      }
    });
  }

  private async saveSettings(): Promise<void> {
    this.settings.appearance.theme = (document.getElementById('theme') as HTMLSelectElement).value as 'light' | 'dark' | 'system';
    this.settings.appearance.compactMode = (document.getElementById('compact-mode') as HTMLInputElement).checked;
    this.settings.appearance.showBadgeCount = (document.getElementById('badge-count') as HTMLInputElement).checked;
    this.settings.autoScanOnNavigation = (document.getElementById('auto-scan') as HTMLInputElement).checked;
    this.settings.activeProfileId = (document.getElementById('scan-profile') as HTMLSelectElement).value;
    this.settings.findingsRetentionDays = parseInt((document.getElementById('retention') as HTMLSelectElement).value);
    this.settings.notifications.enabled = (document.getElementById('notifications-enabled') as HTMLInputElement).checked;
    this.settings.notifications.minSeverity = (document.getElementById('min-severity') as HTMLSelectElement).value as any;

    await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', timestamp: Date.now(), settings: this.settings });
  }

  private renderScanners(): void {
    const list = document.getElementById('scanners-list');
    if (!list) return;

    const scanners = [
      { id: 'api-key-scanner', name: 'API Key & Secrets Scanner', desc: 'Detects exposed API keys and tokens', enabled: true },
      { id: 'header-scanner', name: 'Security Headers Scanner', desc: 'Checks HTTP security headers', enabled: true },
      { id: 'local-storage-scanner', name: 'Local Storage Scanner', desc: 'Scans browser storage', enabled: true },
      { id: 'cookie-scanner', name: 'Cookie Security Scanner', desc: 'Analyzes cookie security', enabled: true },
      { id: 'jwt-analyzer', name: 'JWT Security Analyzer', desc: 'Analyzes JWT tokens', enabled: true },
      { id: 'pii-detector', name: 'PII Detector', desc: 'Detects personal information', enabled: true },
    ];

    list.innerHTML = scanners.map(s => `
      <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
        <div>
          <p class="text-sm font-medium text-gray-900">${s.name}</p>
          <p class="text-xs text-gray-500">${s.desc}</p>
        </div>
        <label class="relative inline-flex items-center cursor-pointer">
          <input type="checkbox" class="sr-only peer" checked>
          <div class="w-11 h-6 bg-gray-200 peer-focus:ring-2 peer-focus:ring-vault-500 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-vault-600"></div>
        </label>
      </div>
    `).join('');
  }
}

new OptionsController();