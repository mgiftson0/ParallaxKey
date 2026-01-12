import { Vulnerability } from '../types/vulnerability';
import { compareSeverity } from '../core/severity-calculator';

class DevToolsPanel {
  private findings: Vulnerability[] = [];

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    document.getElementById('scan-btn')?.addEventListener('click', () => this.startScan());
    await this.loadFindings();
    this.setupMessageListener();
  }

  private async loadFindings(): Promise<void> {
    const response = await chrome.runtime.sendMessage({ type: 'GET_FINDINGS', timestamp: Date.now() });
    if (response?.findings) {
      this.findings = response.findings;
      this.render();
    }
  }

  private setupMessageListener(): void {
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.type === 'SCAN_COMPLETE') {
        this.loadFindings();
      }
    });
  }

  private async startScan(): Promise<void> {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    await chrome.runtime.sendMessage({ type: 'START_SCAN', timestamp: Date.now(), options: { depth: 'standard' }, tabId });
  }

  private render(): void {
    const container = document.getElementById('findings-container');
    if (!container) return;

    if (this.findings.length === 0) {
      container.innerHTML = '<div class="text-center py-12 text-gray-500"><p>No vulnerabilities found</p></div>';
      return;
    }

    const sorted = [...this.findings].sort((a, b) => compareSeverity(a.severity, b.severity));
    const severityColors: Record<string, string> = { critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-500' };

    container.innerHTML = sorted.map(f => `
      <div class="bg-gray-800 rounded-lg p-3 border border-gray-700">
        <div class="flex items-start gap-3">
          <span class="w-2 h-2 rounded-full ${severityColors[f.severity]} mt-2"></span>
          <div class="flex-1">
            <div class="flex items-center justify-between">
              <p class="font-medium text-sm">${this.escapeHtml(f.title)}</p>
              <span class="text-xs px-2 py-0.5 rounded ${severityColors[f.severity]} bg-opacity-20 text-${f.severity === 'critical' ? 'red' : f.severity === 'high' ? 'orange' : f.severity === 'medium' ? 'yellow' : 'blue'}-400">${f.severity}</span>
            </div>
            <p class="text-xs text-gray-400 mt-1">${this.escapeHtml(f.description.substring(0, 100))}...</p>
            <p class="text-xs text-gray-500 mt-1">${this.escapeHtml(f.location.url || f.location.storageKey || '')}</p>
          </div>
        </div>
      </div>
    `).join('');
  }

  private escapeHtml(str: string): string {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
}

new DevToolsPanel();