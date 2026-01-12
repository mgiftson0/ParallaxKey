import { Vulnerability } from '../types';
import { compareSeverity } from '../utils/helpers';

class DevToolsPanel {
  private findings: Vulnerability[] = [];

  constructor() {
    document.getElementById('scan-btn')?.addEventListener('click', () => this.startScan());
    this.loadFindings();
    chrome.runtime.onMessage.addListener((msg: { type: string }) => {
      if (msg.type === 'SCAN_COMPLETE') this.loadFindings();
    });
  }

  private async loadFindings(): Promise<void> {
    const response = await chrome.runtime.sendMessage({ type: 'GET_FINDINGS', timestamp: Date.now() }) as { findings?: Vulnerability[] };
    if (response?.findings) {
      this.findings = response.findings;
      this.render();
    }
  }

  private async startScan(): Promise<void> {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    await chrome.runtime.sendMessage({ type: 'START_SCAN', timestamp: Date.now(), options: {}, tabId });
  }

  private render(): void {
    const container = document.getElementById('findings');
    if (!container) return;

    if (this.findings.length === 0) {
      container.innerHTML = '<p class="text-gray-500">No vulnerabilities found</p>';
      return;
    }

    const sorted = [...this.findings].sort((a, b) => compareSeverity(a.severity, b.severity));
    const colors: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-500' };

    container.innerHTML = sorted.map(f => `
      <div class="bg-gray-800 rounded-lg p-3 border border-gray-700">
        <div class="flex items-center gap-2 mb-1">
          <span class="w-2 h-2 rounded-full ${colors[f.severity]}"></span>
          <span class="font-medium text-sm">${this.escapeHtml(f.title)}</span>
          <span class="text-xs px-2 py-0.5 rounded ${colors[f.severity]} bg-opacity-20">${f.severity}</span>
        </div>
        <p class="text-xs text-gray-400">${this.escapeHtml(f.description.substring(0, 100))}...</p>
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