import { Vulnerability, Severity } from '../types/vulnerability';
import { ScanProgress } from '../types/scanner';
import { compareSeverity } from '../core/severity-calculator';

class PopupController {
  private findings: Vulnerability[] = [];
  private isScanning = false;

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    await this.loadCurrentTab();
    await this.loadFindings();
    this.setupEventListeners();
    this.setupMessageListener();
  }

  private async loadCurrentTab(): Promise<void> {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const urlEl = document.getElementById('current-url');
    if (urlEl && tab?.url) {
      try {
        const url = new URL(tab.url);
        urlEl.textContent = url.hostname + url.pathname;
        urlEl.title = tab.url;
      } catch {
        urlEl.textContent = tab.url || 'Unknown';
      }
    }
  }

  private async loadFindings(): Promise<void> {
    const response = await chrome.runtime.sendMessage({ type: 'GET_FINDINGS', timestamp: Date.now() });
    if (response?.findings) {
      this.findings = response.findings;
      this.renderFindings();
      this.updateSummary();
    }
  }

  private setupEventListeners(): void {
    document.getElementById('scan-btn')?.addEventListener('click', () => this.startScan());
    document.getElementById('settings-btn')?.addEventListener('click', () => chrome.runtime.openOptionsPage());
    document.getElementById('export-btn')?.addEventListener('click', () => this.exportReport());
    document.getElementById('clear-btn')?.addEventListener('click', () => this.clearFindings());
    document.getElementById('modal-close')?.addEventListener('click', () => this.closeModal());
    document.getElementById('modal')?.addEventListener('click', (e) => { if (e.target === e.currentTarget) this.closeModal(); });
  }

  private setupMessageListener(): void {
    chrome.runtime.onMessage.addListener((message) => {
      if (message.type === 'SCAN_PROGRESS') this.updateProgress(message.progress);
      else if (message.type === 'SCAN_COMPLETE') {
        this.isScanning = false;
        this.findings = message.results?.flatMap((r: { findings: Vulnerability[] }) => r.findings) || [];
        this.loadFindings();
        this.hideProgress();
        this.updateScanButton();
      }
    });
  }

  private async startScan(): Promise<void> {
    if (this.isScanning) return;
    this.isScanning = true;
    this.updateScanButton();
    this.showProgress();

    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    await chrome.runtime.sendMessage({ type: 'START_SCAN', timestamp: Date.now(), options: { depth: 'standard' }, tabId: tab?.id });
  }

  private updateScanButton(): void {
    const btn = document.getElementById('scan-btn') as HTMLButtonElement;
    const icon = document.getElementById('scan-icon');
    const text = document.getElementById('scan-text');
    if (btn && icon && text) {
      btn.disabled = this.isScanning;
      if (this.isScanning) {
        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/>';
        icon.classList.add('animate-spin');
        text.textContent = 'Scanning...';
      } else {
        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>';
        icon.classList.remove('animate-spin');
        text.textContent = 'Scan Page';
      }
    }
  }

  private showProgress(): void {
    document.getElementById('progress-section')?.classList.remove('hidden');
  }

  private hideProgress(): void {
    document.getElementById('progress-section')?.classList.add('hidden');
  }

  private updateProgress(progress: ScanProgress): void {
    const percent = document.getElementById('progress-percent');
    const fill = document.getElementById('progress-fill');
    const scanner = document.getElementById('progress-scanner');
    if (percent) percent.textContent = `${Math.round(progress.progress)}%`;
    if (fill) fill.style.width = `${progress.progress}%`;
    if (scanner) scanner.textContent = progress.currentScanner || 'Processing...';
  }

  private updateSummary(): void {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    this.findings.forEach(f => { if (f.severity in counts) counts[f.severity as keyof typeof counts]++; });
    
    (document.getElementById('critical-count') as HTMLElement).textContent = String(counts.critical);
    (document.getElementById('high-count') as HTMLElement).textContent = String(counts.high);
    (document.getElementById('medium-count') as HTMLElement).textContent = String(counts.medium);
    (document.getElementById('low-count') as HTMLElement).textContent = String(counts.low);
    (document.getElementById('findings-count') as HTMLElement).textContent = `${this.findings.length} issues`;
  }

  private renderFindings(): void {
    const list = document.getElementById('findings-list');
    const empty = document.getElementById('empty-state');
    if (!list) return;

    if (this.findings.length === 0) {
      if (empty) empty.classList.remove('hidden');
      return;
    }

    if (empty) empty.classList.add('hidden');
    const sorted = [...this.findings].sort((a, b) => compareSeverity(a.severity, b.severity));
    
    list.innerHTML = sorted.slice(0, 20).map(f => `
      <div class="finding-item flex items-start gap-3 p-3 hover:bg-gray-50 cursor-pointer border-b border-gray-100 last:border-0" data-id="${f.id}">
        <span class="severity-dot severity-dot-${f.severity} mt-1.5 flex-shrink-0"></span>
        <div class="flex-1 min-w-0">
          <p class="text-sm font-medium text-gray-900 truncate">${this.escapeHtml(f.title)}</p>
          <p class="text-xs text-gray-500 truncate">${this.escapeHtml(f.location.url || f.location.storageKey || '')}</p>
        </div>
        <span class="badge badge-${f.severity}">${f.severity}</span>
      </div>
    `).join('');

    list.querySelectorAll('.finding-item').forEach(el => {
      el.addEventListener('click', () => {
        const id = el.getAttribute('data-id');
        const finding = this.findings.find(f => f.id === id);
        if (finding) this.showFindingDetails(finding);
      });
    });
  }

  private showFindingDetails(finding: Vulnerability): void {
    const modal = document.getElementById('modal');
    const title = document.getElementById('modal-title');
    const content = document.getElementById('modal-content');
    if (!modal || !title || !content) return;

    title.textContent = finding.title;
    content.innerHTML = `
      <div class="space-y-4">
        <div class="flex items-center gap-2">
          <span class="badge badge-${finding.severity}">${finding.severity.toUpperCase()}</span>
          <span class="text-sm text-gray-500">${finding.type}</span>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-gray-900 mb-1">Description</h4>
          <p class="text-sm text-gray-600">${this.escapeHtml(finding.description)}</p>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-gray-900 mb-1">Evidence</h4>
          <pre class="code-block text-xs overflow-x-auto">${this.escapeHtml(finding.maskedEvidence)}</pre>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-gray-900 mb-1">Impact</h4>
          <p class="text-sm text-gray-600">${this.escapeHtml(finding.impact.description)}</p>
        </div>
        <div>
          <h4 class="text-sm font-semibold text-gray-900 mb-1">Remediation</h4>
          <p class="text-sm text-gray-600">${this.escapeHtml(finding.remediation.summary)}</p>
          ${finding.remediation.steps.length > 0 ? `
            <ol class="mt-2 space-y-1">
              ${finding.remediation.steps.map(s => `<li class="text-sm text-gray-600"><strong>${s.order}.</strong> ${this.escapeHtml(s.title)}</li>`).join('')}
            </ol>
          ` : ''}
        </div>
        ${finding.remediation.references.length > 0 ? `
          <div>
            <h4 class="text-sm font-semibold text-gray-900 mb-1">References</h4>
            <ul class="space-y-1">
              ${finding.remediation.references.map(r => `<li><a href="${r}" target="_blank" class="text-sm text-vault-600 hover:underline">${r}</a></li>`).join('')}
            </ul>
          </div>
        ` : ''}
      </div>
    `;
    modal.classList.remove('hidden');
  }

  private closeModal(): void {
    document.getElementById('modal')?.classList.add('hidden');
  }

  private async exportReport(): Promise<void> {
    if (this.findings.length === 0) { alert('No findings to export'); return; }
    const data = JSON.stringify(this.findings, null, 2);
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vaultguard-report-${new Date().toISOString().split('T')[0]}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  private async clearFindings(): Promise<void> {
    if (!confirm('Clear all findings?')) return;
    await chrome.runtime.sendMessage({ type: 'CLEAR_FINDINGS', timestamp: Date.now() });
    this.findings = [];
    this.renderFindings();
    this.updateSummary();
  }

  private escapeHtml(str: string): string {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
}

new PopupController();