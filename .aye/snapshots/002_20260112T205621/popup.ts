/**
 * VaultGuard Popup Script
 * Handles popup UI interactions
 */

import type { Message, Vulnerability, ScanSummary, Severity } from '../types';

class PopupController {
  private quickScanBtn: HTMLButtonElement;
  private fullScanBtn: HTMLButtonElement;
  private settingsBtn: HTMLButtonElement;
  private exportBtn: HTMLButtonElement;
  private devtoolsBtn: HTMLButtonElement;
  private scanProgress: HTMLElement;
  private progressFill: HTMLElement;
  private progressText: HTMLElement;
  private findingsContainer: HTMLElement;
  private environmentBadge: HTMLElement;
  
  private criticalCount: HTMLElement;
  private highCount: HTMLElement;
  private mediumCount: HTMLElement;
  private lowCount: HTMLElement;
  
  private currentTabId: number | null = null;
  private isScanning = false;
  
  constructor() {
    // Get DOM elements
    this.quickScanBtn = document.getElementById('quick-scan-btn') as HTMLButtonElement;
    this.fullScanBtn = document.getElementById('full-scan-btn') as HTMLButtonElement;
    this.settingsBtn = document.getElementById('settings-btn') as HTMLButtonElement;
    this.exportBtn = document.getElementById('export-btn') as HTMLButtonElement;
    this.devtoolsBtn = document.getElementById('devtools-btn') as HTMLButtonElement;
    this.scanProgress = document.getElementById('scan-progress') as HTMLElement;
    this.progressFill = this.scanProgress.querySelector('.progress-fill') as HTMLElement;
    this.progressText = this.scanProgress.querySelector('.progress-text') as HTMLElement;
    this.findingsContainer = document.getElementById('findings-container') as HTMLElement;
    this.environmentBadge = document.getElementById('environment-badge') as HTMLElement;
    
    this.criticalCount = document.getElementById('critical-count') as HTMLElement;
    this.highCount = document.getElementById('high-count') as HTMLElement;
    this.mediumCount = document.getElementById('medium-count') as HTMLElement;
    this.lowCount = document.getElementById('low-count') as HTMLElement;
    
    this.initialize();
  }
  
  /**
   * Initialize the popup
   */
  private async initialize(): Promise<void> {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id) {
      this.currentTabId = tab.id;
      this.detectEnvironment(tab.url ?? '');
      await this.loadExistingFindings();
    }
    
    // Set up event listeners
    this.quickScanBtn.addEventListener('click', () => this.startScan(true));
    this.fullScanBtn.addEventListener('click', () => this.startScan(false));
    this.settingsBtn.addEventListener('click', () => this.openSettings());
    this.exportBtn.addEventListener('click', () => this.exportFindings());
    this.devtoolsBtn.addEventListener('click', () => this.openDevTools());
    
    // Listen for scan updates
    chrome.runtime.onMessage.addListener((message: Message) => {
      if (message.type === 'SCAN_PROGRESS') {
        this.updateProgress(message.payload as { progress: number; currentScanner: string });
      } else if (message.type === 'SCAN_COMPLETE') {
        this.onScanComplete(message.payload as { summary: ScanSummary });
      }
    });
  }
  
  /**
   * Detect and display environment
   */
  private detectEnvironment(url: string): void {
    const lowerUrl = url.toLowerCase();
    let env = 'unknown';
    
    if (
      lowerUrl.includes('localhost') ||
      lowerUrl.includes('127.0.0.1') ||
      lowerUrl.includes('.local') ||
      lowerUrl.includes(':3000') ||
      lowerUrl.includes(':8080')
    ) {
      env = 'development';
    } else if (
      lowerUrl.includes('staging') ||
      lowerUrl.includes('stage') ||
      lowerUrl.includes('uat')
    ) {
      env = 'staging';
    } else {
      env = 'production';
    }
    
    this.environmentBadge.className = `environment-badge ${env}`;
    const envText = this.environmentBadge.querySelector('.env-text') as HTMLElement;
    envText.textContent = env.charAt(0).toUpperCase() + env.slice(1);
  }
  
  /**
   * Load existing findings for current tab
   */
  private async loadExistingFindings(): Promise<void> {
    if (!this.currentTabId) return;
    
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'GET_FINDINGS',
        timestamp: Date.now(),
      });
      
      if (response?.success && response.data) {
        this.displayFindings(response.data as Vulnerability[]);
      }
    } catch (error) {
      console.error('Error loading findings:', error);
    }
  }
  
  /**
   * Start a scan
   */
  private async startScan(quickScan: boolean): Promise<void> {
    if (this.isScanning || !this.currentTabId) return;
    
    this.isScanning = true;
    this.setButtonsEnabled(false);
    this.showProgress();
    
    try {
      // First, tell content script to scan
      await chrome.tabs.sendMessage(this.currentTabId, {
        type: 'START_SCAN',
        payload: { quickScan },
        timestamp: Date.now(),
      });
      
      // Then start background scan
      const response = await chrome.runtime.sendMessage({
        type: 'START_SCAN',
        payload: { quickScan },
        tabId: this.currentTabId,
        timestamp: Date.now(),
      });
      
      if (response?.success && response.data) {
        this.onScanComplete({ summary: response.data as ScanSummary });
      }
    } catch (error) {
      console.error('Scan error:', error);
      this.hideProgress();
      this.isScanning = false;
      this.setButtonsEnabled(true);
    }
  }
  
  /**
   * Update progress display
   */
  private updateProgress(data: { progress: number; currentScanner: string }): void {
    this.progressFill.style.width = `${data.progress}%`;
    this.progressText.textContent = `Scanning: ${data.currentScanner}...`;
  }
  
  /**
   * Handle scan completion
   */
  private onScanComplete(data: { summary: ScanSummary }): void {
    this.hideProgress();
    this.isScanning = false;
    this.setButtonsEnabled(true);
    
    const { summary } = data;
    
    // Update counts
    this.criticalCount.textContent = String(summary.bySeverity.critical || 0);
    this.highCount.textContent = String(summary.bySeverity.high || 0);
    this.mediumCount.textContent = String(summary.bySeverity.medium || 0);
    this.lowCount.textContent = String(summary.bySeverity.low || 0);
    
    // Get all vulnerabilities from results
    const allVulns: Vulnerability[] = [];
    for (const result of summary.results) {
      allVulns.push(...result.vulnerabilities);
    }
    
    this.displayFindings(allVulns);
    
    // Enable export if there are findings
    this.exportBtn.disabled = allVulns.length === 0;
  }
  
  /**
   * Display findings in the list
   */
  private displayFindings(findings: Vulnerability[]): void {
    if (findings.length === 0) {
      this.findingsContainer.innerHTML = `
        <p class="empty-state">No vulnerabilities found yet. Run a scan to get started.</p>
      `;
      return;
    }
    
    // Sort by severity
    const sorted = [...findings].sort((a, b) => {
      const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    });
    
    // Take top 10 for display
    const top = sorted.slice(0, 10);
    
    this.findingsContainer.innerHTML = top
      .map(
        (finding) => `
        <div class="finding-item" data-id="${finding.id}">
          <div class="finding-severity ${finding.severity}"></div>
          <div class="finding-content">
            <div class="finding-title">${this.escapeHtml(finding.title)}</div>
            <div class="finding-description">${this.escapeHtml(finding.description.slice(0, 100))}...</div>
          </div>
        </div>
      `
      )
      .join('');
    
    // Add click handlers
    this.findingsContainer.querySelectorAll('.finding-item').forEach((item) => {
      item.addEventListener('click', () => {
        const id = item.getAttribute('data-id');
        if (id) {
          this.showFindingDetails(id);
        }
      });
    });
  }
  
  /**
   * Show finding details (opens DevTools panel)
   */
  private showFindingDetails(id: string): void {
    // For now, just open DevTools
    this.openDevTools();
  }
  
  /**
   * Show progress bar
   */
  private showProgress(): void {
    this.scanProgress.classList.remove('hidden');
    this.progressFill.style.width = '10%';
    this.progressText.textContent = 'Starting scan...';
  }
  
  /**
   * Hide progress bar
   */
  private hideProgress(): void {
    this.scanProgress.classList.add('hidden');
  }
  
  /**
   * Enable/disable buttons
   */
  private setButtonsEnabled(enabled: boolean): void {
    this.quickScanBtn.disabled = !enabled;
    this.fullScanBtn.disabled = !enabled;
  }
  
  /**
   * Open settings page
   */
  private openSettings(): void {
    chrome.runtime.openOptionsPage();
  }
  
  /**
   * Open DevTools
   */
  private openDevTools(): void {
    // DevTools can only be opened programmatically from DevTools itself
    // Show a message to the user
    alert('Open DevTools (F12) and navigate to the VaultGuard panel for detailed analysis.');
  }
  
  /**
   * Export findings
   */
  private async exportFindings(): Promise<void> {
    if (!this.currentTabId) return;
    
    try {
      const response = await chrome.runtime.sendMessage({
        type: 'GET_FINDINGS',
        timestamp: Date.now(),
      });
      
      if (response?.success && response.data) {
        const findings = response.data as Vulnerability[];
        const json = JSON.stringify(findings, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        
        const a = document.createElement('a');
        a.href = url;
        a.download = `vaultguard-report-${Date.now()}.json`;
        a.click();
        
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      console.error('Export error:', error);
    }
  }
  
  /**
   * Escape HTML for safe display
   */
  private escapeHtml(str: string): string {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }
}

// Initialize popup
document.addEventListener('DOMContentLoaded', () => {
  new PopupController();
});