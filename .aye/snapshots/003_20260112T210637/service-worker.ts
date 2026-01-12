import { Message, StartScanMessage, ScanCompleteMessage, ScanProgressMessage } from '../types/messages';
import { ScanProgress } from '../types/scanner';
import { Vulnerability } from '../types/vulnerability';
import { Settings, DEFAULT_SETTINGS } from '../types/settings';
import { scannerEngine } from '../scanners/scanner-engine';
import { database } from '../storage/database';
import logger from '../utils/logger';
import { getDomain } from '../utils/url-utils';

interface TabState { tabId: number; url: string; isScanning: boolean; lastScanTime?: number; findings: Vulnerability[]; }

class BackgroundService {
  private tabStates: Map<number, TabState> = new Map();
  private settings: Settings = DEFAULT_SETTINGS;

  constructor() { this.initialize(); }

  private async initialize(): Promise<void> {
    logger.info('Background', 'Initializing VaultGuard...');
    await database.initialize();
    this.settings = await database.getSettings();
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    chrome.tabs.onUpdated.addListener(this.handleTabUpdated.bind(this));
    chrome.tabs.onRemoved.addListener((id) => this.tabStates.delete(id));
    chrome.alarms.create('cleanup', { periodInMinutes: 60 });
    chrome.alarms.onAlarm.addListener((a) => { if (a.name === 'cleanup') this.cleanupOldFindings(); });
    logger.info('Background', 'VaultGuard initialized');
  }

  private handleMessage(message: Message, sender: chrome.runtime.MessageSender, sendResponse: (r: unknown) => void): boolean {
    const tabId = sender.tab?.id ?? message.tabId;
    logger.debug('Background', `Message: ${message.type}`, { tabId });

    switch (message.type) {
      case 'START_SCAN': this.handleStartScan(message as StartScanMessage, tabId, sendResponse); return true;
      case 'STOP_SCAN': scannerEngine.cancelScan(); if (tabId) { const s = this.tabStates.get(tabId); if (s) s.isScanning = false; } sendResponse({ ok: true }); return false;
      case 'GET_SCAN_STATUS': sendResponse({ isScanning: tabId ? this.tabStates.get(tabId)?.isScanning : false, progress: scannerEngine.getProgress(), findings: tabId ? this.tabStates.get(tabId)?.findings || [] : [] }); return false;
      case 'GET_FINDINGS': this.handleGetFindings(sendResponse); return true;
      case 'CLEAR_FINDINGS': this.handleClearFindings(sendResponse); return true;
      case 'GET_SETTINGS': sendResponse(this.settings); return false;
      case 'UPDATE_SETTINGS': this.handleUpdateSettings(message, sendResponse); return true;
      case 'CONTENT_SCRIPT_READY': if (tabId && sender.tab?.url) this.tabStates.set(tabId, { tabId, url: sender.tab.url, isScanning: false, findings: [] }); sendResponse({ ok: true }); return false;
      case 'PING': sendResponse({ type: 'PONG', timestamp: Date.now() }); return false;
      default: sendResponse({ error: 'Unknown message' }); return false;
    }
  }

  private async handleStartScan(message: StartScanMessage, tabId: number | undefined, sendResponse: (r: unknown) => void): Promise<void> {
    if (!tabId) { sendResponse({ error: 'No tab ID' }); return; }
    let tabState = this.tabStates.get(tabId);
    if (!tabState) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) { sendResponse({ error: 'No URL' }); return; }
      tabState = { tabId, url: tab.url, isScanning: false, findings: [] };
      this.tabStates.set(tabId, tabState);
    }
    if (tabState.isScanning) { sendResponse({ error: 'Already scanning' }); return; }

    tabState.isScanning = true;
    this.updateBadge(tabId, 'scanning');

    try {
      const domData = await this.requestDOMData(tabId);
      scannerEngine.onProgress((p: ScanProgress) => {
        chrome.runtime.sendMessage({ type: 'SCAN_PROGRESS', timestamp: Date.now(), progress: p } as ScanProgressMessage).catch(() => {});
      });

      const { results, findings } = await scannerEngine.scan(tabState.url, tabId, message.options, domData);
      tabState.findings = findings;
      tabState.lastScanTime = Date.now();
      await database.addFindings(findings);
      for (const r of results) await database.addScanHistory({ ...r, domain: getDomain(tabState.url) });

      const criticalHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
      this.updateBadge(tabId, 'complete', criticalHigh);

      const complete: ScanCompleteMessage = { type: 'SCAN_COMPLETE', timestamp: Date.now(), results, summary: { totalFindings: findings.length, duration: results.reduce((s, r) => s + r.scanDuration, 0) } };
      chrome.runtime.sendMessage(complete).catch(() => {});
      sendResponse(complete);
    } catch (error) {
      logger.error('Background', 'Scan failed', error);
      this.updateBadge(tabId, 'error');
      sendResponse({ type: 'SCAN_ERROR', error: error instanceof Error ? error.message : 'Unknown' });
    } finally {
      tabState.isScanning = false;
    }
  }

  private async requestDOMData(tabId: number): Promise<{ scripts: { src?: string; content: string }[]; localStorage: Record<string, string>; sessionStorage: Record<string, string>; cookies: string; html: string } | undefined> {
    return new Promise(resolve => {
      chrome.tabs.sendMessage(tabId, { type: 'GET_DOM_DATA', timestamp: Date.now() }, r => {
        if (chrome.runtime.lastError) { logger.warn('Background', `DOM data failed: ${chrome.runtime.lastError.message}`); resolve(undefined); }
        else resolve(r);
      });
    });
  }

  private async handleGetFindings(sendResponse: (r: unknown) => void): Promise<void> {
    try {
      const findings = await database.getAllFindings();
      sendResponse({ findings, total: findings.length });
    } catch (e) { sendResponse({ error: 'Failed', findings: [] }); }
  }

  private async handleClearFindings(sendResponse: (r: unknown) => void): Promise<void> {
    try {
      await database.clearFindings();
      this.tabStates.forEach(s => { s.findings = []; this.updateBadge(s.tabId, 'idle'); });
      sendResponse({ ok: true });
    } catch (e) { sendResponse({ error: 'Failed' }); }
  }

  private async handleUpdateSettings(message: Message & { settings?: Partial<Settings> }, sendResponse: (r: unknown) => void): Promise<void> {
    if (message.settings) {
      this.settings = { ...this.settings, ...message.settings };
      await database.saveSettings(this.settings);
    }
    sendResponse({ ok: true, settings: this.settings });
  }

  private handleTabUpdated(tabId: number, info: chrome.tabs.TabChangeInfo, tab: chrome.tabs.Tab): void {
    if (info.status === 'complete' && tab.url) {
      const existing = this.tabStates.get(tabId);
      if (existing && existing.url !== tab.url) { existing.url = tab.url; existing.findings = []; this.updateBadge(tabId, 'idle'); }
      else if (!existing) this.tabStates.set(tabId, { tabId, url: tab.url, isScanning: false, findings: [] });
    }
  }

  private async cleanupOldFindings(): Promise<void> {
    const findings = await database.getAllFindings();
    const cutoff = Date.now() - this.settings.findingsRetentionDays * 86400000;
    for (const f of findings) if (f.timestamp < cutoff) await database.deleteFinding(f.id);
  }

  private updateBadge(tabId: number, status: 'idle' | 'scanning' | 'complete' | 'error', count?: number): void {
    const colors: Record<string, string> = { idle: '#6B7280', scanning: '#3B82F6', complete: count ? '#EF4444' : '#10B981', error: '#EF4444' };
    chrome.action.setBadgeBackgroundColor({ color: colors[status], tabId });
    if (status === 'scanning') chrome.action.setBadgeText({ text: '...', tabId });
    else if (status === 'complete') chrome.action.setBadgeText({ text: count ? String(count) : '✓', tabId });
    else if (status === 'error') chrome.action.setBadgeText({ text: '!', tabId });
    else chrome.action.setBadgeText({ text: '', tabId });
  }
}

new BackgroundService();
logger.info('ServiceWorker', 'VaultGuard started');