import { ScanProgress, Settings, DEFAULT_SETTINGS, Vulnerability, DOMData } from '../types';
import { scannerEngine } from '../scanners/scanner-engine';
import { database } from '../storage/database';
import logger from '../utils/logger';
import { getDomain } from '../utils/helpers';

interface TabState {
  tabId: number;
  url: string;
  isScanning: boolean;
  findings: Vulnerability[];
}

class BackgroundService {
  private tabStates: Map<number, TabState> = new Map();
  private settings: Settings = DEFAULT_SETTINGS;

  constructor() {
    this.initialize();
  }

  private async initialize(): Promise<void> {
    logger.info('Background', 'Initializing VaultGuard...');
    await database.initialize();
    this.settings = await database.getSettings();
    
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      this.handleMessage(message, sender, sendResponse);
      return true; // Keep channel open for async response
    });
    
    chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
      if (info.status === 'complete' && tab.url) {
        this.tabStates.set(tabId, { tabId, url: tab.url, isScanning: false, findings: [] });
      }
    });
    
    chrome.tabs.onRemoved.addListener(tabId => this.tabStates.delete(tabId));
    
    logger.info('Background', 'VaultGuard initialized');
  }

  private async handleMessage(message: { type: string; [key: string]: unknown }, sender: chrome.runtime.MessageSender, sendResponse: (r: unknown) => void): Promise<void> {
    const tabId = sender.tab?.id ?? (message.tabId as number | undefined);
    logger.debug('Background', `Message: ${message.type}`);

    try {
      switch (message.type) {
        case 'START_SCAN':
          await this.handleStartScan(message, tabId, sendResponse);
          break;
        case 'STOP_SCAN':
          scannerEngine.cancelScan();
          if (tabId) {
            const state = this.tabStates.get(tabId);
            if (state) state.isScanning = false;
          }
          sendResponse({ ok: true });
          break;
        case 'GET_SCAN_STATUS':
          sendResponse({
            isScanning: tabId ? this.tabStates.get(tabId)?.isScanning : false,
            progress: scannerEngine.getProgress(),
            findings: tabId ? this.tabStates.get(tabId)?.findings || [] : [],
          });
          break;
        case 'GET_FINDINGS':
          const findings = await database.getAllFindings();
          sendResponse({ findings, total: findings.length });
          break;
        case 'CLEAR_FINDINGS':
          await database.clearFindings();
          this.tabStates.forEach(s => { s.findings = []; this.updateBadge(s.tabId, 'idle'); });
          sendResponse({ ok: true });
          break;
        case 'GET_SETTINGS':
          sendResponse(this.settings);
          break;
        case 'UPDATE_SETTINGS':
          if (message.settings) {
            this.settings = { ...this.settings, ...(message.settings as Partial<Settings>) };
            await database.saveSettings(this.settings);
          }
          sendResponse({ ok: true, settings: this.settings });
          break;
        case 'CONTENT_SCRIPT_READY':
          if (tabId && sender.tab?.url) {
            this.tabStates.set(tabId, { tabId, url: sender.tab.url, isScanning: false, findings: [] });
          }
          sendResponse({ ok: true });
          break;
        case 'PING':
          sendResponse({ type: 'PONG', timestamp: Date.now() });
          break;
        default:
          sendResponse({ error: 'Unknown message type' });
      }
    } catch (error) {
      logger.error('Background', 'Message handler error', error);
      sendResponse({ error: error instanceof Error ? error.message : 'Unknown error' });
    }
  }

  private async handleStartScan(message: { type: string; [key: string]: unknown }, tabId: number | undefined, sendResponse: (r: unknown) => void): Promise<void> {
    if (!tabId) {
      sendResponse({ error: 'No tab ID' });
      return;
    }

    let tabState = this.tabStates.get(tabId);
    if (!tabState) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) {
        sendResponse({ error: 'No URL' });
        return;
      }
      tabState = { tabId, url: tab.url, isScanning: false, findings: [] };
      this.tabStates.set(tabId, tabState);
    }

    if (tabState.isScanning) {
      sendResponse({ error: 'Already scanning' });
      return;
    }

    tabState.isScanning = true;
    this.updateBadge(tabId, 'scanning');

    try {
      const domData = await this.requestDOMData(tabId);
      
      scannerEngine.onProgress((progress: ScanProgress) => {
        chrome.runtime.sendMessage({ type: 'SCAN_PROGRESS', timestamp: Date.now(), progress }).catch(() => {});
      });

      const { results, findings } = await scannerEngine.scan(
        tabState.url,
        tabId,
        (message.options as { depth?: string }) || {},
        domData
      );

      tabState.findings = findings;
      await database.addFindings(findings);
      
      for (const r of results) {
        await database.addScanHistory({ ...r, domain: getDomain(tabState.url) });
      }

      const criticalHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high').length;
      this.updateBadge(tabId, 'complete', criticalHigh);

      const complete = {
        type: 'SCAN_COMPLETE',
        timestamp: Date.now(),
        results,
        summary: { totalFindings: findings.length, duration: results.reduce((s, r) => s + r.scanDuration, 0) },
      };
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

  private async requestDOMData(tabId: number): Promise<DOMData | undefined> {
    return new Promise(resolve => {
      chrome.tabs.sendMessage(tabId, { type: 'GET_DOM_DATA' }, response => {
        if (chrome.runtime.lastError) {
          logger.warn('Background', `DOM data failed: ${chrome.runtime.lastError.message}`);
          resolve(undefined);
        } else {
          resolve(response as DOMData | undefined);
        }
      });
    });
  }

  private updateBadge(tabId: number, status: 'idle' | 'scanning' | 'complete' | 'error', count?: number): void {
    const colors: Record<string, string> = {
      idle: '#6B7280',
      scanning: '#3B82F6',
      complete: count ? '#EF4444' : '#10B981',
      error: '#EF4444',
    };
    chrome.action.setBadgeBackgroundColor({ color: colors[status], tabId });
    if (status === 'scanning') chrome.action.setBadgeText({ text: '...', tabId });
    else if (status === 'complete') chrome.action.setBadgeText({ text: count ? String(count) : '✓', tabId });
    else if (status === 'error') chrome.action.setBadgeText({ text: '!', tabId });
    else chrome.action.setBadgeText({ text: '', tabId });
  }
}

new BackgroundService();
logger.info('ServiceWorker', 'VaultGuard started');