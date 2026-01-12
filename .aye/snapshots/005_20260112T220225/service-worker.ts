import { logger } from '../utils/logger';
import { scannerEngine } from '../scanners/scanner-engine';
import { database } from '../storage/database';
import { settingsStore } from '../storage/settings';
import { Message, ScanOptions, ScanResult, DOMAnalysisResult, NetworkRequest, NetworkResponse } from '../types';

interface TabState {
  url: string;
  isScanning: boolean;
  lastScan?: ScanResult;
  networkRequests: NetworkRequest[];
  networkResponses: NetworkResponse[];
}

const tabStates = new Map<number, TabState>();

logger.info('ServiceWorker', 'VaultGuard starting...');
database.init().then(() => logger.info('ServiceWorker', 'Database ready'));

chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  const tabId = sender.tab?.id ?? message.tabId;
  handleMessage(message, tabId).then(sendResponse).catch(e => sendResponse({ error: e.message }));
  return true;
});

async function handleMessage(message: any, tabId?: number): Promise<any> {
  switch (message.type) {
    case 'START_SCAN':
      const payload = message.payload || message.options || {};
      const scanType = (payload.type || payload.depth || 'standard') as 'quick' | 'standard' | 'deep';
      return handleStartScan(tabId!, { type: scanType });
    case 'STOP_SCAN': scannerEngine.cancelScan(); return { success: true };
    case 'GET_RESULTS': return tabStates.get(tabId!)?.lastScan || null;
    case 'GET_STATUS':
      const s = tabStates.get(tabId!);
      return { status: s?.isScanning ? 'scanning' : s?.lastScan ? 'complete' : 'ready', url: s?.url, count: s?.lastScan?.summary.total };
    case 'GET_SETTINGS': return settingsStore.get();
    case 'UPDATE_SETTINGS': await settingsStore.update(message.payload); return { success: true };
    case 'CONTENT_READY': return { success: true };
    case 'CLEAR_RESULTS':
      const state = tabStates.get(tabId!);
      if (state) { state.lastScan = undefined; state.networkRequests = []; state.networkResponses = []; updateBadge(tabId!, 'clear'); }
      return { success: true };
    case 'EXPORT_REPORT':
      const result = tabStates.get(tabId!)?.lastScan;
      return result ? { success: true, data: JSON.stringify(result, null, 2) } : { success: false };
    case 'GET_SCAN_HISTORY': return database.getRecentScans(20);
    case 'ANALYZE_DOM': return { error: 'Should be handled by content script' };
    default: return { error: `Unknown message type: ${message.type}` };
  }
}

async function handleStartScan(tabId: number, options: ScanOptions): Promise<{ success: boolean; scanId?: string; error?: string }> {
  let state = tabStates.get(tabId);
  if (!state) {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return { success: false, error: 'No active tab' };
    state = { url: tab.url, isScanning: false, networkRequests: [], networkResponses: [] };
    tabStates.set(tabId, state);
  }
  if (state.isScanning) return { success: false, error: 'Scan in progress' };

  state.isScanning = true;
  updateBadge(tabId, 'scanning');

  try {
    const domAnalysis = await requestDOMAnalysis(tabId);
    const result = await scannerEngine.scan(state.url, tabId, options, domAnalysis, state.networkRequests, state.networkResponses);
    state.lastScan = result;
    state.isScanning = false;
    await database.saveScan(result);
    updateBadge(tabId, 'complete', result.summary.total);
    chrome.runtime.sendMessage({
      type: 'SCAN_COMPLETE',
      payload: result,
      timestamp: Date.now()
    }).catch(() => { });
    return { success: true, scanId: result.id };
  } catch (e: any) {
    state.isScanning = false;
    updateBadge(tabId, 'error');
    return { success: false, error: e.message };
  }
}

async function requestDOMAnalysis(tabId: number): Promise<DOMAnalysisResult | undefined> {
  return new Promise(resolve => {
    chrome.tabs.sendMessage(tabId, {
      type: 'ANALYZE_DOM',
      timestamp: Date.now()
    }, (response: any) => {
      if (chrome.runtime.lastError) { logger.warn('ServiceWorker', 'DOM analysis failed'); resolve(undefined); }
      else resolve(response);
    });
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    tabStates.set(tabId, { url: tab.url, isScanning: false, networkRequests: [], networkResponses: [] });
    settingsStore.isAutoScanEnabled().then(auto => { if (auto) handleStartScan(tabId, { type: 'standard' }); });
  }
});

chrome.tabs.onRemoved.addListener(tabId => tabStates.delete(tabId));

function updateBadge(tabId: number, status: 'scanning' | 'complete' | 'error' | 'clear', count?: number) {
  switch (status) {
    case 'scanning':
      chrome.action.setBadgeText({ text: '...', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#3B82F6', tabId });
      break;
    case 'complete':
      chrome.action.setBadgeText({ text: count && count > 0 ? count.toString() : '\u2713', tabId });
      chrome.action.setBadgeBackgroundColor({ color: count && count > 5 ? '#EF4444' : '#10B981', tabId });
      break;
    case 'error':
      chrome.action.setBadgeText({ text: '!', tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#EF4444', tabId });
      break;
    case 'clear':
      chrome.action.setBadgeText({ text: '', tabId });
      break;
  }
}

chrome.webRequest.onBeforeRequest.addListener(
  details => {
    if (details.tabId < 0) return;
    const state = tabStates.get(details.tabId);
    if (state) state.networkRequests.push({ id: details.requestId, url: details.url, method: details.method, headers: {}, timestamp: details.timeStamp, type: details.type });
  },
  { urls: ['<all_urls>'] }
);

chrome.webRequest.onHeadersReceived.addListener(
  details => {
    if (details.tabId < 0) return;
    const headers: Record<string, string> = {};
    details.responseHeaders?.forEach(h => { headers[h.name] = h.value || ''; });
    const state = tabStates.get(details.tabId);
    if (state) state.networkResponses.push({ requestId: details.requestId, url: details.url, status: details.statusCode, statusText: '', headers, timestamp: details.timeStamp, size: 0 });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders']
);

logger.info('ServiceWorker', 'VaultGuard initialized');