import { scannerEngine } from '../scanners/scanner-engine';
import { database } from '../storage/database';
import { settingsStore } from '../storage/settings';
import { Message, ScanOptions, ScanResult, DOMAnalysisResult, NetworkRequest, NetworkResponse } from '../types';

interface TabState {
  url: string;
  scanning: boolean;
  lastScan?: ScanResult;
  requests: NetworkRequest[];
  responses: NetworkResponse[];
}

const tabs = new Map<number, TabState>();

console.log('[VaultGuard] Service worker starting...');

// Initialize database
database.init()
  .then(() => console.log('[VaultGuard] Database initialized'))
  .catch(e => console.error('[VaultGuard] Database init failed:', e));

// Message handler
chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  console.log('[VaultGuard] Message received:', message.type, message);
  
  const tabId = sender.tab?.id ?? message.tabId;
  
  handleMessage(message, tabId)
    .then(response => {
      console.log('[VaultGuard] Sending response:', response);
      sendResponse(response);
    })
    .catch(error => {
      console.error('[VaultGuard] Error handling message:', error);
      sendResponse({ error: error.message });
    });
  
  return true; // Keep channel open for async response
});

async function handleMessage(message: Message, tabId?: number): Promise<any> {
  console.log('[VaultGuard] Handling:', message.type, 'for tab:', tabId);
  
  switch (message.type) {
    case 'START_SCAN':
      if (!tabId) {
        // Get active tab if no tabId
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) tabId = tab.id;
      }
      if (!tabId) return { success: false, error: 'No tab ID' };
      return startScan(tabId, message.payload as ScanOptions);
    
    case 'STOP_SCAN':
      scannerEngine.stop();
      return { success: true };
    
    case 'GET_RESULTS':
      if (!tabId) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) tabId = tab.id;
      }
      const state = tabs.get(tabId!);
      console.log('[VaultGuard] GET_RESULTS for tab', tabId, ':', state?.lastScan ? 'has results' : 'no results');
      return state?.lastScan || null;
    
    case 'GET_STATUS':
      if (!tabId) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) tabId = tab.id;
      }
      const s = tabs.get(tabId!);
      return { 
        status: s?.scanning ? 'scanning' : s?.lastScan ? 'complete' : 'ready', 
        count: s?.lastScan?.summary?.total || 0 
      };
    
    case 'GET_SETTINGS':
      return settingsStore.get();
    
    case 'UPDATE_SETTINGS':
      await settingsStore.update(message.payload);
      return { success: true };
    
    case 'CONTENT_READY':
      console.log('[VaultGuard] Content script ready on tab:', tabId);
      return { success: true };
    
    case 'CLEAR_RESULTS':
      if (tabId) {
        const st = tabs.get(tabId);
        if (st) {
          st.lastScan = undefined;
          st.requests = [];
          st.responses = [];
          updateBadge(tabId, 'clear');
        }
      }
      return { success: true };
    
    case 'EXPORT_REPORT':
      if (!tabId) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab?.id) tabId = tab.id;
      }
      const result = tabs.get(tabId!)?.lastScan;
      return result 
        ? { success: true, data: JSON.stringify(result, null, 2) } 
        : { success: false, error: 'No results' };
    
    case 'GET_HISTORY':
      return database.getRecentScans(20);
    
    default:
      console.warn('[VaultGuard] Unknown message type:', message.type);
      return { error: 'Unknown message type' };
  }
}

async function startScan(tabId: number, options?: ScanOptions): Promise<{ success: boolean; scanId?: string; error?: string }> {
  console.log('[VaultGuard] Starting scan for tab:', tabId);
  
  // Get tab info
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch (e) {
    console.error('[VaultGuard] Could not get tab:', e);
    return { success: false, error: 'Could not get tab info' };
  }
  
  if (!tab.url) {
    return { success: false, error: 'Tab has no URL' };
  }
  
  // Skip chrome:// and other restricted URLs
  if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
    return { success: false, error: 'Cannot scan this page type' };
  }
  
  let state = tabs.get(tabId);
  if (!state) {
    state = { url: tab.url, scanning: false, requests: [], responses: [] };
    tabs.set(tabId, state);
  }
  
  if (state.scanning) {
    return { success: false, error: 'Scan already in progress' };
  }
  
  const scanOptions: ScanOptions = options || {
    type: await settingsStore.getDefaultType(),
    categories: await settingsStore.getCategories()
  };
  
  state.scanning = true;
  state.url = tab.url;
  updateBadge(tabId, 'scanning');
  
  try {
    // Inject content script if needed and get DOM analysis
    console.log('[VaultGuard] Requesting DOM analysis...');
    const domAnalysis = await getDOMAnalysis(tabId);
    console.log('[VaultGuard] DOM analysis result:', domAnalysis ? 'received' : 'null');
    
    // Run the scan
    console.log('[VaultGuard] Running scanner engine...');
    const result = await scannerEngine.scan(
      state.url,
      tabId,
      scanOptions,
      domAnalysis,
      state.requests,
      state.responses
    );
    
    console.log('[VaultGuard] Scan complete:', result.summary.total, 'vulnerabilities found');
    
    state.lastScan = result;
    state.scanning = false;
    
    // Save to database
    try {
      await database.saveScan(result);
    } catch (e) {
      console.error('[VaultGuard] Failed to save scan:', e);
    }
    
    updateBadge(tabId, 'done', result.summary.total);
    
    // Notify popup
    try {
      chrome.runtime.sendMessage({ type: 'SCAN_COMPLETE', payload: result });
    } catch (e) {
      // Popup might be closed, ignore
    }
    
    return { success: true, scanId: result.id };
    
  } catch (error: any) {
    console.error('[VaultGuard] Scan failed:', error);
    state.scanning = false;
    updateBadge(tabId, 'error');
    return { success: false, error: error.message };
  }
}

async function getDOMAnalysis(tabId: number): Promise<DOMAnalysisResult | undefined> {
  return new Promise((resolve) => {
    // First try to inject the content script
    chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content-script.js']
    }).then(() => {
      console.log('[VaultGuard] Content script injected');
      // Small delay to let script initialize
      setTimeout(() => {
        requestDOMAnalysis(tabId).then(resolve);
      }, 100);
    }).catch(e => {
      console.log('[VaultGuard] Could not inject script (may already be there):', e.message);
      // Try to communicate anyway
      requestDOMAnalysis(tabId).then(resolve);
    });
  });
}

function requestDOMAnalysis(tabId: number): Promise<DOMAnalysisResult | undefined> {
  return new Promise((resolve) => {
    const timeout = setTimeout(() => {
      console.warn('[VaultGuard] DOM analysis timeout');
      resolve(undefined);
    }, 5000);
    
    chrome.tabs.sendMessage(tabId, { type: 'ANALYZE_DOM' }, (response) => {
      clearTimeout(timeout);
      if (chrome.runtime.lastError) {
        console.warn('[VaultGuard] DOM analysis error:', chrome.runtime.lastError.message);
        resolve(undefined);
      } else {
        console.log('[VaultGuard] DOM analysis received');
        resolve(response);
      }
    });
  });
}

// Track tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    console.log('[VaultGuard] Tab updated:', tabId, tab.url);
    tabs.set(tabId, { url: tab.url, scanning: false, requests: [], responses: [] });
    
    settingsStore.isAutoScan().then(auto => {
      if (auto && !tab.url?.startsWith('chrome')) {
        startScan(tabId);
      }
    });
  }
});

// Clean up when tab closes
chrome.tabs.onRemoved.addListener((tabId) => {
  tabs.delete(tabId);
});

function updateBadge(tabId: number, status: 'scanning' | 'done' | 'error' | 'clear', count?: number): void {
  try {
    switch (status) {
      case 'scanning':
        chrome.action.setBadgeText({ text: '...', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#3B82F6', tabId });
        break;
      case 'done':
        const text = count && count > 0 ? String(count) : '✓';
        chrome.action.setBadgeText({ text, tabId });
        chrome.action.setBadgeBackgroundColor({ color: count && count > 0 ? '#EF4444' : '#10B981', tabId });
        break;
      case 'error':
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#EF4444', tabId });
        break;
      case 'clear':
        chrome.action.setBadgeText({ text: '', tabId });
        break;
    }
  } catch (e) {
    console.error('[VaultGuard] Badge update error:', e);
  }
}

// Track network requests
try {
  chrome.webRequest.onBeforeRequest.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const state = tabs.get(details.tabId);
      if (state) {
        state.requests.push({
          id: details.requestId,
          url: details.url,
          method: details.method,
          headers: {},
          timestamp: details.timeStamp,
          type: details.type
        });
      }
    },
    { urls: ['<all_urls>'] }
  );
  
  chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
      if (details.tabId < 0) return;
      const headers: Record<string, string> = {};
      details.responseHeaders?.forEach(h => {
        headers[h.name] = h.value || '';
      });
      const state = tabs.get(details.tabId);
      if (state) {
        state.responses.push({
          requestId: details.requestId,
          url: details.url,
          status: details.statusCode,
          headers,
          timestamp: details.timeStamp
        });
      }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders']
  );
} catch (e) {
  console.error('[VaultGuard] WebRequest listener error:', e);
}

console.log('[VaultGuard] Service worker initialized');