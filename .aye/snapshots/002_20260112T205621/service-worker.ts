/**
 * VaultGuard Background Service Worker
 * Central coordinator for all extension operations
 */

import { MessageRouter } from './message-router';
import { NetworkInterceptor } from './network-interceptor';
import { TabManager } from './tab-manager';
import { ScannerOrchestrator } from './scanner-orchestrator';
import { StorageManager } from './storage-manager';
import { logger } from '../utils/logger';
import type { Message, StartScanPayload } from '../types';

// Initialize components
const messageRouter = new MessageRouter();
const networkInterceptor = new NetworkInterceptor();
const tabManager = new TabManager();
const scannerOrchestrator = new ScannerOrchestrator();
const storageManager = new StorageManager();

/**
 * Extension installation handler
 */
chrome.runtime.onInstalled.addListener(async (details) => {
  logger.info('ServiceWorker', `Extension installed: ${details.reason}`);
  
  if (details.reason === 'install') {
    // First time installation
    await storageManager.initializeSettings();
    logger.info('ServiceWorker', 'Initial setup complete');
  } else if (details.reason === 'update') {
    // Extension updated
    logger.info('ServiceWorker', `Updated from ${details.previousVersion}`);
  }
});

/**
 * Extension startup handler
 */
chrome.runtime.onStartup.addListener(() => {
  logger.info('ServiceWorker', 'Extension started');
});

/**
 * Message handler
 */
chrome.runtime.onMessage.addListener(
  (message: Message, sender, sendResponse): boolean => {
    logger.debug('ServiceWorker', 'Message received', { type: message.type });
    
    // Handle async messages
    (async () => {
      try {
        const response = await handleMessage(message, sender);
        sendResponse({ success: true, data: response });
      } catch (error) {
        logger.error('ServiceWorker', 'Message handling error', error);
        sendResponse({ success: false, error: String(error) });
      }
    })();
    
    return true; // Keep channel open for async response
  }
);

/**
 * Handle incoming messages
 */
async function handleMessage(
  message: Message,
  sender: chrome.runtime.MessageSender
): Promise<unknown> {
  const tabId = sender.tab?.id;
  
  switch (message.type) {
    case 'START_SCAN': {
      const payload = message.payload as StartScanPayload | undefined;
      if (tabId) {
        return scannerOrchestrator.startScan(tabId, payload);
      }
      throw new Error('No tab ID for scan');
    }
    
    case 'STOP_SCAN': {
      scannerOrchestrator.stopScan();
      return { stopped: true };
    }
    
    case 'GET_FINDINGS': {
      if (tabId) {
        return tabManager.getTabFindings(tabId);
      }
      return [];
    }
    
    case 'CLEAR_FINDINGS': {
      if (tabId) {
        tabManager.clearTabFindings(tabId);
      }
      return { cleared: true };
    }
    
    case 'GET_SETTINGS': {
      return storageManager.getSettings();
    }
    
    case 'UPDATE_SETTINGS': {
      await storageManager.updateSettings(message.payload as Record<string, unknown>);
      return { updated: true };
    }
    
    case 'CONTENT_READY': {
      if (tabId) {
        tabManager.markTabReady(tabId);
      }
      return { acknowledged: true };
    }
    
    case 'DOM_ANALYSIS': {
      if (tabId) {
        return scannerOrchestrator.processDOMAnalysis(tabId, message.payload);
      }
      return null;
    }
    
    case 'STORAGE_ANALYSIS': {
      if (tabId) {
        return scannerOrchestrator.processStorageAnalysis(tabId, message.payload);
      }
      return null;
    }
    
    default:
      logger.warn('ServiceWorker', `Unknown message type: ${message.type}`);
      return null;
  }
}

/**
 * Tab update handler
 */
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    logger.debug('ServiceWorker', `Tab ${tabId} loaded: ${tab.url}`);
    tabManager.updateTab(tabId, tab.url, tab.title ?? '');
  }
});

/**
 * Tab removed handler
 */
chrome.tabs.onRemoved.addListener((tabId) => {
  logger.debug('ServiceWorker', `Tab ${tabId} closed`);
  tabManager.removeTab(tabId);
});

/**
 * Network request handler
 */
chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    networkInterceptor.captureRequest(details);
    return {};
  },
  { urls: ['http://*/*', 'https://*/*'] },
  ['requestBody']
);

/**
 * Network response handler
 */
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    networkInterceptor.captureResponseHeaders(details);
    return {};
  },
  { urls: ['http://*/*', 'https://*/*'] },
  ['responseHeaders']
);

/**
 * Extension action (icon) click handler
 */
chrome.action.onClicked.addListener(async (tab) => {
  if (tab.id) {
    // Open popup or trigger quick scan
    logger.info('ServiceWorker', 'Action clicked', { tabId: tab.id });
  }
});

logger.info('ServiceWorker', 'VaultGuard initialized');