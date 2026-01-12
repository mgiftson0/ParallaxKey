/**
 * VaultGuard Content Script
 * Injected into web pages for DOM and client-side analysis
 */

import { DOMAnalyzer } from './dom-analyzer';
import { StorageScanner } from './storage-scanner';
import type { Message, StorageItem } from '../types';

class ContentScript {
  private domAnalyzer: DOMAnalyzer;
  private storageScanner: StorageScanner;
  private initialized = false;
  
  constructor() {
    this.domAnalyzer = new DOMAnalyzer();
    this.storageScanner = new StorageScanner();
  }
  
  /**
   * Initialize the content script
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;
    
    // Set up message listener
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    
    // Notify background that content script is ready
    await this.sendMessage('CONTENT_READY', { url: window.location.href });
    
    this.initialized = true;
    console.log('[VaultGuard] Content script initialized');
  }
  
  /**
   * Handle incoming messages
   */
  private handleMessage(
    message: Message,
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void
  ): boolean {
    switch (message.type) {
      case 'START_SCAN':
        this.performScan().then(sendResponse);
        return true;
        
      default:
        return false;
    }
  }
  
  /**
   * Perform a scan of the page
   */
  async performScan(): Promise<{ success: boolean; data: unknown }> {
    try {
      // Analyze DOM
      const domData = this.domAnalyzer.analyze();
      await this.sendMessage('DOM_ANALYSIS', domData);
      
      // Analyze storage
      const storageData = this.storageScanner.scan();
      await this.sendMessage('STORAGE_ANALYSIS', storageData);
      
      return { success: true, data: { dom: domData, storage: storageData } };
    } catch (error) {
      console.error('[VaultGuard] Scan error:', error);
      return { success: false, data: error };
    }
  }
  
  /**
   * Send a message to the background script
   */
  private async sendMessage(type: Message['type'], payload: unknown): Promise<unknown> {
    return chrome.runtime.sendMessage({
      type,
      payload,
      timestamp: Date.now(),
    });
  }
}

// Initialize content script
const contentScript = new ContentScript();
contentScript.initialize().catch(console.error);

// Export for testing
export { ContentScript };