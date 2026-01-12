/**
 * VaultGuard Storage Scanner
 * Scans client-side storage for sensitive data
 */

import type { StorageItem } from '../types';

export interface StorageScanResult {
  localStorage: StorageItem[];
  sessionStorage: StorageItem[];
  cookies: string;
  indexedDBDatabases: string[];
}

export class StorageScanner {
  /**
   * Scan all client-side storage
   */
  scan(): StorageScanResult {
    return {
      localStorage: this.scanLocalStorage(),
      sessionStorage: this.scanSessionStorage(),
      cookies: this.getCookies(),
      indexedDBDatabases: this.listIndexedDBDatabases(),
    };
  }
  
  /**
   * Scan localStorage
   */
  private scanLocalStorage(): StorageItem[] {
    const items: StorageItem[] = [];
    
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key) {
          const value = localStorage.getItem(key) || '';
          items.push({
            key,
            value,
            type: 'localStorage',
            size: value.length * 2, // UTF-16
            domain: window.location.hostname,
          });
        }
      }
    } catch (error) {
      console.warn('[VaultGuard] Error scanning localStorage:', error);
    }
    
    return items;
  }
  
  /**
   * Scan sessionStorage
   */
  private scanSessionStorage(): StorageItem[] {
    const items: StorageItem[] = [];
    
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        if (key) {
          const value = sessionStorage.getItem(key) || '';
          items.push({
            key,
            value,
            type: 'sessionStorage',
            size: value.length * 2,
            domain: window.location.hostname,
          });
        }
      }
    } catch (error) {
      console.warn('[VaultGuard] Error scanning sessionStorage:', error);
    }
    
    return items;
  }
  
  /**
   * Get cookies (accessible ones only)
   */
  private getCookies(): string {
    try {
      return document.cookie;
    } catch (error) {
      console.warn('[VaultGuard] Error reading cookies:', error);
      return '';
    }
  }
  
  /**
   * List IndexedDB databases
   */
  private listIndexedDBDatabases(): string[] {
    const databases: string[] = [];
    
    try {
      // Note: indexedDB.databases() is not available in all browsers
      if ('databases' in indexedDB) {
        // This is async, so we can't get the actual list here
        // Just note that IndexedDB exists
        databases.push('IndexedDB available');
      }
    } catch (error) {
      console.warn('[VaultGuard] Error checking IndexedDB:', error);
    }
    
    return databases;
  }
}