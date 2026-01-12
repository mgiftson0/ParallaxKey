import { ScanResult, Settings } from '../types';

const DB_NAME = 'VaultGuardDB';
const DB_VERSION = 1;

class Database {
  private db: IDBDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    if (this.initPromise) return this.initPromise;
    
    this.initPromise = new Promise((resolve, reject) => {
      console.log('[VaultGuard] Opening database...');
      
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      
      request.onerror = () => {
        console.error('[VaultGuard] Database open error:', request.error);
        reject(request.error);
      };
      
      request.onsuccess = () => {
        console.log('[VaultGuard] Database opened');
        this.db = request.result;
        resolve();
      };
      
      request.onupgradeneeded = (event) => {
        console.log('[VaultGuard] Database upgrade needed');
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains('scans')) {
          const scansStore = db.createObjectStore('scans', { keyPath: 'id' });
          scansStore.createIndex('by-date', 'startTime');
          console.log('[VaultGuard] Created scans store');
        }
        
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings');
          console.log('[VaultGuard] Created settings store');
        }
      };
    });
    
    return this.initPromise;
  }

  private async ensureDb(): Promise<IDBDatabase> {
    if (!this.db) {
      await this.init();
    }
    return this.db!;
  }

  async saveScan(scan: ScanResult): Promise<void> {
    const db = await this.ensureDb();
    
    return new Promise((resolve, reject) => {
      const tx = db.transaction('scans', 'readwrite');
      tx.onerror = () => reject(tx.error);
      tx.oncomplete = () => resolve();
      tx.objectStore('scans').put(scan);
    });
  }

  async getRecentScans(limit = 10): Promise<ScanResult[]> {
    const db = await this.ensureDb();
    
    return new Promise((resolve, reject) => {
      const tx = db.transaction('scans', 'readonly');
      const index = tx.objectStore('scans').index('by-date');
      const request = index.openCursor(null, 'prev');
      const results: ScanResult[] = [];
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor && results.length < limit) {
          results.push(cursor.value);
          cursor.continue();
        } else {
          resolve(results);
        }
      };
    });
  }

  async getSettings(): Promise<Settings | null> {
    const db = await this.ensureDb();
    
    return new Promise((resolve, reject) => {
      const tx = db.transaction('settings', 'readonly');
      const request = tx.objectStore('settings').get('all');
      
      request.onerror = () => reject(request.error);
      request.onsuccess = () => resolve(request.result || null);
    });
  }

  async saveSettings(settings: Settings): Promise<void> {
    const db = await this.ensureDb();
    
    return new Promise((resolve, reject) => {
      const tx = db.transaction('settings', 'readwrite');
      tx.onerror = () => reject(tx.error);
      tx.oncomplete = () => resolve();
      tx.objectStore('settings').put(settings, 'all');
    });
  }
}

export const database = new Database();