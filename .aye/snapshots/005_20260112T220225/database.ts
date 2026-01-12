import { ScanResult, Settings } from '../types';

const DB_NAME = 'VaultGuardDB';
const DB_VERSION = 1;

class Database {
  private db: IDBDatabase | null = null;

  async init(): Promise<void> {
    if (this.db) return;
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onerror = () => reject(req.error);
      req.onsuccess = () => { this.db = req.result; resolve(); };
      req.onupgradeneeded = (e) => {
        const db = (e.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains('scans')) {
          db.createObjectStore('scans', { keyPath: 'id' }).createIndex('by-date', 'startTime');
        }
        if (!db.objectStoreNames.contains('settings')) db.createObjectStore('settings');
      };
    });
  }

  private async ensureInit(): Promise<IDBDatabase> { if (!this.db) await this.init(); return this.db!; }

  async saveScan(scan: ScanResult): Promise<void> {
    const db = await this.ensureInit();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('scans', 'readwrite');
      tx.onerror = () => reject(tx.error);
      tx.oncomplete = () => resolve();
      tx.objectStore('scans').put(scan);
    });
  }

  async getRecentScans(limit = 10): Promise<ScanResult[]> {
    const db = await this.ensureInit();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('scans', 'readonly');
      const req = tx.objectStore('scans').index('by-date').openCursor(null, 'prev');
      const results: ScanResult[] = [];
      req.onerror = () => reject(req.error);
      req.onsuccess = () => {
        const cursor = req.result;
        if (cursor && results.length < limit) { results.push(cursor.value); cursor.continue(); }
        else resolve(results);
      };
    });
  }

  async getAllSettings(): Promise<Settings | null> {
    const db = await this.ensureInit();
    return new Promise((resolve, reject) => {
      const req = db.transaction('settings', 'readonly').objectStore('settings').get('all');
      req.onerror = () => reject(req.error);
      req.onsuccess = () => resolve(req.result || null);
    });
  }

  async saveAllSettings(settings: Settings): Promise<void> {
    const db = await this.ensureInit();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('settings', 'readwrite');
      tx.onerror = () => reject(tx.error);
      tx.oncomplete = () => resolve();
      tx.objectStore('settings').put(settings, 'all');
    });
  }
}

export const database = new Database();