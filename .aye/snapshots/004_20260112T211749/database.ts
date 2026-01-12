import { Vulnerability, Settings, DEFAULT_SETTINGS, ScanResult } from '../types';
import logger from '../utils/logger';

const DB_NAME = 'VaultGuardDB';
const DB_VERSION = 1;

class Database {
  private db: IDBDatabase | null = null;
  private initPromise: Promise<void> | null = null;

  async initialize(): Promise<void> {
    if (this.db) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(DB_NAME, DB_VERSION);
      
      request.onerror = () => {
        logger.error('Database', 'Failed to open', request.error);
        reject(request.error);
      };
      
      request.onsuccess = () => {
        this.db = request.result;
        logger.info('Database', 'Initialized');
        resolve();
      };
      
      request.onupgradeneeded = (event) => {
        const db = (event.target as IDBOpenDBRequest).result;
        
        if (!db.objectStoreNames.contains('findings')) {
          const store = db.createObjectStore('findings', { keyPath: 'id' });
          store.createIndex('severity', 'severity', { unique: false });
          store.createIndex('timestamp', 'timestamp', { unique: false });
        }
        
        if (!db.objectStoreNames.contains('scanHistory')) {
          const store = db.createObjectStore('scanHistory', { keyPath: 'scanId', autoIncrement: true });
          store.createIndex('startTime', 'startTime', { unique: false });
        }
        
        if (!db.objectStoreNames.contains('settings')) {
          db.createObjectStore('settings', { keyPath: 'key' });
        }
      };
    });
    
    return this.initPromise;
  }

  private async getStore(name: string, mode: IDBTransactionMode = 'readonly'): Promise<IDBObjectStore> {
    await this.initialize();
    if (!this.db) throw new Error('Database not initialized');
    return this.db.transaction(name, mode).objectStore(name);
  }

  async addFinding(finding: Vulnerability): Promise<void> {
    const store = await this.getStore('findings', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.add(finding);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async addFindings(findings: Vulnerability[]): Promise<void> {
    if (findings.length === 0) return;
    const store = await this.getStore('findings', 'readwrite');
    return new Promise((resolve, reject) => {
      let completed = 0;
      findings.forEach(f => {
        const req = store.put(f);
        req.onsuccess = () => { if (++completed === findings.length) resolve(); };
        req.onerror = () => reject(req.error);
      });
    });
  }

  async getAllFindings(): Promise<Vulnerability[]> {
    const store = await this.getStore('findings');
    return new Promise((resolve, reject) => {
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () => reject(req.error);
    });
  }

  async deleteFinding(id: string): Promise<void> {
    const store = await this.getStore('findings', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.delete(id);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async clearFindings(): Promise<void> {
    const store = await this.getStore('findings', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.clear();
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async addScanHistory(result: ScanResult & { domain: string }): Promise<void> {
    const store = await this.getStore('scanHistory', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.add(result);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }

  async getSettings(): Promise<Settings> {
    const store = await this.getStore('settings');
    return new Promise((resolve, reject) => {
      const req = store.get('settings');
      req.onsuccess = () => resolve(req.result?.value ?? DEFAULT_SETTINGS);
      req.onerror = () => reject(req.error);
    });
  }

  async saveSettings(settings: Settings): Promise<void> {
    const store = await this.getStore('settings', 'readwrite');
    return new Promise((resolve, reject) => {
      const req = store.put({ key: 'settings', value: settings });
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
}

export const database = new Database();
export default database;