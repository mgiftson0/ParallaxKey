import logger from '../utils/logger';
import { DOMData } from '../types';

class ContentScript {
  constructor() {
    chrome.runtime.sendMessage({ type: 'CONTENT_SCRIPT_READY', timestamp: Date.now() });
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    logger.debug('ContentScript', 'Initialized');
  }

  private handleMessage(msg: { type: string }, _sender: chrome.runtime.MessageSender, sendResponse: (r: unknown) => void): boolean {
    if (msg.type === 'GET_DOM_DATA') {
      this.collectDOMData().then(sendResponse);
      return true;
    }
    return false;
  }

  private async collectDOMData(): Promise<DOMData> {
    return {
      scripts: this.getScripts(),
      localStorage: this.getLocalStorage(),
      sessionStorage: this.getSessionStorage(),
      cookies: document.cookie,
      html: document.documentElement.outerHTML,
    };
  }

  private getScripts(): { src?: string; content: string }[] {
    const scripts: { src?: string; content: string }[] = [];
    document.querySelectorAll('script:not([src])').forEach(s => {
      if (s.textContent) scripts.push({ content: s.textContent });
    });
    document.querySelectorAll('script[src]').forEach(s => {
      const src = s.getAttribute('src');
      if (src) {
        try {
          scripts.push({ src: new URL(src, document.baseURI).href, content: '' });
        } catch {
          scripts.push({ src, content: '' });
        }
      }
    });
    return scripts;
  }

  private getLocalStorage(): Record<string, string> {
    const data: Record<string, string> = {};
    try {
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (k) data[k] = localStorage.getItem(k) || '';
      }
    } catch { /* Ignore errors */ }
    return data;
  }

  private getSessionStorage(): Record<string, string> {
    const data: Record<string, string> = {};
    try {
      for (let i = 0; i < sessionStorage.length; i++) {
        const k = sessionStorage.key(i);
        if (k) data[k] = sessionStorage.getItem(k) || '';
      }
    } catch { /* Ignore errors */ }
    return data;
  }
}

new ContentScript();