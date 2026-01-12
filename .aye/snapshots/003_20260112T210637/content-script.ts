import logger from '../utils/logger';

interface DOMData {
  scripts: { src?: string; content: string }[];
  forms: { action: string; method: string; inputs: { name: string; type: string }[] }[];
  links: { href: string; rel: string }[];
  meta: { name: string; content: string }[];
  cookies: string;
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
  html: string;
}

class ContentScript {
  constructor() {
    chrome.runtime.sendMessage({ type: 'CONTENT_SCRIPT_READY', timestamp: Date.now() });
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));
    logger.debug('ContentScript', 'Initialized');
  }

  private handleMessage(msg: { type: string }, _: chrome.runtime.MessageSender, sendResponse: (r: unknown) => void): boolean {
    if (msg.type === 'GET_DOM_DATA') { this.collectDOMData().then(sendResponse); return true; }
    if (msg.type === 'GET_STORAGE_DATA') { sendResponse({ localStorage: this.getLocalStorage(), sessionStorage: this.getSessionStorage() }); return false; }
    if (msg.type === 'GET_COOKIES') { sendResponse({ cookies: document.cookie }); return false; }
    return false;
  }

  private async collectDOMData(): Promise<DOMData> {
    return {
      scripts: this.getScripts(),
      forms: this.getForms(),
      links: this.getLinks(),
      meta: this.getMeta(),
      cookies: document.cookie,
      localStorage: this.getLocalStorage(),
      sessionStorage: this.getSessionStorage(),
      html: document.documentElement.outerHTML,
    };
  }

  private getScripts(): { src?: string; content: string }[] {
    const scripts: { src?: string; content: string }[] = [];
    document.querySelectorAll('script:not([src])').forEach(s => { if (s.textContent) scripts.push({ content: s.textContent }); });
    document.querySelectorAll('script[src]').forEach(s => { const src = s.getAttribute('src'); if (src) scripts.push({ src: this.resolveURL(src), content: '' }); });
    return scripts;
  }

  private getForms(): { action: string; method: string; inputs: { name: string; type: string }[] }[] {
    return Array.from(document.querySelectorAll('form')).map(f => ({
      action: this.resolveURL(f.action || ''),
      method: f.method || 'get',
      inputs: Array.from(f.querySelectorAll('input,textarea,select')).map(i => ({ name: (i as HTMLInputElement).name || (i as HTMLInputElement).id || '', type: (i as HTMLInputElement).type || 'text' }))
    }));
  }

  private getLinks(): { href: string; rel: string }[] {
    return Array.from(document.querySelectorAll('a[href],link[href]')).map(l => ({ href: this.resolveURL(l.getAttribute('href') || ''), rel: l.getAttribute('rel') || '' })).filter(l => l.href);
  }

  private getMeta(): { name: string; content: string }[] {
    return Array.from(document.querySelectorAll('meta')).map(m => ({ name: m.getAttribute('name') || m.getAttribute('property') || '', content: m.getAttribute('content') || '' })).filter(m => m.name || m.content);
  }

  private getLocalStorage(): Record<string, string> {
    const data: Record<string, string> = {};
    try { for (let i = 0; i < localStorage.length; i++) { const k = localStorage.key(i); if (k) data[k] = localStorage.getItem(k) || ''; } } catch {}
    return data;
  }

  private getSessionStorage(): Record<string, string> {
    const data: Record<string, string> = {};
    try { for (let i = 0; i < sessionStorage.length; i++) { const k = sessionStorage.key(i); if (k) data[k] = sessionStorage.getItem(k) || ''; } } catch {}
    return data;
  }

  private resolveURL(url: string): string {
    try { return new URL(url, document.baseURI).href; } catch { return url; }
  }
}

new ContentScript();