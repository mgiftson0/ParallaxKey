import { DOMAnalysisResult, ScriptInfo, FormInfo, StorageItem, CookieInfo, LinkInfo, Message } from '../types';

chrome.runtime.sendMessage({ type: 'CONTENT_READY' });

chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_DOM') { analyzeDom().then(sendResponse); return true; }
  return false;
});

async function analyzeDom(): Promise<DOMAnalysisResult> {
  return {
    scripts: analyzeScripts(),
    forms: analyzeForms(),
    localStorage: analyzeStorage('localStorage'),
    sessionStorage: analyzeStorage('sessionStorage'),
    cookies: analyzeCookies(),
    meta: analyzeMeta(),
    links: analyzeLinks(),
  };
}

function analyzeScripts(): ScriptInfo[] {
  const scripts: ScriptInfo[] = [];
  document.querySelectorAll('script').forEach(script => {
    scripts.push({ src: script.src || undefined, inline: !script.src, content: !script.src ? script.textContent || undefined : undefined, hash: '', async: script.async, defer: script.defer, type: script.type || undefined });
  });
  return scripts;
}

function analyzeForms(): FormInfo[] {
  const forms: FormInfo[] = [];
  document.querySelectorAll('form').forEach(form => {
    const inputs = Array.from(form.querySelectorAll('input, textarea, select'));
    forms.push({
      action: form.action, method: form.method || 'GET',
      hasPasswordField: inputs.some(i => (i as HTMLInputElement).type === 'password'),
      hasFileUpload: inputs.some(i => (i as HTMLInputElement).type === 'file'),
      autocomplete: form.autocomplete,
      inputs: inputs.map(i => { const el = i as HTMLInputElement; return { type: el.type || 'text', name: el.name || '', autocomplete: el.autocomplete || '', hasPattern: !!el.pattern, required: el.required }; }),
    });
  });
  return forms;
}

function analyzeStorage(type: 'localStorage' | 'sessionStorage'): StorageItem[] {
  const items: StorageItem[] = [];
  try {
    const storage = type === 'localStorage' ? localStorage : sessionStorage;
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key) { const value = storage.getItem(key) || ''; items.push({ key, value, size: value.length }); }
    }
  } catch {}
  return items;
}

function analyzeCookies(): CookieInfo[] {
  const cookies: CookieInfo[] = [];
  try {
    document.cookie.split(';').forEach(pair => {
      const [name, ...rest] = pair.trim().split('=');
      if (name) cookies.push({ name: name.trim(), value: rest.join('='), domain: window.location.hostname, path: '/', secure: window.location.protocol === 'https:', httpOnly: false, sameSite: 'unknown' });
    });
  } catch {}
  return cookies;
}

function analyzeMeta(): Record<string, string> {
  const meta: Record<string, string> = {};
  document.querySelectorAll('meta').forEach(el => {
    const name = el.getAttribute('name') || el.getAttribute('property');
    const content = el.getAttribute('content');
    if (name && content) meta[name] = content;
  });
  return meta;
}

function analyzeLinks(): LinkInfo[] {
  const links: LinkInfo[] = [];
  document.querySelectorAll('link').forEach(link => { links.push({ href: link.href, rel: link.rel, type: link.type || undefined }); });
  return links;
}