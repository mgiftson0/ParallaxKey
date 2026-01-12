import { DOMAnalysisResult, Message } from '../types';

console.log('[VaultGuard] Content script loaded');

// Notify background that content script is ready
try {
  chrome.runtime.sendMessage({ type: 'CONTENT_READY' });
} catch (e) {
  console.log('[VaultGuard] Could not send ready message');
}

// Listen for messages from background
chrome.runtime.onMessage.addListener((message: Message, sender, sendResponse) => {
  console.log('[VaultGuard] Content script received:', message.type);
  
  if (message.type === 'ANALYZE_DOM') {
    try {
      const result = analyzeDom();
      console.log('[VaultGuard] DOM analysis complete:', {
        scripts: result.scripts.length,
        forms: result.forms.length,
        localStorage: result.localStorage.length,
        sessionStorage: result.sessionStorage.length,
        cookies: result.cookies.length
      });
      sendResponse(result);
    } catch (e: any) {
      console.error('[VaultGuard] DOM analysis error:', e);
      sendResponse({
        scripts: [],
        forms: [],
        localStorage: [],
        sessionStorage: [],
        cookies: [],
        meta: {},
        error: e.message
      });
    }
    return true;
  }
  
  return false;
});

function analyzeDom(): DOMAnalysisResult {
  return {
    scripts: getScripts(),
    forms: getForms(),
    localStorage: getStorageItems('localStorage'),
    sessionStorage: getStorageItems('sessionStorage'),
    cookies: getCookies(),
    meta: getMeta()
  };
}

function getScripts(): DOMAnalysisResult['scripts'] {
  const scripts: DOMAnalysisResult['scripts'] = [];
  
  try {
    document.querySelectorAll('script').forEach((script) => {
      scripts.push({
        src: script.src || undefined,
        content: !script.src ? (script.textContent || undefined) : undefined
      });
    });
  } catch (e) {
    console.error('[VaultGuard] Error getting scripts:', e);
  }
  
  return scripts;
}

function getForms(): DOMAnalysisResult['forms'] {
  const forms: DOMAnalysisResult['forms'] = [];
  
  try {
    document.querySelectorAll('form').forEach((form) => {
      forms.push({
        action: form.action || '',
        method: form.method || 'GET',
        hasPassword: !!form.querySelector('input[type="password"]')
      });
    });
  } catch (e) {
    console.error('[VaultGuard] Error getting forms:', e);
  }
  
  return forms;
}

function getStorageItems(type: 'localStorage' | 'sessionStorage'): { key: string; value: string }[] {
  const items: { key: string; value: string }[] = [];
  
  try {
    const storage = type === 'localStorage' ? window.localStorage : window.sessionStorage;
    
    for (let i = 0; i < storage.length; i++) {
      const key = storage.key(i);
      if (key) {
        const value = storage.getItem(key) || '';
        items.push({ key, value });
      }
    }
  } catch (e) {
    // Storage might be blocked
    console.log('[VaultGuard] Could not access', type);
  }
  
  return items;
}

function getCookies(): DOMAnalysisResult['cookies'] {
  const cookies: DOMAnalysisResult['cookies'] = [];
  
  try {
    const cookieString = document.cookie;
    if (cookieString) {
      cookieString.split(';').forEach((cookie) => {
        const trimmed = cookie.trim();
        if (trimmed) {
          const [name, ...valueParts] = trimmed.split('=');
          if (name) {
            cookies.push({
              name: name.trim(),
              value: valueParts.join('='),
              secure: window.location.protocol === 'https:',
              httpOnly: false, // Can't detect from JS
              sameSite: 'unknown'
            });
          }
        }
      });
    }
  } catch (e) {
    console.log('[VaultGuard] Could not access cookies');
  }
  
  return cookies;
}

function getMeta(): Record<string, string> {
  const meta: Record<string, string> = {};
  
  try {
    document.querySelectorAll('meta').forEach((el) => {
      const name = el.getAttribute('name') || el.getAttribute('property');
      const content = el.getAttribute('content');
      if (name && content) {
        meta[name] = content;
      }
    });
  } catch (e) {
    console.error('[VaultGuard] Error getting meta:', e);
  }
  
  return meta;
}

console.log('[VaultGuard] Content script ready');