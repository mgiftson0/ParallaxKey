// VaultGuard Content Script - Self-contained

console.log('[VaultGuard] Content script loaded on:', window.location.href);

interface DOMData {
  scripts: { src?: string; content?: string }[];
  forms: { action: string; method: string; hasPassword: boolean }[];
  localStorage: { key: string; value: string }[];
  sessionStorage: { key: string; value: string }[];
  cookies: { name: string; value: string }[];
}

function analyzeDom(): DOMData {
  console.log('[VaultGuard] Analyzing DOM...');
  
  const result: DOMData = {
    scripts: [],
    forms: [],
    localStorage: [],
    sessionStorage: [],
    cookies: []
  };
  
  // Get scripts
  try {
    document.querySelectorAll('script').forEach(script => {
      result.scripts.push({
        src: script.src || undefined,
        content: !script.src ? (script.textContent || undefined) : undefined
      });
    });
  } catch (e) {
    console.error('[VaultGuard] Error getting scripts:', e);
  }
  
  // Get forms
  try {
    document.querySelectorAll('form').forEach(form => {
      result.forms.push({
        action: form.action || '',
        method: form.method || 'GET',
        hasPassword: !!form.querySelector('input[type="password"]')
      });
    });
  } catch (e) {
    console.error('[VaultGuard] Error getting forms:', e);
  }
  
  // Get localStorage
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) {
        result.localStorage.push({
          key,
          value: localStorage.getItem(key) || ''
        });
      }
    }
  } catch (e) {
    console.log('[VaultGuard] Could not access localStorage');
  }
  
  // Get sessionStorage
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key) {
        result.sessionStorage.push({
          key,
          value: sessionStorage.getItem(key) || ''
        });
      }
    }
  } catch (e) {
    console.log('[VaultGuard] Could not access sessionStorage');
  }
  
  // Get cookies
  try {
    if (document.cookie) {
      document.cookie.split(';').forEach(cookie => {
        const [name, ...valueParts] = cookie.trim().split('=');
        if (name) {
          result.cookies.push({
            name: name.trim(),
            value: valueParts.join('=')
          });
        }
      });
    }
  } catch (e) {
    console.log('[VaultGuard] Could not access cookies');
  }
  
  console.log('[VaultGuard] DOM analysis complete:', {
    scripts: result.scripts.length,
    forms: result.forms.length,
    localStorage: result.localStorage.length,
    sessionStorage: result.sessionStorage.length,
    cookies: result.cookies.length
  });
  
  return result;
}

// Listen for messages
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[VaultGuard] Content script received:', message.type);
  
  if (message.type === 'ANALYZE_DOM') {
    try {
      const data = analyzeDom();
      sendResponse(data);
    } catch (e: any) {
      console.error('[VaultGuard] Analysis error:', e);
      sendResponse({ error: e.message });
    }
    return true;
  }
  
  return false;
});

// Notify background that we're ready
try {
  chrome.runtime.sendMessage({ type: 'CONTENT_READY' }).catch(() => {});
} catch (e) {
  // Extension context may be invalid
}

console.log('[VaultGuard] Content script ready');