// ParallaxKey Content Script
console.log('[ParallaxKey] Content script loaded');

interface DOMData {
  scripts: { src?: string; content?: string }[];
  localStorage: { key: string; value: string }[];
  sessionStorage: { key: string; value: string }[];
  cookies: { name: string; value: string }[];
  forms: { action: string; hasPassword: boolean }[];
}

function analyze(): DOMData {
  const data: DOMData = {
    scripts: [],
    localStorage: [],
    sessionStorage: [],
    cookies: [],
    forms: []
  };

  // Scripts
  try {
    document.querySelectorAll('script').forEach(s => {
      data.scripts.push({
        src: s.src || undefined,
        content: !s.src ? (s.textContent || undefined) : undefined
      });
    });
  } catch (e) { console.log('[VG] scripts error:', e); }

  // localStorage
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key) data.localStorage.push({ key, value: localStorage.getItem(key) || '' });
    }
  } catch (e) { console.log('[VG] localStorage error:', e); }

  // sessionStorage
  try {
    for (let i = 0; i < sessionStorage.length; i++) {
      const key = sessionStorage.key(i);
      if (key) data.sessionStorage.push({ key, value: sessionStorage.getItem(key) || '' });
    }
  } catch (e) { console.log('[VG] sessionStorage error:', e); }

  // Cookies
  try {
    document.cookie.split(';').forEach(c => {
      const [name, ...v] = c.trim().split('=');
      if (name) data.cookies.push({ name: name.trim(), value: v.join('=') });
    });
  } catch (e) { console.log('[VG] cookies error:', e); }

  // Forms
  try {
    document.querySelectorAll('form').forEach(f => {
      data.forms.push({
        action: f.action || '',
        hasPassword: !!f.querySelector('input[type="password"]')
      });
    });
  } catch (e) { console.log('[VG] forms error:', e); }

  console.log('[ParallaxKey] Analysis:', {
    scripts: data.scripts.length,
    localStorage: data.localStorage.length,
    sessionStorage: data.sessionStorage.length,
    cookies: data.cookies.length,
    forms: data.forms.length
  });

  return data;
}

chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type === 'ANALYZE') {
    respond(analyze());
    return true;
  }
});

try {
  chrome.runtime.sendMessage({ type: 'CONTENT_READY' }).catch(() => {});
} catch (e) {}

console.log('[ParallaxKey] Content script ready');