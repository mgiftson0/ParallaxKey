// VaultGuard Service Worker
console.log('[VaultGuard] Starting...');

// Types
interface Vulnerability {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: string;
  evidence: string;
}

interface ScanResult {
  id: string;
  url: string;
  timestamp: number;
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    bySeverity: { critical: number; high: number; medium: number; low: number; info: number };
    grade: string;
  };
}

interface DOMData {
  scripts: { src?: string; content?: string }[];
  localStorage: { key: string; value: string }[];
  sessionStorage: { key: string; value: string }[];
  cookies: { name: string; value: string }[];
  forms: { action: string; hasPassword: boolean }[];
}

// State
const results = new Map<number, ScanResult>();
const scanning = new Set<number>();

// Utilities
function genId(): string {
  return Math.random().toString(36).substr(2, 9);
}

function mask(s: string): string {
  if (!s || s.length < 8) return '****';
  return s.slice(0, 4) + '...' + s.slice(-4);
}

// Secret patterns
const PATTERNS: { name: string; regex: RegExp; severity: 'critical' | 'high' | 'medium' }[] = [
  { name: 'AWS Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9]{36,}/g, severity: 'critical' },
  { name: 'Stripe Key', regex: /sk_(test|live)_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { name: 'OpenAI Key', regex: /sk-[A-Za-z0-9]{48}/g, severity: 'critical' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, severity: 'medium' },
  { name: 'Slack Token', regex: /xox[baprs]-[0-9A-Za-z-]+/g, severity: 'high' },
  { name: 'Private Key', regex: /-----BEGIN [A-Z]* PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g, severity: 'high' },
];

const SENSITIVE_KEYS = [/token/i, /key/i, /secret/i, /password/i, /auth/i, /session/i, /jwt/i];

// Scanner
function findSecrets(text: string, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const found = new Set<string>();

  for (const { name, regex, severity } of PATTERNS) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      const secret = match[0];
      if (found.has(secret)) continue;
      if (/test|example|placeholder|your|xxx/i.test(secret)) continue;
      found.add(secret);

      vulns.push({
        id: genId(),
        severity,
        title: `Exposed ${name}`,
        description: `Found ${name} in ${source}`,
        location: source,
        evidence: mask(secret)
      });
    }
  }

  return vulns;
}

function scanStorage(items: { key: string; value: string }[], type: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];

  for (const { key, value } of items) {
    // Check sensitive key names
    if (SENSITIVE_KEYS.some(p => p.test(key))) {
      vulns.push({
        id: genId(),
        severity: 'medium',
        title: `Sensitive data in ${type}`,
        description: `Key "${key}" may contain sensitive data`,
        location: `${type}:${key}`,
        evidence: mask(value)
      });
    }

    // Check for secrets in value
    vulns.push(...findSecrets(value, `${type}:${key}`));
  }

  return vulns;
}

async function runScan(tabId: number, url: string): Promise<ScanResult> {
  console.log('[VaultGuard] Scanning:', url);
  const vulns: Vulnerability[] = [];

  // Get DOM data
  let domData: DOMData | null = null;
  try {
    // Inject content script
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content-script.js']
    }).catch(() => {});

    await new Promise(r => setTimeout(r, 100));

    // Request analysis
    domData = await new Promise<DOMData | null>(resolve => {
      const timeout = setTimeout(() => resolve(null), 3000);
      chrome.tabs.sendMessage(tabId, { type: 'ANALYZE' }, response => {
        clearTimeout(timeout);
        if (chrome.runtime.lastError) {
          console.log('[VaultGuard] Content script error:', chrome.runtime.lastError.message);
          resolve(null);
        } else {
          resolve(response);
        }
      });
    });
  } catch (e) {
    console.log('[VaultGuard] Could not get DOM:', e);
  }

  if (domData) {
    console.log('[VaultGuard] Got DOM data');

    // Scan scripts
    for (const script of domData.scripts || []) {
      if (script.content) {
        vulns.push(...findSecrets(script.content, script.src || 'inline-script'));
      }
    }

    // Scan storage
    vulns.push(...scanStorage(domData.localStorage || [], 'localStorage'));
    vulns.push(...scanStorage(domData.sessionStorage || [], 'sessionStorage'));

    // Scan cookies
    for (const cookie of domData.cookies || []) {
      vulns.push(...findSecrets(cookie.value, `cookie:${cookie.name}`));
    }

    // Check forms
    for (const form of domData.forms || []) {
      if (form.hasPassword && !url.startsWith('https://')) {
        vulns.push({
          id: genId(),
          severity: 'critical',
          title: 'Password form over HTTP',
          description: 'Login form on insecure page',
          location: form.action || url,
          evidence: 'Password field found'
        });
      }
    }
  }

  // Calculate summary
  const summary = {
    total: vulns.length,
    bySeverity: {
      critical: vulns.filter(v => v.severity === 'critical').length,
      high: vulns.filter(v => v.severity === 'high').length,
      medium: vulns.filter(v => v.severity === 'medium').length,
      low: vulns.filter(v => v.severity === 'low').length,
      info: vulns.filter(v => v.severity === 'info').length
    },
    grade: 'A'
  };

  const score = summary.bySeverity.critical * 25 + summary.bySeverity.high * 15 + summary.bySeverity.medium * 8 + summary.bySeverity.low * 3;
  if (score <= 10) summary.grade = 'A';
  else if (score <= 25) summary.grade = 'B';
  else if (score <= 50) summary.grade = 'C';
  else if (score <= 75) summary.grade = 'D';
  else summary.grade = 'F';

  console.log('[VaultGuard] Scan complete:', summary.total, 'issues');

  return {
    id: genId(),
    url,
    timestamp: Date.now(),
    vulnerabilities: vulns,
    summary
  };
}

// Message handler
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  console.log('[VaultGuard] Message:', msg.type);

  (async () => {
    try {
      if (msg.type === 'START_SCAN') {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id || !tab.url) {
          return { error: 'No active tab' };
        }
        if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
          return { error: 'Cannot scan this page' };
        }
        if (scanning.has(tab.id)) {
          return { error: 'Scan in progress' };
        }

        scanning.add(tab.id);
        chrome.action.setBadgeText({ text: '...', tabId: tab.id });
        chrome.action.setBadgeBackgroundColor({ color: '#3B82F6', tabId: tab.id });

        try {
          const result = await runScan(tab.id, tab.url);
          results.set(tab.id, result);

          const count = result.summary.total;
          chrome.action.setBadgeText({ text: count > 0 ? String(count) : '✓', tabId: tab.id });
          chrome.action.setBadgeBackgroundColor({ color: count > 0 ? '#EF4444' : '#10B981', tabId: tab.id });

          return { success: true, result };
        } finally {
          scanning.delete(tab.id);
        }
      }

      if (msg.type === 'GET_RESULTS') {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        return tab?.id ? results.get(tab.id) || null : null;
      }

      if (msg.type === 'GET_STATUS') {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab?.id) return { status: 'ready' };
        return {
          status: scanning.has(tab.id) ? 'scanning' : results.has(tab.id) ? 'complete' : 'ready',
          count: results.get(tab.id)?.summary.total || 0
        };
      }

      if (msg.type === 'CONTENT_READY') {
        return { ok: true };
      }

      return { error: 'Unknown message' };
    } catch (e: any) {
      console.error('[VaultGuard] Error:', e);
      return { error: e.message };
    }
  })().then(respond);

  return true;
});

// Clear results on navigation
chrome.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === 'loading') {
    results.delete(tabId);
    chrome.action.setBadgeText({ text: '', tabId });
  }
});

chrome.tabs.onRemoved.addListener(tabId => {
  results.delete(tabId);
  scanning.delete(tabId);
});

console.log('[VaultGuard] Ready');