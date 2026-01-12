// VaultGuard Service Worker - Self-contained, no imports

console.log('[VaultGuard] Service worker starting...');

// ============ TYPES ============
interface Vulnerability {
  id: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  location: string;
  evidence: string;
  remediation: string[];
}

interface ScanResult {
  id: string;
  url: string;
  timestamp: number;
  vulnerabilities: Vulnerability[];
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    riskScore: number;
    grade: string;
  };
}

interface DOMData {
  scripts: { src?: string; content?: string }[];
  forms: { action: string; method: string; hasPassword: boolean }[];
  localStorage: { key: string; value: string }[];
  sessionStorage: { key: string; value: string }[];
  cookies: { name: string; value: string }[];
}

interface TabState {
  url: string;
  scanning: boolean;
  result?: ScanResult;
}

// ============ STATE ============
const tabStates = new Map<number, TabState>();

// ============ UTILITIES ============
function generateId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

function maskSecret(s: string): string {
  if (!s || s.length < 8) return '****';
  return s.slice(0, 4) + '****' + s.slice(-4);
}

// ============ PATTERNS ============
const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const },
  { name: 'GitHub Token', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g, severity: 'critical' as const },
  { name: 'Stripe Secret', pattern: /sk_(test|live)_[0-9a-zA-Z]{24,}/g, severity: 'critical' as const },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'medium' as const },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,}-[0-9A-Za-z]{24,}/g, severity: 'high' as const },
  { name: 'OpenAI Key', pattern: /sk-[A-Za-z0-9]{48}/g, severity: 'critical' as const },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/g, severity: 'critical' as const },
  { name: 'Generic API Key', pattern: /['"][a-zA-Z0-9_-]*api[_-]?key['"]\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi, severity: 'high' as const },
  { name: 'Generic Secret', pattern: /['"][a-zA-Z0-9_-]*secret['"]\s*[:=]\s*['"][a-zA-Z0-9_-]{20,}['"]/gi, severity: 'high' as const },
];

const STORAGE_SENSITIVE_KEYS = [
  /token/i, /key/i, /secret/i, /password/i, /auth/i, /session/i, /jwt/i, /credential/i
];

// ============ SCANNER ============
function scanForSecrets(content: string, source: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const found = new Set<string>();
  
  for (const { name, pattern, severity } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const secret = match[0];
      const key = `${name}:${secret}`;
      if (found.has(key)) continue;
      found.add(key);
      
      // Skip obvious placeholders
      if (/example|test|placeholder|your|xxx/i.test(secret)) continue;
      
      vulns.push({
        id: generateId(),
        type: 'secret_exposure',
        severity,
        title: `Exposed ${name}`,
        description: `A ${name} was found in ${source}`,
        location: source,
        evidence: maskSecret(secret),
        remediation: ['Remove the secret from client-side code', 'Rotate the compromised credential', 'Use environment variables on the server']
      });
    }
  }
  
  return vulns;
}

function scanStorage(items: { key: string; value: string }[], storageType: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  
  for (const { key, value } of items) {
    // Check for sensitive keys
    if (STORAGE_SENSITIVE_KEYS.some(p => p.test(key))) {
      vulns.push({
        id: generateId(),
        type: 'sensitive_storage',
        severity: 'medium',
        title: `Sensitive data in ${storageType}`,
        description: `Key "${key}" may contain sensitive data`,
        location: `${storageType}:${key}`,
        evidence: maskSecret(value),
        remediation: ['Use httpOnly cookies for sensitive data', 'Avoid storing secrets in browser storage']
      });
    }
    
    // Check for JWT
    if (/^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/.test(value)) {
      vulns.push({
        id: generateId(),
        type: 'jwt_in_storage',
        severity: 'high',
        title: `JWT token in ${storageType}`,
        description: 'JWT tokens in browser storage are vulnerable to XSS attacks',
        location: `${storageType}:${key}`,
        evidence: maskSecret(value),
        remediation: ['Use httpOnly cookies for JWT tokens', 'Implement token refresh mechanism']
      });
    }
    
    // Scan value for secrets
    vulns.push(...scanForSecrets(value, `${storageType}:${key}`));
  }
  
  return vulns;
}

function scanForms(forms: DOMData['forms'], url: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  const isHttps = url.startsWith('https://');
  
  for (const form of forms) {
    if (form.hasPassword) {
      const actionIsHttps = !form.action || form.action.startsWith('https://') || form.action.startsWith('/');
      
      if (!isHttps || !actionIsHttps) {
        vulns.push({
          id: generateId(),
          type: 'insecure_form',
          severity: 'critical',
          title: 'Password form over insecure connection',
          description: 'Login form submits credentials over HTTP',
          location: form.action || url,
          evidence: `Form method: ${form.method}`,
          remediation: ['Use HTTPS for all pages with password forms', 'Ensure form action uses HTTPS']
        });
      }
    }
  }
  
  return vulns;
}

async function runScan(tabId: number, url: string): Promise<ScanResult> {
  console.log('[VaultGuard] Running scan for:', url);
  
  const vulnerabilities: Vulnerability[] = [];
  
  // Get DOM data from content script
  let domData: DOMData | null = null;
  
  try {
    // First try to inject content script
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ['content/content-script.js']
    }).catch(() => {});
    
    // Wait a bit for script to initialize
    await new Promise(r => setTimeout(r, 200));
    
    // Request DOM analysis
    domData = await new Promise<DOMData | null>((resolve) => {
      const timeout = setTimeout(() => resolve(null), 3000);
      
      chrome.tabs.sendMessage(tabId, { type: 'ANALYZE_DOM' }, (response) => {
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
    console.log('[VaultGuard] Could not get DOM data:', e);
  }
  
  if (domData) {
    console.log('[VaultGuard] Got DOM data:', {
      scripts: domData.scripts?.length || 0,
      forms: domData.forms?.length || 0,
      localStorage: domData.localStorage?.length || 0,
      sessionStorage: domData.sessionStorage?.length || 0,
      cookies: domData.cookies?.length || 0
    });
    
    // Scan inline scripts
    for (const script of domData.scripts || []) {
      if (script.content) {
        vulnerabilities.push(...scanForSecrets(script.content, script.src || 'inline-script'));
      }
    }
    
    // Scan storage
    vulnerabilities.push(...scanStorage(domData.localStorage || [], 'localStorage'));
    vulnerabilities.push(...scanStorage(domData.sessionStorage || [], 'sessionStorage'));
    
    // Scan cookies
    for (const cookie of domData.cookies || []) {
      vulnerabilities.push(...scanForSecrets(cookie.value, `cookie:${cookie.name}`));
    }
    
    // Scan forms
    vulnerabilities.push(...scanForms(domData.forms || [], url));
  } else {
    console.log('[VaultGuard] No DOM data available, running limited scan');
  }
  
  // Calculate summary
  const summary = {
    total: vulnerabilities.length,
    bySeverity: {
      critical: vulnerabilities.filter(v => v.severity === 'critical').length,
      high: vulnerabilities.filter(v => v.severity === 'high').length,
      medium: vulnerabilities.filter(v => v.severity === 'medium').length,
      low: vulnerabilities.filter(v => v.severity === 'low').length,
      info: vulnerabilities.filter(v => v.severity === 'info').length
    },
    riskScore: 0,
    grade: 'A'
  };
  
  // Calculate risk score
  summary.riskScore = Math.min(100,
    summary.bySeverity.critical * 25 +
    summary.bySeverity.high * 15 +
    summary.bySeverity.medium * 8 +
    summary.bySeverity.low * 3
  );
  
  // Calculate grade
  if (summary.riskScore <= 10) summary.grade = 'A';
  else if (summary.riskScore <= 25) summary.grade = 'B';
  else if (summary.riskScore <= 50) summary.grade = 'C';
  else if (summary.riskScore <= 75) summary.grade = 'D';
  else summary.grade = 'F';
  
  const result: ScanResult = {
    id: generateId(),
    url,
    timestamp: Date.now(),
    vulnerabilities,
    summary
  };
  
  console.log('[VaultGuard] Scan complete:', summary);
  
  return result;
}

// ============ MESSAGE HANDLER ============
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log('[VaultGuard] Message:', message.type);
  
  const handleAsync = async () => {
    try {
      switch (message.type) {
        case 'START_SCAN': {
          // Get active tab
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (!tab?.id || !tab.url) {
            return { success: false, error: 'No active tab' };
          }
          
          // Check if scannable
          if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
            return { success: false, error: 'Cannot scan this page' };
          }
          
          let state = tabStates.get(tab.id);
          if (state?.scanning) {
            return { success: false, error: 'Scan in progress' };
          }
          
          // Set scanning state
          state = { url: tab.url, scanning: true };
          tabStates.set(tab.id, state);
          
          // Update badge
          chrome.action.setBadgeText({ text: '...', tabId: tab.id });
          chrome.action.setBadgeBackgroundColor({ color: '#3B82F6', tabId: tab.id });
          
          // Run scan
          const result = await runScan(tab.id, tab.url);
          
          // Save result
          state.scanning = false;
          state.result = result;
          tabStates.set(tab.id, state);
          
          // Save to storage
          try {
            const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
            scanHistory.unshift(result);
            if (scanHistory.length > 50) scanHistory.pop();
            await chrome.storage.local.set({ scanHistory });
          } catch (e) {
            console.error('[VaultGuard] Failed to save scan:', e);
          }
          
          // Update badge
          const count = result.summary.total;
          chrome.action.setBadgeText({ text: count > 0 ? String(count) : '\'u2713', tabId: tab.id });
          chrome.action.setBadgeBackgroundColor({ color: count > 0 ? '#EF4444' : '#10B981', tabId: tab.id });
          
          return { success: true, result };
        }
        
        case 'GET_RESULTS': {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (!tab?.id) return null;
          return tabStates.get(tab.id)?.result || null;
        }
        
        case 'GET_STATUS': {
          const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
          if (!tab?.id) return { status: 'ready' };
          const state = tabStates.get(tab.id);
          return {
            status: state?.scanning ? 'scanning' : state?.result ? 'complete' : 'ready',
            count: state?.result?.summary.total || 0
          };
        }
        
        case 'GET_HISTORY': {
          const { scanHistory = [] } = await chrome.storage.local.get('scanHistory');
          return scanHistory;
        }
        
        case 'CONTENT_READY': {
          console.log('[VaultGuard] Content script ready');
          return { success: true };
        }
        
        default:
          return { error: 'Unknown message type' };
      }
    } catch (e: any) {
      console.error('[VaultGuard] Error:', e);
      return { error: e.message };
    }
  };
  
  handleAsync().then(sendResponse);
  return true; // Keep channel open
});

// ============ TAB EVENTS ============
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Clear old results when page changes
    const state = tabStates.get(tabId);
    if (state && state.url !== tab.url) {
      tabStates.set(tabId, { url: tab.url, scanning: false });
      chrome.action.setBadgeText({ text: '', tabId });
    }
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  tabStates.delete(tabId);
});

// ============ KEEP ALIVE ============
// Set up alarm to keep service worker alive during scans
chrome.alarms.create('keepAlive', { periodInMinutes: 0.4 });

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    // Check if any scans are in progress
    for (const [tabId, state] of tabStates) {
      if (state.scanning) {
        console.log('[VaultGuard] Keeping alive for scan on tab', tabId);
      }
    }
  }
});

console.log('[VaultGuard] Service worker initialized');