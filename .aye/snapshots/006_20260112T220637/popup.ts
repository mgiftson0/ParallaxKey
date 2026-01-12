import { ScanResult, Message } from '../types';

const $ = (id: string) => document.getElementById(id)!;

let currentTabId: number | undefined;
let currentResult: ScanResult | null = null;

console.log('[VaultGuard] Popup loaded');

async function init() {
  console.log('[VaultGuard] Initializing popup...');
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    console.log('[VaultGuard] Active tab:', tab);
    
    if (tab?.id && tab.url) {
      currentTabId = tab.id;
      
      // Show hostname
      try {
        $('site-url').textContent = new URL(tab.url).hostname;
      } catch {
        $('site-url').textContent = tab.url;
      }
      
      // Check for existing results
      const status = await sendMessage({ type: 'GET_STATUS', tabId: currentTabId });
      console.log('[VaultGuard] Status:', status);
      
      if (status?.status === 'complete') {
        const result = await sendMessage({ type: 'GET_RESULTS', tabId: currentTabId });
        if (result) {
          currentResult = result;
          showResults(result);
        }
      }
      
      // Check if we can scan this page
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
        $('site-url').textContent = 'Cannot scan this page';
        ($('btn-scan') as HTMLButtonElement).disabled = true;
      }
    } else {
      $('site-url').textContent = 'No page loaded';
      ($('btn-scan') as HTMLButtonElement).disabled = true;
    }
  } catch (e) {
    console.error('[VaultGuard] Init error:', e);
  }
  
  // Set up event listeners
  $('btn-scan').addEventListener('click', startScan);
  $('btn-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
  $('btn-export').addEventListener('click', exportReport);
  
  // Listen for scan completion
  chrome.runtime.onMessage.addListener((message: Message) => {
    console.log('[VaultGuard] Popup received message:', message.type);
    if (message.type === 'SCAN_COMPLETE' && message.payload) {
      currentResult = message.payload as ScanResult;
      showResults(currentResult);
    }
  });
}

async function startScan() {
  console.log('[VaultGuard] Starting scan...');
  
  if (!currentTabId) {
    console.error('[VaultGuard] No tab ID');
    alert('Cannot scan: No active tab');
    return;
  }
  
  // Show scanning state
  showScanning();
  
  try {
    const scanType = ($('scan-type') as HTMLSelectElement).value as 'quick' | 'standard' | 'deep';
    console.log('[VaultGuard] Scan type:', scanType);
    
    // Request scan
    const scanResponse = await sendMessage({ 
      type: 'START_SCAN', 
      tabId: currentTabId, 
      payload: { type: scanType } 
    });
    
    console.log('[VaultGuard] Scan response:', scanResponse);
    
    if (scanResponse?.error) {
      throw new Error(scanResponse.error);
    }
    
    // Get results after a short delay
    await new Promise(resolve => setTimeout(resolve, 500));
    
    const result = await sendMessage({ type: 'GET_RESULTS', tabId: currentTabId });
    console.log('[VaultGuard] Got results:', result);
    
    if (result) {
      currentResult = result;
      showResults(result);
    } else {
      showEmpty();
    }
    
  } catch (error: any) {
    console.error('[VaultGuard] Scan error:', error);
    showEmpty();
    alert('Scan failed: ' + (error.message || 'Unknown error'));
  }
}

function showScanning() {
  $('empty').classList.add('hidden');
  $('results').classList.add('hidden');
  $('scanning').classList.remove('hidden');
  ($('btn-scan') as HTMLButtonElement).disabled = true;
}

function showResults(result: ScanResult) {
  console.log('[VaultGuard] Showing results:', result.summary);
  
  $('scanning').classList.add('hidden');
  $('empty').classList.add('hidden');
  $('results').classList.remove('hidden');
  ($('btn-scan') as HTMLButtonElement).disabled = false;
  
  const summary = result.summary;
  
  // Update count and grade
  $('vuln-count').textContent = `${summary.total} issue${summary.total !== 1 ? 's' : ''} found`;
  $('grade').textContent = summary.grade;
  $('grade').className = `w-14 h-14 rounded-full flex items-center justify-center text-2xl font-bold ${getGradeClasses(summary.grade)}`;
  
  // Update severity bars
  const total = Math.max(summary.total, 1);
  
  $('cnt-crit').textContent = String(summary.bySeverity.critical || 0);
  $('cnt-high').textContent = String(summary.bySeverity.high || 0);
  $('cnt-med').textContent = String(summary.bySeverity.medium || 0);
  $('cnt-low').textContent = String(summary.bySeverity.low || 0);
  
  ($('bar-crit') as HTMLElement).style.width = `${((summary.bySeverity.critical || 0) / total) * 100}%`;
  ($('bar-high') as HTMLElement).style.width = `${((summary.bySeverity.high || 0) / total) * 100}%`;
  ($('bar-med') as HTMLElement).style.width = `${((summary.bySeverity.medium || 0) / total) * 100}%`;
  ($('bar-low') as HTMLElement).style.width = `${((summary.bySeverity.low || 0) / total) * 100}%`;
  
  // Update findings list
  const findingsList = $('findings');
  
  if (result.vulnerabilities.length === 0) {
    findingsList.innerHTML = '<div class="text-center py-4 text-green-600">No vulnerabilities found! 🎉</div>';
  } else {
    findingsList.innerHTML = result.vulnerabilities.slice(0, 5).map(v => `
      <div class="p-3 bg-white rounded-lg border">
        <div class="flex items-center gap-2 mb-1">
          <span class="w-2 h-2 rounded-full ${getSeverityBgClass(v.severity)}"></span>
          <span class="text-sm font-medium truncate">${escapeHtml(v.title)}</span>
        </div>
        <p class="text-xs text-gray-500 truncate">${escapeHtml(v.location.url || v.location.storageKey || 'N/A')}</p>
      </div>
    `).join('');
  }
}

function showEmpty() {
  $('scanning').classList.add('hidden');
  $('results').classList.add('hidden');
  $('empty').classList.remove('hidden');
  ($('btn-scan') as HTMLButtonElement).disabled = false;
}

function getGradeClasses(grade: string): string {
  const classes: Record<string, string> = {
    'A': 'bg-green-100 text-green-600',
    'B': 'bg-lime-100 text-lime-600',
    'C': 'bg-yellow-100 text-yellow-600',
    'D': 'bg-orange-100 text-orange-600',
    'F': 'bg-red-100 text-red-600'
  };
  return classes[grade] || 'bg-gray-100 text-gray-600';
}

function getSeverityBgClass(severity: string): string {
  const classes: Record<string, string> = {
    'critical': 'bg-red-600',
    'high': 'bg-orange-500',
    'medium': 'bg-yellow-500',
    'low': 'bg-blue-500',
    'info': 'bg-gray-400'
  };
  return classes[severity] || 'bg-gray-400';
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function exportReport() {
  if (!currentResult) {
    alert('No scan results to export');
    return;
  }
  
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vaultguard-report-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function sendMessage(message: Message): Promise<any> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        console.error('[VaultGuard] Message error:', chrome.runtime.lastError);
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(response);
      }
    });
  });
}

// Initialize
init();