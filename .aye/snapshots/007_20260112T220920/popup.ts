// VaultGuard Popup - Self-contained

console.log('[VaultGuard] Popup loaded');

interface Vulnerability {
  id: string;
  type: string;
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
    bySeverity: Record<string, number>;
    riskScore: number;
    grade: string;
  };
}

const $ = (id: string) => document.getElementById(id)!;

let currentResult: ScanResult | null = null;

async function init() {
  console.log('[VaultGuard] Initializing popup...');
  
  try {
    // Get current tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (tab?.url) {
      // Show URL
      try {
        $('site-url').textContent = new URL(tab.url).hostname;
      } catch {
        $('site-url').textContent = tab.url.slice(0, 40);
      }
      
      // Check if we can scan
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('about:')) {
        $('site-url').textContent = 'Cannot scan this page';
        ($('btn-scan') as HTMLButtonElement).disabled = true;
        ($('btn-scan') as HTMLButtonElement).classList.add('opacity-50');
      } else {
        // Check for existing results
        const status = await sendMessage({ type: 'GET_STATUS' });
        console.log('[VaultGuard] Status:', status);
        
        if (status?.status === 'complete') {
          const result = await sendMessage({ type: 'GET_RESULTS' });
          if (result) {
            currentResult = result;
            showResults(result);
          }
        }
      }
    } else {
      $('site-url').textContent = 'No page loaded';
      ($('btn-scan') as HTMLButtonElement).disabled = true;
    }
  } catch (e) {
    console.error('[VaultGuard] Init error:', e);
    $('site-url').textContent = 'Error loading page info';
  }
  
  // Set up click handler
  $('btn-scan').addEventListener('click', startScan);
}

async function startScan() {
  console.log('[VaultGuard] Starting scan...');
  
  // Update UI
  ($('btn-scan') as HTMLButtonElement).disabled = true;
  $('btn-text').textContent = 'Scanning...';
  $('empty').classList.add('hidden');
  $('results').classList.add('hidden');
  
  try {
    const response = await sendMessage({ type: 'START_SCAN' });
    console.log('[VaultGuard] Scan response:', response);
    
    if (response?.error) {
      alert('Scan failed: ' + response.error);
      showEmpty();
    } else if (response?.result) {
      currentResult = response.result;
      showResults(response.result);
    } else {
      // Try to get results
      const result = await sendMessage({ type: 'GET_RESULTS' });
      if (result) {
        currentResult = result;
        showResults(result);
      } else {
        showEmpty();
      }
    }
  } catch (e: any) {
    console.error('[VaultGuard] Scan error:', e);
    alert('Scan failed: ' + e.message);
    showEmpty();
  }
  
  // Reset button
  ($('btn-scan') as HTMLButtonElement).disabled = false;
  $('btn-text').textContent = 'Scan Again';
}

function showResults(result: ScanResult) {
  console.log('[VaultGuard] Showing results:', result.summary);
  
  $('empty').classList.add('hidden');
  $('results').classList.remove('hidden');
  
  const { summary, vulnerabilities } = result;
  
  // Update summary
  $('vuln-count').textContent = `${summary.total} issue${summary.total !== 1 ? 's' : ''} found`;
  $('grade').textContent = summary.grade;
  $('grade').className = `w-12 h-12 rounded-full flex items-center justify-center text-xl font-bold ${getGradeClass(summary.grade)}`;
  
  // Update severity counts and bars
  const maxCount = Math.max(summary.total, 1);
  
  $('cnt-crit').textContent = String(summary.bySeverity.critical || 0);
  $('cnt-high').textContent = String(summary.bySeverity.high || 0);
  $('cnt-med').textContent = String(summary.bySeverity.medium || 0);
  $('cnt-low').textContent = String(summary.bySeverity.low || 0);
  
  ($('bar-crit') as HTMLElement).style.width = `${((summary.bySeverity.critical || 0) / maxCount) * 100}%`;
  ($('bar-high') as HTMLElement).style.width = `${((summary.bySeverity.high || 0) / maxCount) * 100}%`;
  ($('bar-med') as HTMLElement).style.width = `${((summary.bySeverity.medium || 0) / maxCount) * 100}%`;
  ($('bar-low') as HTMLElement).style.width = `${((summary.bySeverity.low || 0) / maxCount) * 100}%`;
  
  // Show findings
  const findingsEl = $('findings');
  
  if (vulnerabilities.length === 0) {
    findingsEl.innerHTML = `
      <div class="text-center py-4 text-green-600">
        <svg class="w-8 h-8 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <p class="font-medium">No vulnerabilities found!</p>
      </div>
    `;
  } else {
    findingsEl.innerHTML = vulnerabilities.slice(0, 10).map(v => `
      <div class="p-2.5 bg-white rounded-lg border text-sm">
        <div class="flex items-start gap-2">
          <span class="w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${getSeverityBgClass(v.severity)}"></span>
          <div class="min-w-0">
            <p class="font-medium text-gray-900 truncate">${escapeHtml(v.title)}</p>
            <p class="text-xs text-gray-500 truncate">${escapeHtml(v.location)}</p>
          </div>
        </div>
      </div>
    `).join('');
  }
}

function showEmpty() {
  $('results').classList.add('hidden');
  $('empty').classList.remove('hidden');
}

function getGradeClass(grade: string): string {
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
  div.textContent = text || '';
  return div.innerHTML;
}

function sendMessage(message: any): Promise<any> {
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