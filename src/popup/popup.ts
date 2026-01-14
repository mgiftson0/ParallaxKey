import { ScanResult, Vulnerability, Severity, Location as VaultLocation } from '../types';

const $ = (id: string) => document.getElementById(id)!;

// Theme handling
function initTheme() {
  const isDark = localStorage.getItem('theme') !== 'light';
  document.documentElement.classList.toggle('dark', isDark);
  updateThemeIcons(isDark);

  $('theme-toggle').onclick = () => {
    const nowDark = document.documentElement.classList.toggle('dark');
    localStorage.setItem('theme', nowDark ? 'dark' : 'light');
    updateThemeIcons(nowDark);
  };
}

function updateThemeIcons(isDark: boolean) {
  $('sun-icon').classList.toggle('hidden', !isDark);
  $('moon-icon').classList.toggle('hidden', isDark);
}

async function init() {
  initTheme();

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (tab?.url) {
    try {
      $('url').textContent = new URL(tab.url).hostname;
    } catch {
      $('url').textContent = tab.url.slice(0, 40);
    }

    if (tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
      $('url').textContent = 'System Restricted';
      ($('scan-btn') as HTMLButtonElement).disabled = true;
      $('btn-text').textContent = 'Restricted';
    } else {
      const status = await sendMsg({ type: 'GET_STATUS' });
      if (status?.status === 'complete') {
        const result = await sendMsg({ type: 'GET_RESULTS' });
        if (result) showResults(result);
      }
    }
  }

  $('scan-btn').onclick = scan;
}

async function scan() {
  console.log('[VaultGuard] Scan button clicked');
  const btn = $('scan-btn') as HTMLButtonElement;
  btn.disabled = true;
  $('btn-text').textContent = 'Analyzing Site...';
  $('empty').classList.add('hidden');
  $('results').classList.add('hidden');

  try {
    console.log('[VaultGuard] Sending START_SCAN message');
    const response = await sendMsg({ type: 'START_SCAN' });
    console.log('[VaultGuard] Got response:', response);

    if (response?.error) {
      console.error('[VaultGuard] Scan error:', response.error);
      showEmpty();
    } else if (response?.result) {
      showResults(response.result);
    } else {
      showEmpty();
    }
  } catch (e: any) {
    console.error('[VaultGuard] Exception:', e);
    showEmpty();
  }

  btn.disabled = false;
  $('btn-text').textContent = 'Shield Verify';
}

function showResults(result: ScanResult) {
  $('empty').classList.add('hidden');
  const resEl = $('results');
  resEl.classList.remove('hidden');
  resEl.classList.add('animate-slide-up');

  const { summary, vulnerabilities } = result;

  // Header stats
  $('issue-count').textContent = summary.total === 0 ? 'System Secure' : `${summary.total} Exposure${summary.total !== 1 ? 's' : ''}`;
  const gradeEl = $('grade');
  gradeEl.textContent = summary.grade;

  const gradeClasses: Record<string, string> = {
    A: 'bg-gradient-to-br from-green-500/20 to-emerald-600/20 border-2 border-green-500/50 text-green-400 shadow-glow',
    B: 'bg-gradient-to-br from-lime-500/20 to-green-600/20 border-2 border-lime-500/50 text-lime-400',
    C: 'bg-gradient-to-br from-amber-500/20 to-yellow-600/20 border-2 border-amber-500/50 text-amber-400',
    D: 'bg-gradient-to-br from-orange-500/20 to-red-600/20 border-2 border-orange-500/50 text-orange-400',
    F: 'bg-gradient-to-br from-red-500/20 to-red-700/20 border-2 border-red-500/50 text-red-400 threat-level-critical'
  };
  gradeEl.className = `w-14 h-14 rounded-2xl flex items-center justify-center text-2xl font-black shadow-inner transition-colors duration-500 ${gradeClasses[summary.grade] || ''}`;

  // Mini bars
  const max = Math.max(summary.total, 1);
  $('cnt-c').textContent = String(summary.bySeverity.critical);
  $('cnt-h').textContent = String(summary.bySeverity.high);
  $('cnt-m').textContent = String(summary.bySeverity.medium);
  $('cnt-l').textContent = String(summary.bySeverity.low);

  ($('bar-c') as HTMLElement).style.width = (summary.bySeverity.critical / max * 100) + '%';
  ($('bar-h') as HTMLElement).style.width = (summary.bySeverity.high / max * 100) + '%';
  ($('bar-m') as HTMLElement).style.width = (summary.bySeverity.medium / max * 100) + '%';
  ($('bar-l') as HTMLElement).style.width = (summary.bySeverity.low / max * 100) + '%';

  // Finding cards
  const list = $('findings-list');
  if (vulnerabilities.length === 0) {
    list.innerHTML = `
      <div class="text-center py-6 space-y-3">
        <div class="flex items-center justify-center gap-2 text-green-400 font-mono text-sm">
          <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
          </svg>
          <span>SECURITY PROTOCOL ACTIVE</span>
        </div>
        <div class="text-xs text-cyan-400/60 font-mono uppercase tracking-wider">No threats detected in current sector</div>
      </div>
    `;
  } else {
    list.innerHTML = vulnerabilities.map((v, i) => `
      <div class="group relative bg-slate-900/50 border border-cyan-500/20 rounded-xl p-4 hover:border-cyan-500/40 transition-all duration-300 animate-slide-up backdrop-blur-sm" style="animation-delay: ${i * 100}ms">
        <div class="absolute top-0 left-0 w-1 h-full ${getSeverityBorder(v.severity)} rounded-l-xl"></div>
        
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-3">
            <div class="w-2 h-2 rounded-full ${getSevDot(v.severity)}"></div>
            <div>
              <h4 class="text-sm font-bold text-white font-mono truncate max-w-[200px]">${esc(v.title)}</h4>
              <p class="text-xs text-cyan-400/60 font-mono mt-1">${esc(v.description || 'Threat detected')}</p>
            </div>
          </div>
          <span class="security-badge ${getSeverityBadge(v.severity)}">${v.severity}</span>
        </div>
        
        <div class="flex items-center gap-2 text-xs text-cyan-400/80 font-mono">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"/>
          </svg>
          <span>${esc(formatLocation(v.location as VaultLocation))}</span>
        </div>
        
        ${v.evidence ? `
          <div class="mt-3 pt-3 border-t border-cyan-500/20">
            <div class="text-xs text-cyan-400/60 font-mono">EVIDENCE:</div>
            <div class="text-xs text-cyan-300 font-mono bg-black/30 px-2 py-1 rounded mt-1">${esc(v.evidence)}</div>
          </div>
        ` : ''}
      </div>
    `).join('');
  }
}

function formatLocation(loc: VaultLocation): string {
  if (loc.type === 'storage') return `Storage: ${loc.storageKey}`;
  if (loc.type === 'network') return `Network: ${loc.url}`;
  if (loc.type === 'header') return `Header: ${loc.url}`;
  return loc.url || 'Internal';
}

function getSevDot(s: string): string {
  const dots: Record<string, string> = {
    critical: 'bg-red-500 shadow-red-500/50 threat-level-critical',
    high: 'bg-orange-500 shadow-orange-500/50',
    medium: 'bg-amber-500 shadow-amber-500/50',
    low: 'bg-cyan-500 shadow-cyan-500/50'
  };
  return dots[s] || 'bg-gray-400';
}

function getSeverityBorder(s: string): string {
  const borders: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-amber-500',
    low: 'bg-cyan-500'
  };
  return borders[s] || 'bg-gray-400';
}

function getSeverityBadge(s: string): string {
  const badges: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
    medium: 'bg-amber-500/20 text-amber-400 border border-amber-500/30',
    low: 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
  };
  return badges[s] || 'bg-gray-500/20 text-gray-400 border border-gray-500/30';
}

function showEmpty() {
  $('results').classList.add('hidden');
  $('empty').classList.remove('hidden');
}

function esc(s: string): string {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

function sendMsg(msg: any): Promise<any> {
  console.log('[VaultGuard] Sending message:', msg);
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, r => {
      if (chrome.runtime.lastError) {
        console.error('[VaultGuard] Runtime error:', chrome.runtime.lastError.message);
        resolve({ error: chrome.runtime.lastError.message });
      } else {
        console.log('[VaultGuard] Message response:', r);
        resolve(r);
      }
    });
  });
}

init();
