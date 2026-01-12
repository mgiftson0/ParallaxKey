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
  const btn = $('scan-btn') as HTMLButtonElement;
  btn.disabled = true;
  $('btn-text').textContent = 'Analyzing Site...';
  $('empty').classList.add('hidden');
  $('results').classList.add('hidden');

  try {
    const response = await sendMsg({ type: 'START_SCAN' });

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
    A: 'bg-green-100 text-green-600 dark:bg-green-500/20 dark:text-green-400',
    B: 'bg-lime-100 text-lime-600 dark:bg-lime-500/20 dark:text-lime-400',
    C: 'bg-yellow-100 text-yellow-600 dark:bg-yellow-500/20 dark:text-yellow-400',
    D: 'bg-orange-100 text-orange-600 dark:bg-orange-500/20 dark:text-orange-400',
    F: 'bg-red-100 text-red-600 dark:bg-red-500/20 dark:text-red-400'
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
    list.innerHTML = '<div class="py-8 text-center space-y-2"><div class="text-green-500 font-bold">✓ Shield Active</div><div class="text-[10px] opacity-50 uppercase tracking-tighter">No threats detected in this sector</div></div>';
  } else {
    list.innerHTML = vulnerabilities.map((v, i) => `
      <div class="group p-3 bg-gray-50 dark:bg-white/5 rounded-xl border border-gray-100 dark:border-white/5 hover:border-primary/50 dark:hover:border-primary/50 transition-all duration-300 animate-slide-up" style="animation-delay: ${i * 50}ms">
        <div class="flex items-center justify-between mb-1.5">
          <div class="flex items-center gap-2">
            <span class="w-1.5 h-1.5 rounded-full ${getSevDot(v.severity)} shadow-sm"></span>
            <span class="text-xs font-bold truncate max-w-[180px] dark:text-white">${esc(v.title)}</span>
          </div>
          <span class="text-[9px] font-black uppercase tracking-tighter opacity-40">${v.severity}</span>
        </div>
        <div class="text-[10px] text-secondary-light truncate opacity-80">${esc(formatLocation(v.location as VaultLocation))}</div>
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
    critical: 'bg-red-500 shadow-red-500/50',
    high: 'bg-orange-500 shadow-orange-500/50',
    medium: 'bg-amber-500 shadow-amber-500/50',
    low: 'bg-blue-400 shadow-blue-400/50'
  };
  return dots[s] || 'bg-gray-400';
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
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, r => {
      if (chrome.runtime.lastError) resolve({ error: chrome.runtime.lastError.message });
      else resolve(r);
    });
  });
}

init();
