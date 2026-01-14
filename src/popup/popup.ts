import { ScanResult, Vulnerability, Severity, Location as ParallaxLocation } from '../types';

const $ = (id: string) => document.getElementById(id)!;

// Theme handling
function initTheme() {
  const isDark = localStorage.getItem('theme') !== 'light';
  document.documentElement.classList.add('dark'); // Always dark for premium feel
  updateThemeIcons(true);

  $('theme-toggle').onclick = () => {
    // For now, keep it dark but maintain the toggle logic for future themes
    const isNowLight = document.documentElement.classList.toggle('dark');
    updateThemeIcons(!isNowLight);
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
      showRestricted();
    } else {
      const status = await sendMsg({ type: 'GET_STATUS' });
      if (status?.status === 'complete') {
        const result = await sendMsg({ type: 'GET_RESULTS' });
        if (result) showResults(result);
      }
    }
  }

  $('scan-btn').onclick = scan;

  // Real-time counter simulation
  const safeReq = $('safe-requests');
  if (safeReq) {
    let count = 842;
    setInterval(() => {
      count += Math.floor(Math.random() * 2);
      safeReq.textContent = String(count);
    }, 3000);
  }
}

function showRestricted() {
  const btn = $('scan-btn') as HTMLButtonElement;
  btn.disabled = true;
  $('btn-text').textContent = 'Restricted domain';
  $('empty-msg').textContent = 'Have you been vibe coding? This domain is restricted for security reasons.';
}

async function scan() {
  const btn = $('scan-btn') as HTMLButtonElement;
  btn.disabled = true;
  $('btn-text').textContent = 'Analyzing...';

  // Visual feedback
  const content = $('content-area');
  content.style.opacity = '0.5';
  content.style.pointerEvents = 'none';

  try {
    const response = await sendMsg({ type: 'START_SCAN' });

    if (response?.error) {
      showFriendlyError(response.error);
    } else if (response?.result) {
      showResults(response.result);
    } else {
      showFriendlyError('No response from scanner');
    }
  } catch (e: any) {
    showFriendlyError(e.message);
  }

  btn.disabled = false;
  $('btn-text').textContent = 'Re-Verify';
  content.style.opacity = '1';
  content.style.pointerEvents = 'auto';
}

function showFriendlyError(msg: string) {
  $('results').classList.add('hidden');
  $('empty').classList.remove('hidden');
  $('empty-msg').innerHTML = `<span class="text-[#ef4444] font-bold block mb-2 tracking-tight">ALERT_EXCEPTION</span> <span class="text-white opacity-90">Have you been vibe coding?</span> <br/><span class="text-[10px] text-muted-foreground mt-2 inline-block bg-white/5 px-2 py-0.5 rounded border border-white/5">${msg}</span>`;
}

function showResults(result: ScanResult) {
  $('empty').classList.add('hidden');
  const resEl = $('results');
  resEl.classList.remove('hidden');

  const { summary, vulnerabilities } = result;

  // Header stats
  $('issue-count').textContent = summary.total === 0 ? 'Surface Secure' : `${summary.total} Exposure${summary.total !== 1 ? 's' : ''}`;
  const gradeEl = $('grade');
  gradeEl.textContent = summary.grade;

  // Semantic Colors for Grade and Bars
  const gradeMap: Record<string, { color: string, border: string, bg: string }> = {
    A: { color: 'text-[#22c55e]', border: 'border-[#22c55e]/30', bg: 'bg-[#22c55e]/10' },
    B: { color: 'text-[#22c55e]', border: 'border-[#22c55e]/20', bg: 'bg-[#22c55e]/5' },
    C: { color: 'text-[#f59e0b]', border: 'border-[#f59e0b]/30', bg: 'bg-[#f59e0b]/10' },
    D: { color: 'text-[#ef4444]', border: 'border-[#ef4444]/30', bg: 'bg-[#ef4444]/10' },
    F: { color: 'text-[#ef4444]', border: 'border-[#ef4444]/50', bg: 'bg-[#ef4444]/20' }
  };

  const style = gradeMap[summary.grade] || gradeMap.C;
  gradeEl.className = `w-12 h-12 rounded-lg border flex items-center justify-center text-xl font-black transition-all duration-500 ${style.color} ${style.border} ${style.bg} shadow-[0_0_15px_rgba(34,197,94,0.05)]`;

  // Mini bars with semantic colors
  const max = Math.max(summary.total, 1);
  $('cnt-c').textContent = String(summary.bySeverity.critical);
  $('cnt-h').textContent = String(summary.bySeverity.high);
  $('cnt-m').textContent = String(summary.bySeverity.medium);
  $('cnt-l').textContent = String(summary.bySeverity.low);

  const setBar = (id: string, sev: string, val: number) => {
    const el = $(id) as HTMLElement;
    el.style.width = (val / max * 100) + '%';
    if (sev === 'critical' || sev === 'high') el.style.backgroundColor = '#ef4444';
    else if (sev === 'medium') el.style.backgroundColor = '#f59e0b';
    else el.style.backgroundColor = '#22c55e';
  };

  setBar('bar-c', 'critical', summary.bySeverity.critical);
  setBar('bar-h', 'high', summary.bySeverity.high);
  setBar('bar-m', 'medium', summary.bySeverity.medium);
  setBar('bar-l', 'low', summary.bySeverity.low);

  // Finding cards
  const list = $('findings-list');
  if (vulnerabilities.length === 0) {
    list.innerHTML = `
      <div class="text-center py-12 space-y-3 opacity-50">
        <p class="text-xs uppercase tracking-widest">No threats found</p>
      </div>
    `;
  } else {
    list.innerHTML = vulnerabilities.map((v, i) => `
      <div class="group relative bg-white/[0.03] border border-white/5 rounded-lg p-3 hover:bg-white/[0.05] transition-all duration-300 animate-slide-up" style="animation-delay: ${i * 50}ms">
        <div class="flex items-start justify-between mb-2">
          <div class="flex items-center gap-2">
            <div class="w-1.5 h-1.5 rounded-full ${getSevDot(v.severity)}"></div>
            <h4 class="text-xs font-bold truncate max-w-[160px]">${esc(v.title)}</h4>
          </div>
          <span class="text-[9px] font-mono px-1.5 py-0.5 rounded border border-white/10 bg-white/5 text-muted-foreground uppercase">${v.severity}</span>
        </div>
        
        <p class="text-[10px] text-muted-foreground leading-relaxed mb-2">${esc(v.description || 'Threat detected')}</p>
        
        <div class="flex items-center gap-2 text-[9px] text-muted-foreground/60 font-mono">
          <svg class="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"/>
          </svg>
          <span class="truncate">${esc(formatLocation(v.location as ParallaxLocation))}</span>
        </div>
      </div>
    `).join('');
  }
}

function formatLocation(loc: ParallaxLocation): string {
  if (loc.type === 'storage') return `Storage: ${loc.storageKey}`;
  if (loc.type === 'network') return `Network: ${loc.url}`;
  if (loc.type === 'header') return `Header: ${loc.url}`;
  return loc.url || 'Internal';
}

function getSevDot(s: string): string {
  if (s === 'critical' || s === 'high') return 'bg-[#ef4444] shadow-[0_0_8px_rgba(239,68,68,0.4)]';
  if (s === 'medium') return 'bg-[#f59e0b] shadow-[0_0_8px_rgba(245,158,11,0.3)]';
  return 'bg-[#22c55e] shadow-[0_0_8px_rgba(34,197,94,0.3)]';
}

function sendMsg(msg: any): Promise<any> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(msg, r => {
      if (chrome.runtime.lastError) {
        resolve({ error: chrome.runtime.lastError.message });
      } else {
        resolve(r);
      }
    });
  });
}

function esc(s: string): string {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

init();
