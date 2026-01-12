import { ScanResult, Message } from '../types';

const $ = (id: string) => document.getElementById(id)!;
let currentTabId: number | undefined;
let currentResult: ScanResult | null = null;

async function init() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id && tab.url) {
    currentTabId = tab.id;
    ($('site-url') as HTMLElement).textContent = new URL(tab.url).hostname;
    const status = await sendMessage({ type: 'GET_STATUS', tabId: tab.id, timestamp: Date.now() });
    if (status?.status === 'complete') {
      const result = await sendMessage({ type: 'GET_RESULTS', tabId: tab.id, timestamp: Date.now() });
      if (result) { currentResult = result; showResults(result); }
    }
  }
  setupListeners();
}

function setupListeners() {
  $('btn-scan').addEventListener('click', startScan);
  $('btn-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
  $('btn-export').addEventListener('click', exportResults);
  chrome.runtime.onMessage.addListener((msg: Message) => {
    if (msg.type === 'SCAN_COMPLETE') { currentResult = msg.payload as ScanResult; showResults(currentResult); }
  });
}

async function startScan() {
  if (!currentTabId) return;
  showScanning();
  try {
    const scanType = ($('scan-type') as HTMLSelectElement).value;
    await sendMessage({ type: 'START_SCAN', tabId: currentTabId, payload: { type: scanType }, timestamp: Date.now() });
    const result = await sendMessage({ type: 'GET_RESULTS', tabId: currentTabId, timestamp: Date.now() });
    if (result) { currentResult = result; setTimeout(() => showResults(result), 300); }
    else showEmpty();
  } catch { showEmpty(); }
}

function showScanning() {
  $('empty-state').classList.add('hidden');
  $('results-section').classList.add('hidden');
  $('scanning-status').classList.remove('hidden');
  ($('btn-scan') as HTMLButtonElement).disabled = true;
}

function showResults(result: ScanResult) {
  $('scanning-status').classList.add('hidden');
  $('empty-state').classList.add('hidden');
  $('results-section').classList.remove('hidden');
  ($('btn-scan') as HTMLButtonElement).disabled = false;
  const { summary } = result;
  $('vuln-count').textContent = `${summary.total} issue${summary.total !== 1 ? 's' : ''} found`;
  $('grade-badge').textContent = summary.grade;
  $('grade-badge').className = `w-14 h-14 rounded-full flex items-center justify-center text-2xl font-bold ${getGradeClass(summary.grade)}`;
  const total = Math.max(summary.total, 1);
  $('count-critical').textContent = summary.bySeverity.critical.toString();
  $('count-high').textContent = summary.bySeverity.high.toString();
  $('count-medium').textContent = summary.bySeverity.medium.toString();
  $('count-low').textContent = summary.bySeverity.low.toString();
  ($('bar-critical') as HTMLElement).style.width = `${(summary.bySeverity.critical / total) * 100}%`;
  ($('bar-high') as HTMLElement).style.width = `${(summary.bySeverity.high / total) * 100}%`;
  ($('bar-medium') as HTMLElement).style.width = `${(summary.bySeverity.medium / total) * 100}%`;
  ($('bar-low') as HTMLElement).style.width = `${(summary.bySeverity.low / total) * 100}%`;
  const list = $('findings-list');
  list.innerHTML = result.vulnerabilities.length === 0
    ? '<div class="text-center py-4 text-green-600">No vulnerabilities found!</div>'
    : result.vulnerabilities.slice(0, 5).map(v => `<div class="p-3 bg-white rounded-lg border border-gray-200"><div class="flex items-center gap-2 mb-1"><span class="w-2 h-2 rounded-full ${getSevClass(v.severity)}"></span><span class="text-sm font-medium truncate">${v.title}</span></div><p class="text-xs text-gray-500 truncate">${v.location.url || v.location.storageKey || 'Unknown'}</p></div>`).join('');
}

function showEmpty() {
  $('scanning-status').classList.add('hidden');
  $('results-section').classList.add('hidden');
  $('empty-state').classList.remove('hidden');
  ($('btn-scan') as HTMLButtonElement).disabled = false;
}

function getGradeClass(g: string): string {
  const m: Record<string, string> = { A: 'bg-green-100 text-green-600', B: 'bg-lime-100 text-lime-600', C: 'bg-yellow-100 text-yellow-600', D: 'bg-orange-100 text-orange-600', F: 'bg-red-100 text-red-600' };
  return m[g] || 'bg-gray-100 text-gray-600';
}

function getSevClass(s: string): string {
  const m: Record<string, string> = { critical: 'bg-red-600', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-blue-500', info: 'bg-gray-400' };
  return m[s] || 'bg-gray-400';
}

async function exportResults() {
  if (!currentResult) return;
  const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = `vaultguard-${Date.now()}.json`; a.click();
  URL.revokeObjectURL(url);
}

function sendMessage(m: Message): Promise<any> { return chrome.runtime.sendMessage(m); }

init();