import { ScanResult } from '../types';
const $ = (id: string) => document.getElementById(id)!;

async function init() {
  const tabId = chrome.devtools.inspectedWindow.tabId;
  const result = await chrome.runtime.sendMessage({ type: 'GET_RESULTS', tabId });
  if (result) renderResults(result);
  $('btn-scan').addEventListener('click', async () => {
    ($('btn-scan') as HTMLButtonElement).disabled = true;
    $('btn-scan').textContent = 'Scanning...';
    await chrome.runtime.sendMessage({ type: 'START_SCAN', tabId });
    const res = await chrome.runtime.sendMessage({ type: 'GET_RESULTS', tabId });
    if (res) renderResults(res);
    ($('btn-scan') as HTMLButtonElement).disabled = false;
    $('btn-scan').textContent = 'Scan';
  });
}

function renderResults(result: ScanResult) {
  const { summary, vulnerabilities } = result;
  $('stat-critical').textContent = summary.bySeverity.critical.toString();
  $('stat-high').textContent = summary.bySeverity.high.toString();
  $('stat-medium').textContent = summary.bySeverity.medium.toString();
  $('stat-low').textContent = summary.bySeverity.low.toString();
  $('stat-info').textContent = summary.bySeverity.info.toString();
  $('vuln-list').innerHTML = vulnerabilities.length === 0
    ? '<p class="text-green-500">No vulnerabilities found!</p>'
    : vulnerabilities.map(v => `<div class="p-3 bg-gray-800 rounded-lg"><div class="flex items-center gap-2 mb-1"><span class="w-2 h-2 rounded-full" style="background:${getSevColor(v.severity)}"></span><span class="font-medium">${v.title}</span></div><p class="text-xs text-gray-400">${v.description}</p></div>`).join('');
}

function getSevColor(s: string): string {
  const m: Record<string, string> = { critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#2563eb', info: '#6b7280' };
  return m[s] || '#6b7280';
}

init();