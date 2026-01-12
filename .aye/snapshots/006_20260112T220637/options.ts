import { Settings } from '../types';
const $ = (id: string) => document.getElementById(id)!;

async function init() {
  const settings = await chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }) as Settings;
  ($('auto-scan') as HTMLInputElement).checked = settings.general.autoScan;
  ($('show-badge') as HTMLInputElement).checked = settings.general.showBadge;
  ($('default-scan-type') as HTMLSelectElement).value = settings.scanning.defaultScanType;
  $('btn-save').addEventListener('click', saveSettings);
}

async function saveSettings() {
  const settings: Settings = {
    general: { autoScan: ($('auto-scan') as HTMLInputElement).checked, scanOnNavigation: false, showBadge: ($('show-badge') as HTMLInputElement).checked, debugMode: false },
    scanning: { defaultScanType: ($('default-scan-type') as HTMLSelectElement).value as any, enabledCategories: ['secret_exposure', 'network_security', 'storage_security', 'authentication', 'data_exposure', 'misconfiguration'], customPatterns: [], whitelistedDomains: [], blacklistedDomains: [], maxConcurrentScans: 3, scanTimeout: 300000 },
    notifications: { enabled: true, minSeverity: 'medium', sound: false, desktop: true },
    privacy: { collectAnonymousStats: false, sharePatterns: false, localStorageOnly: true },
    appearance: { theme: 'system', compactMode: false, showConfidenceScores: true },
  };
  await chrome.runtime.sendMessage({ type: 'UPDATE_SETTINGS', payload: settings });
  alert('Settings saved!');
}

init();