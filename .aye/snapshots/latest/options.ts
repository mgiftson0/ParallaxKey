// VaultGuard Options Page

async function init() {
  const historyEl = document.getElementById('history')!;
  
  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_HISTORY' });
    const history = response || [];
    
    if (history.length === 0) {
      historyEl.innerHTML = '<p class="text-gray-500">No scan history yet.</p>';
    } else {
      historyEl.innerHTML = history.slice(0, 20).map((scan: any) => `
        <div class="p-3 bg-gray-50 rounded-lg">
          <div class="flex justify-between items-start">
            <div>
              <p class="font-medium truncate" style="max-width: 300px">${escapeHtml(scan.url)}</p>
              <p class="text-xs text-gray-500">${new Date(scan.timestamp).toLocaleString()}</p>
            </div>
            <span class="px-2 py-1 text-xs font-medium rounded ${getGradeClass(scan.summary?.grade || 'A')}">
              ${scan.summary?.total || 0} issues
            </span>
          </div>
        </div>
      `).join('');
    }
  } catch (e) {
    console.error('Failed to load history:', e);
    historyEl.innerHTML = '<p class="text-red-500">Failed to load history.</p>';
  }
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function getGradeClass(grade: string): string {
  const classes: Record<string, string> = {
    'A': 'bg-green-100 text-green-700',
    'B': 'bg-lime-100 text-lime-700',
    'C': 'bg-yellow-100 text-yellow-700',
    'D': 'bg-orange-100 text-orange-700',
    'F': 'bg-red-100 text-red-700'
  };
  return classes[grade] || 'bg-gray-100 text-gray-700';
}

init();