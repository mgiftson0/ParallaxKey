chrome.devtools.panels.create(
  'VaultGuard',
  'assets/icons/icon-32.png',
  'devtools/panel.html',
  (panel) => {
    console.log('VaultGuard DevTools panel created');
  }
);