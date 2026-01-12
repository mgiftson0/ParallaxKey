const fs = require('fs');
const path = require('path');

function copyFile(src, dest) {
  const dir = path.dirname(dest);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
    console.log('Copied:', src, '->', dest);
  } else {
    console.warn('Missing:', src);
  }
}

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  fs.readdirSync(src, { withFileTypes: true }).forEach(entry => {
    const s = path.join(src, entry.name);
    const d = path.join(dest, entry.name);
    entry.isDirectory() ? copyDir(s, d) : fs.copyFileSync(s, d);
  });
  console.log('Copied dir:', src);
}

copyFile('manifest.json', 'dist/manifest.json');
copyFile('src/popup/popup.html', 'dist/popup/popup.html');
copyFile('src/options/options.html', 'dist/options/options.html');
copyDir('src/assets', 'dist/assets');

console.log('Copy complete!');