const fs = require('fs');
const path = require('path');

function copyFile(src, dest) {
  const destDir = path.dirname(dest);
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
  if (fs.existsSync(src)) { fs.copyFileSync(src, dest); console.log(`Copied: ${src} -> ${dest}`); }
}

function copyDir(src, dest) {
  if (!fs.existsSync(src)) return;
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  fs.readdirSync(src, { withFileTypes: true }).forEach(entry => {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    entry.isDirectory() ? copyDir(srcPath, destPath) : fs.copyFileSync(srcPath, destPath);
  });
  console.log(`Copied directory: ${src} -> ${dest}`);
}

if (!fs.existsSync('dist')) fs.mkdirSync('dist', { recursive: true });

copyFile('manifest.json', 'dist/manifest.json');
[['src/popup/popup.html', 'dist/popup/popup.html'], ['src/options/options.html', 'dist/options/options.html'], ['src/devtools/devtools.html', 'dist/devtools/devtools.html'], ['src/devtools/panel.html', 'dist/devtools/panel.html']].forEach(([s, d]) => copyFile(s, d));
copyDir('src/assets', 'dist/assets');

console.log('Asset copy complete!');