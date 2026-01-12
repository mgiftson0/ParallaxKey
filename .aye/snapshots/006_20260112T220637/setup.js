const fs = require('fs');
const path = require('path');

const dirs = ['dist', 'dist/background', 'dist/content', 'dist/popup', 'dist/options', 'dist/devtools', 'dist/styles', 'dist/assets', 'dist/assets/icons', 'src/assets', 'src/assets/icons'];
dirs.forEach(dir => { if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); console.log(`Created: ${dir}`); } });

[16, 32, 48, 128].forEach(size => {
  const iconPath = `src/assets/icons/icon-${size}.png`;
  if (!fs.existsSync(iconPath)) {
    fs.writeFileSync(iconPath, Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==', 'base64'));
    console.log(`Created placeholder: ${iconPath}`);
  }
});

console.log('Setup complete!');