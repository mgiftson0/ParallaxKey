const fs = require('fs');
const path = require('path');

const dirs = [
  'dist',
  'dist/background',
  'dist/content', 
  'dist/popup',
  'dist/options',
  'dist/styles',
  'dist/assets/icons',
  'src/assets/icons'
];

dirs.forEach(dir => {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
    console.log('Created:', dir);
  }
});

// Create placeholder icons
[16, 32, 48, 128].forEach(size => {
  const iconPath = `src/assets/icons/icon-${size}.png`;
  if (!fs.existsSync(iconPath)) {
    // 1x1 blue pixel PNG
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPj/HwADBwIAMCbHYQAAAABJRU5ErkJggg==', 'base64');
    fs.writeFileSync(iconPath, png);
    console.log('Created:', iconPath);
  }
});

console.log('Setup complete!');