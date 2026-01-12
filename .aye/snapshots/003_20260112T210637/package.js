const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const distPath = path.join(__dirname, '..', 'dist');
const packagePath = path.join(__dirname, '..', 'vaultguard-extension.zip');

console.log('📦 Packaging VaultGuard extension...');

// Remove old package
if (fs.existsSync(packagePath)) {
  fs.unlinkSync(packagePath);
}

// Create zip
try {
  if (process.platform === 'win32') {
    execSync(`powershell Compress-Archive -Path "${distPath}\\*" -DestinationPath "${packagePath}"`);
  } else {
    execSync(`cd "${distPath}" && zip -r "${packagePath}" .`);
  }
  console.log('✅ Package created: vaultguard-extension.zip');
} catch (error) {
  console.error('❌ Packaging failed:', error.message);
  process.exit(1);
}