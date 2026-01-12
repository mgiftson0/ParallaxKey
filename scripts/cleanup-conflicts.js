const fs = require('fs');
const path = require('path');

// Files to delete (conflicting duplicates)
const filesToDelete = [
  'src/background/scanner-orchestrator.ts',
  'src/background/message-router.ts',
  'src/background/network-interceptor.ts',
  'src/background/storage-manager.ts',
  'src/background/tab-manager.ts',
  'src/scanners/network/header-scanner.ts',
  'src/scanners/network/request-analyzer.ts',
  'src/scanners/authentication/jwt-analyzer.ts',
  'src/scanners/data-exposure/pii-detector.ts',
  'src/scanners/headers/header-scanner.ts',
  'src/scanners/storage/cookie-scanner.ts',
  'src/scanners/storage/local-storage-scanner.ts',
  'src/content/storage-scanner.ts',
  'src/types/scanner.ts',
  'src/utils/url-utils.ts',
  'src/utils/crypto-utils.ts',
  'src/scanners/secrets/patterns.ts',
];

// Directories to delete
const dirsToDelete = [
  'src/scanners/network',
  'src/scanners/authentication', 
  'src/scanners/data-exposure',
  'src/scanners/headers',
];

function deleteFile(filePath) {
  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
    console.log(`Deleted: ${filePath}`);
  }
}

function deleteDir(dirPath) {
  if (fs.existsSync(dirPath)) {
    fs.rmSync(dirPath, { recursive: true, force: true });
    console.log(`Deleted directory: ${dirPath}`);
  }
}

console.log('Cleaning up conflicting files...\n');

// Delete files first
filesToDelete.forEach(deleteFile);

// Then delete directories
dirsToDelete.forEach(deleteDir);

console.log('\nCleanup complete! Now run: npm run build');