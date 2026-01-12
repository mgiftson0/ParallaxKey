const fs = require('fs');
const path = require('path');

const stylesDir = path.join(__dirname, '..', 'src', 'styles');
const outputFile = path.join(stylesDir, 'output.css');

// Ensure styles directory exists
if (!fs.existsSync(stylesDir)) {
  fs.mkdirSync(stylesDir, { recursive: true });
}

// Create placeholder if output.css doesn't exist
if (!fs.existsSync(outputFile)) {
  fs.writeFileSync(outputFile, '/* Placeholder - will be replaced by Tailwind */');
}

console.log('CSS build preparation complete');