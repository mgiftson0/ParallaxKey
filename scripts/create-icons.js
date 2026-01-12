const fs = require('fs');
const path = require('path');

// Simple 1x1 blue pixel PNG as base64 (placeholder)
// In production, replace with actual icon files
const createPlaceholderPNG = (size) => {
  // This creates a minimal valid PNG
  // For production, use actual designed icons
  const png = Buffer.from([
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, // IHDR length
    0x49, 0x48, 0x44, 0x52, // IHDR
    0x00, 0x00, 0x00, 0x01, // width: 1
    0x00, 0x00, 0x00, 0x01, // height: 1
    0x08, 0x02,             // bit depth: 8, color type: 2 (RGB)
    0x00, 0x00, 0x00,       // compression, filter, interlace
    0x90, 0x77, 0x53, 0xDE, // CRC
    0x00, 0x00, 0x00, 0x0C, // IDAT length
    0x49, 0x44, 0x41, 0x54, // IDAT
    0x08, 0xD7, 0x63, 0x60, 0x60, 0xF8, 0x0F, 0x00, // compressed data (blue pixel)
    0x01, 0x01, 0x01, 0x00,
    0x18, 0xDD, 0x8D, 0xB4, // CRC
    0x00, 0x00, 0x00, 0x00, // IEND length
    0x49, 0x45, 0x4E, 0x44, // IEND
    0xAE, 0x42, 0x60, 0x82  // CRC
  ]);
  return png;
};

const iconsDir = path.join(__dirname, '..', 'src', 'assets', 'icons');

if (!fs.existsSync(iconsDir)) {
  fs.mkdirSync(iconsDir, { recursive: true });
}

[16, 32, 48, 128].forEach(size => {
  const iconPath = path.join(iconsDir, `icon-${size}.png`);
  if (!fs.existsSync(iconPath)) {
    fs.writeFileSync(iconPath, createPlaceholderPNG(size));
    console.log(`Created placeholder: icon-${size}.png`);
  }
});

console.log('Icons ready!');