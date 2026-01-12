# VaultGuard Security Scanner

> 🔒 **Protect Your Secrets, Guard Your Vault**

A browser-based security scanner that detects vulnerabilities in web applications.

## Features

- 🔑 **API Key Detection** - Finds exposed secrets
- 🛡️ **Security Headers** - Checks for CSP, HSTS, etc.
- 🍪 **Cookie Analysis** - Validates cookie security
- 🎫 **JWT Analysis** - Detects token vulnerabilities
- 👤 **PII Detection** - Finds exposed personal data
- 💾 **Storage Scanning** - Checks localStorage/sessionStorage

## Installation

```bash
# Install dependencies
npm install

# Build extension
npm run build

# Load dist/ folder in chrome://extensions (Developer mode)
```

## Usage

1. Click the VaultGuard icon
2. Click "Scan Page"
3. Review findings
4. Export report if needed

## Privacy

- ✅ All processing is local
- ✅ No external data transmission
- ✅ No telemetry

## License

MIT