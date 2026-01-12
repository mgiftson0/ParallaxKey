# VaultGuard Security Scanner

> 🔒 **Protect Your Secrets, Guard Your Vault**

VaultGuard is a comprehensive browser-based security analysis tool designed to help developers, security teams, and organizations identify vulnerabilities in web applications.

## Features

- 🔑 **API Key & Secrets Detection** - Detect exposed API keys, tokens, and credentials
- 🛡️ **Security Headers Analysis** - Check for missing or misconfigured security headers
- 🍪 **Cookie Security** - Analyze cookie security attributes
- 🎫 **JWT Analysis** - Detect JWT vulnerabilities and misconfigurations  
- 👤 **PII Detection** - Find exposed personal information
- 💾 **Storage Scanning** - Check localStorage/sessionStorage for sensitive data
- 📊 **Comprehensive Reports** - Export reports in JSON, CSV, HTML, or Markdown

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/vaultguard.git
cd vaultguard

# Install dependencies
npm install

# Build the extension
npm run build
```

### Load in Chrome

1. Open Chrome and navigate to `chrome://extensions`
2. Enable "Developer mode" (toggle in top right)
3. Click "Load unpacked"
4. Select the `dist` folder from the project

## Usage

### Quick Scan

1. Click the VaultGuard icon in your browser toolbar
2. Click "Scan Page"
3. Review findings in the popup

### DevTools Integration

1. Open DevTools (F12)
2. Navigate to the "VaultGuard" panel
3. Click "Scan Page" for detailed analysis

### Export Reports

1. Complete a scan
2. Click "Export" in the popup
3. Choose your preferred format

## Configuration

Access settings via the gear icon in the popup or `chrome://extensions` → VaultGuard → Options.

### Available Settings

- **Theme**: Light, Dark, or System
- **Auto-scan**: Automatically scan on navigation
- **Notifications**: Configure alert preferences
- **Retention**: How long to keep finding history

## Scanners

| Scanner | Description | Severity Range |
|---------|-------------|----------------|
| API Key Scanner | Detects exposed API keys and secrets | Critical - Medium |
| Header Scanner | Checks security headers | High - Info |
| Storage Scanner | Scans browser storage | Critical - Low |
| Cookie Scanner | Analyzes cookie security | High - Info |
| JWT Analyzer | Checks JWT vulnerabilities | Critical - Medium |
| PII Detector | Finds personal information | Critical - Medium |

## Development

```bash
# Start development mode with hot reload
npm run dev

# Run tests
npm test

# Lint code
npm run lint

# Format code
npm run format
```

## Privacy

**VaultGuard is privacy-first:**

- ✅ All processing happens locally in your browser
- ✅ No data is sent to external servers
- ✅ No telemetry or analytics
- ✅ Findings stored only on your device

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## Support

- 📖 [Documentation](docs/)
- 🐛 [Report Issues](https://github.com/your-org/vaultguard/issues)
- 💬 [Discussions](https://github.com/your-org/vaultguard/discussions)