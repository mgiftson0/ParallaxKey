# VaultGuard Complete User Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Understanding the Interface](#understanding-the-interface)
3. [Running Scans](#running-scans)
4. [Understanding Findings](#understanding-findings)
5. [Remediation Guide](#remediation-guide)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)

---

## Getting Started

### Installation

1. **Build from source:**
   ```bash
   npm install
   npm run build
   ```

2. **Load in Chrome:**
   - Go to `chrome://extensions`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select the `dist` folder

3. **Verify installation:**
   - Look for the VaultGuard shield icon in your toolbar
   - Click it to open the popup

### First Scan

1. Navigate to any website
2. Click the VaultGuard icon
3. Click "Scan Page"
4. Wait for scan completion (usually 5-30 seconds)
5. Review the findings

---

## Understanding the Interface

### Popup Window

```
┌─────────────────────────────────────┐
│  🔒 VaultGuard        ⚙️           │
├─────────────────────────────────────┤
│  Current Page                       │
│  example.com/app                    │
├─────────────────────────────────────┤
│  [ 🛡️ Scan Page ]                  │
├─────────────────────────────────────┤
│  Security Summary                   │
│  ┌────┬────┬────┬────┐             │
│  │ 2  │ 5  │ 8  │ 3  │             │
│  │Crit│High│Med │Low │             │
│  └────┴────┴────┴────┘             │
├─────────────────────────────────────┤
│  Findings                    18     │
│  ● Stripe Secret Key Exposed        │
│  ● Missing CSP Header               │
│  ● JWT in localStorage              │
│  ...                                │
├─────────────────────────────────────┤
│  [Export]  [Clear]        v1.0.0   │
└─────────────────────────────────────┘
```

### Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| **Critical** | 🔴 Red | Immediate action required. Active exploitation possible. |
| **High** | 🟠 Orange | Serious vulnerability. Should be fixed ASAP. |
| **Medium** | 🟡 Yellow | Moderate risk. Plan remediation soon. |
| **Low** | 🔵 Blue | Minor issue. Fix when convenient. |
| **Info** | ⚪ Gray | Informational. May or may not need action. |

---

## Running Scans

### Scan Profiles

**Quick Scan** (5-10 seconds)
- Checks for critical issues only
- Best for rapid assessment

**Standard Scan** (10-30 seconds)
- Balanced coverage
- Recommended for most use cases

**Deep Scan** (30-60 seconds)
- Comprehensive analysis
- Best for security audits

### What Gets Scanned

1. **Inline Scripts** - JavaScript embedded in HTML
2. **Browser Storage** - localStorage, sessionStorage
3. **Cookies** - Security attributes and values
4. **Response Headers** - Security headers
5. **Page Content** - PII and sensitive data
6. **JWT Tokens** - Structure and claims

---

## Understanding Findings

### Finding Details

Each finding includes:

- **Title** - Brief description of the issue
- **Severity** - Risk level (Critical to Info)
- **Type** - Category of vulnerability
- **Description** - Detailed explanation
- **Evidence** - Masked proof of the issue
- **Impact** - Potential consequences
- **Remediation** - Steps to fix

### Common Finding Types

#### API Key Exposed
```
⚠️ CRITICAL: Stripe Secret Key Exposed

A Stripe secret key was found in client-side JavaScript.
This allows attackers to make charges on your account.

Evidence: sk_live_****...****Kj2m
Location: https://example.com/app.js

Remediation:
1. Revoke this key in Stripe Dashboard immediately
2. Generate a new key
3. Move API calls to your backend server
```

#### Missing Security Header
```
⚠️ HIGH: Missing Content-Security-Policy

No CSP header was found. This makes XSS attacks easier.

Remediation:
1. Add CSP header to server responses
2. Start with: default-src 'self'
3. Gradually tighten restrictions
```

#### Insecure Cookie
```
⚠️ HIGH: Cookie Missing HttpOnly Flag

The session cookie is accessible to JavaScript.

Evidence: Cookie "session" is readable via document.cookie

Remediation:
1. Set httpOnly: true when creating the cookie
2. Ensure your framework supports this flag
```

---

## Remediation Guide

### Priority Order

1. **Critical findings** - Fix immediately
2. **High findings** - Fix within 24-48 hours
3. **Medium findings** - Fix within 1-2 weeks
4. **Low findings** - Fix in next release cycle

### Common Fixes

#### Moving API Keys to Backend

**Before (Vulnerable):**
```javascript
// ❌ Never do this
const stripe = Stripe('sk_live_xxx');
```

**After (Secure):**
```javascript
// ✅ Call your backend instead
const response = await fetch('/api/create-payment', {
  method: 'POST',
  body: JSON.stringify({ amount: 1000 })
});
```

#### Adding Security Headers (Express.js)

```javascript
const helmet = require('helmet');
app.use(helmet());

// Or manually:
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
  next();
});
```

#### Secure Cookie Settings

```javascript
res.cookie('session', token, {
  httpOnly: true,  // Not accessible to JavaScript
  secure: true,    // HTTPS only
  sameSite: 'strict',  // CSRF protection
  maxAge: 3600000  // 1 hour
});
```

---

## Advanced Usage

### DevTools Panel

1. Open DevTools (F12)
2. Find "VaultGuard" tab
3. Use for detailed analysis during development

### Exporting Reports

**JSON Export:**
```json
{
  "generatedAt": "2024-01-15T10:30:00Z",
  "summary": { "critical": 2, "high": 5, ... },
  "findings": [ ... ]
}
```

**HTML Export:**
- Formatted report suitable for sharing
- Includes all finding details
- Can be printed or converted to PDF

**CSV Export:**
- Spreadsheet-compatible
- Good for tracking and metrics

---

## Troubleshooting

### Scan Not Starting

1. Refresh the page and try again
2. Check if the site uses CSP that blocks the extension
3. Try on a different page

### No Findings (Expected Some)

1. Ensure the page is fully loaded
2. Try a Deep Scan
3. Check if content is loaded dynamically

### Extension Not Loading

1. Go to `chrome://extensions`
2. Click "Reload" on VaultGuard
3. Check for errors in extension console

### High CPU/Memory Usage

1. Large pages may take longer to scan
2. Close other tabs during scan
3. Use Quick Scan for routine checks

---

## Best Practices

1. **Scan before deployment** - Run VaultGuard on staging
2. **Regular scans** - Check periodically for new issues
3. **Fix critical first** - Prioritize by severity
4. **Educate team** - Share findings and remediation steps
5. **Integrate into CI/CD** - Consider automated security testing

---

## Getting Help

- **Documentation**: Check the `docs/` folder
- **Issues**: Report bugs on GitHub
- **Updates**: Watch the repository for new features

---

*VaultGuard - Protect Your Secrets, Guard Your Vault* 🔒