/**
 * VaultGuard LocalStorage Scanner
 * Scans localStorage for sensitive data
 */

import { BaseScanner } from '../base-scanner';
import type { ScanContext, Vulnerability, ScannerType, StorageItem } from '../../types';
import { createVulnerability } from '../../core/vulnerability';
import { logger } from '../../utils/logger';
import { calculateEntropy, maskValue, decodeJWT, isJWTExpired } from '../../utils/crypto-utils';
import { SECRET_PATTERNS } from '../secrets/patterns';

export class LocalStorageScanner extends BaseScanner {
  readonly id = 'local-storage-scanner';
  readonly name = 'LocalStorage Scanner';
  readonly type: ScannerType = 'storage';
  readonly description = 'Scans localStorage for sensitive data and security issues';
  
  async scan(context: ScanContext): Promise<void> {
    logger.debug(this.id, 'Starting localStorage scan', { url: context.url });
    // Storage data is analyzed via analyzeStorage method called by content script
  }
  
  /**
   * Analyze localStorage items
   */
  analyzeStorage(items: StorageItem[], context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    for (const item of items) {
      this.incrementScanned();
      
      // Check for JWT tokens
      if (this.looksLikeJWT(item.value)) {
        const jwtFindings = this.analyzeJWT(item, context);
        findings.push(...jwtFindings);
      }
      
      // Check for API keys/secrets using patterns
      const secretFindings = this.scanForSecrets(item, context);
      findings.push(...secretFindings);
      
      // Check for PII
      const piiFindings = this.scanForPII(item, context);
      findings.push(...piiFindings);
      
      // Check for sensitive key names
      if (this.isSensitiveKeyName(item.key)) {
        const vuln = createVulnerability({
          type: 'sensitive_storage_key',
          scannerType: 'storage',
          severity: 'medium',
          title: `Sensitive Data in LocalStorage: ${item.key}`,
          description: `The localStorage key "${item.key}" suggests sensitive data is being stored client-side`,
          location: {
            type: 'storage',
            storageKey: item.key,
          },
          impact: {
            description: 'Client-side storage is accessible to JavaScript and can be extracted by XSS attacks',
            exploitScenario: 'An XSS vulnerability could be used to steal this data from localStorage',
            dataAtRisk: ['Potentially sensitive data based on key name'],
          },
          remediation: {
            steps: [
              'Evaluate if this data needs to be stored client-side',
              'Consider using httpOnly cookies for sensitive tokens',
              'Implement XSS protections (CSP, input validation)',
            ],
            estimatedEffort: 'medium',
            references: [
              'https://owasp.org/www-community/attacks/xss/',
            ],
          },
          environment: context.environment,
          cweId: 'CWE-922',
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
      
      // Check for high-entropy values
      if (item.value.length >= 20 && calculateEntropy(item.value) > 4.5) {
        const vuln = createVulnerability({
          type: 'high_entropy_storage',
          scannerType: 'storage',
          severity: 'low',
          title: 'High-Entropy Value in LocalStorage',
          description: `Key "${item.key}" contains a high-entropy value that may be a secret`,
          location: {
            type: 'storage',
            storageKey: item.key,
          },
          impact: {
            description: 'If this is a secret, it could be extracted by malicious scripts',
            exploitScenario: 'XSS attacks could steal this potentially sensitive data',
            dataAtRisk: ['Potential secrets or tokens'],
          },
          remediation: {
            steps: [
              'Review if this value is sensitive',
              'Consider server-side session management',
            ],
            estimatedEffort: 'low',
          },
          environment: context.environment,
          metadata: {
            maskedValue: maskValue(item.value),
          },
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
    }
    
    return findings;
  }
  
  /**
   * Check if value looks like a JWT
   */
  private looksLikeJWT(value: string): boolean {
    return /^eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*$/.test(value);
  }
  
  /**
   * Analyze a JWT token
   */
  private analyzeJWT(item: StorageItem, context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const payload = decodeJWT(item.value);
    
    if (!payload) return findings;
    
    // Check for expired token
    if (isJWTExpired(item.value)) {
      const vuln = createVulnerability({
        type: 'expired_jwt',
        scannerType: 'storage',
        severity: 'low',
        title: 'Expired JWT in LocalStorage',
        description: `The JWT stored in "${item.key}" has expired`,
        location: {
          type: 'storage',
          storageKey: item.key,
        },
        impact: {
          description: 'Expired tokens should be cleared to prevent confusion and potential security issues',
          exploitScenario: 'An expired token might be accidentally used or could indicate session management issues',
          dataAtRisk: [],
        },
        remediation: {
          steps: [
            'Clear expired tokens from storage',
            'Implement automatic token refresh',
          ],
          estimatedEffort: 'low',
        },
        environment: context.environment,
      });
      
      findings.push(vuln);
      this.addVulnerability(vuln);
    }
    
    // Check for sensitive claims
    const sensitiveClaims = ['password', 'secret', 'credit_card', 'ssn'];
    for (const claim of Object.keys(payload)) {
      if (sensitiveClaims.some((s) => claim.toLowerCase().includes(s))) {
        const vuln = createVulnerability({
          type: 'sensitive_jwt_claim',
          scannerType: 'storage',
          severity: 'high',
          title: 'Sensitive Data in JWT',
          description: `JWT in "${item.key}" contains potentially sensitive claim: ${claim}`,
          location: {
            type: 'storage',
            storageKey: item.key,
          },
          impact: {
            description: 'JWT claims are base64 encoded and can be easily decoded',
            exploitScenario: 'Anyone with access to the token can read the sensitive data',
            dataAtRisk: [claim],
          },
          remediation: {
            steps: [
              'Remove sensitive data from JWT claims',
              'Store sensitive data server-side only',
            ],
            estimatedEffort: 'medium',
          },
          environment: context.environment,
          cweId: 'CWE-200',
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
    }
    
    // Check for service_role (Supabase specific)
    if (payload.role === 'service_role') {
      const vuln = createVulnerability({
        type: 'service_role_key_exposed',
        scannerType: 'storage',
        severity: 'critical',
        title: 'Supabase Service Role Key in Client Storage',
        description: `A Supabase service role key is stored in "${item.key}". This key bypasses Row Level Security!`,
        location: {
          type: 'storage',
          storageKey: item.key,
        },
        impact: {
          description: 'Service role keys have full database access, bypassing all RLS policies',
          exploitScenario: 'An attacker could read, modify, or delete any data in your Supabase database',
          dataAtRisk: ['All database data', 'User data', 'Application integrity'],
        },
        remediation: {
          steps: [
            'IMMEDIATELY rotate the service role key in Supabase dashboard',
            'Remove the key from client-side code',
            'Use only anon key on the client',
            'Keep service role key on server only',
          ],
          references: [
            'https://supabase.com/docs/guides/api/api-keys',
          ],
          estimatedEffort: 'high',
        },
        environment: context.environment,
        cweId: 'CWE-798',
        owaspCategory: 'A01:2021 - Broken Access Control',
      });
      
      findings.push(vuln);
      this.addVulnerability(vuln);
    }
    
    return findings;
  }
  
  /**
   * Scan for secrets in storage value
   */
  private scanForSecrets(item: StorageItem, context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    for (const pattern of SECRET_PATTERNS) {
      if (pattern.pattern.test(item.value)) {
        const vuln = createVulnerability({
          type: 'secret_in_storage',
          scannerType: 'storage',
          severity: pattern.severity,
          title: `${pattern.name} in LocalStorage`,
          description: `A ${pattern.name} for ${pattern.service} was found in localStorage key "${item.key}"`,
          location: {
            type: 'storage',
            storageKey: item.key,
          },
          impact: {
            description: `Exposed ${pattern.service} credentials can lead to unauthorized access`,
            exploitScenario: 'XSS attacks could steal this credential from localStorage',
            dataAtRisk: [`${pattern.service} account access`],
          },
          remediation: {
            steps: [
              'Remove the secret from client-side storage',
              'Rotate/revoke the exposed credential',
              'Implement proper server-side session management',
            ],
            estimatedEffort: 'medium',
          },
          environment: context.environment,
          cweId: 'CWE-922',
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
        break; // One finding per item
      }
    }
    
    return findings;
  }
  
  /**
   * Scan for PII in storage
   */
  private scanForPII(item: StorageItem, context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    // Email pattern
    const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/;
    const phonePattern = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/;
    const ssnPattern = /\d{3}-?\d{2}-?\d{4}/;
    
    const piiTypes: Array<{ pattern: RegExp; name: string }> = [
      { pattern: emailPattern, name: 'Email Address' },
      { pattern: phonePattern, name: 'Phone Number' },
      { pattern: ssnPattern, name: 'SSN' },
    ];
    
    for (const pii of piiTypes) {
      if (pii.pattern.test(item.value)) {
        const vuln = createVulnerability({
          type: 'pii_in_storage',
          scannerType: 'storage',
          severity: pii.name === 'SSN' ? 'high' : 'medium',
          title: `${pii.name} in LocalStorage`,
          description: `Potential ${pii.name} found in localStorage key "${item.key}"`,
          location: {
            type: 'storage',
            storageKey: item.key,
          },
          impact: {
            description: 'PII stored client-side is vulnerable to XSS attacks',
            exploitScenario: 'An attacker could steal personal information via XSS',
            dataAtRisk: [pii.name],
          },
          remediation: {
            steps: [
              'Evaluate if PII needs to be stored client-side',
              'Use server-side sessions for sensitive data',
              'Implement XSS protections',
            ],
            estimatedEffort: 'medium',
          },
          environment: context.environment,
          cweId: 'CWE-359',
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
    }
    
    return findings;
  }
  
  /**
   * Check if key name suggests sensitive data
   */
  private isSensitiveKeyName(key: string): boolean {
    const sensitivePatterns = [
      'password',
      'secret',
      'api_key',
      'apikey',
      'private_key',
      'privatekey',
      'credential',
      'auth_token',
      'access_token',
      'refresh_token',
    ];
    
    const lowerKey = key.toLowerCase();
    return sensitivePatterns.some((p) => lowerKey.includes(p));
  }
}