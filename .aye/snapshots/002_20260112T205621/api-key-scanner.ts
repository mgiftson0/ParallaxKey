/**
 * VaultGuard API Key Scanner
 * Detects exposed API keys, access tokens, and secrets
 */

import { BaseScanner } from '../base-scanner';
import type { ScanContext, Vulnerability, SecretFinding, ScannerType } from '../../types';
import { createVulnerability } from '../../core/vulnerability';
import { maskValue } from '../../utils/crypto-utils';
import { SECRET_PATTERNS } from './patterns';
import { analyzeEntropy, isLikelyFalsePositive, calculateConfidence } from './entropy-analyzer';
import { logger } from '../../utils/logger';

export class APIKeyScanner extends BaseScanner {
  readonly id = 'api-key-scanner';
  readonly name = 'API Key Scanner';
  readonly type: ScannerType = 'secrets';
  readonly description = 'Detects exposed API keys, tokens, and secrets in client-side code';
  
  async scan(context: ScanContext): Promise<void> {
    logger.debug(this.id, 'Starting API key scan', { url: context.url });
    
    // We'll receive data from content script via messages
    // For now, this scanner is triggered with data from the orchestrator
    // The actual scanning logic is here
  }
  
  /**
   * Scan text content for secrets
   */
  scanText(text: string, source: string, context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    // Pattern-based detection
    for (const pattern of SECRET_PATTERNS) {
      const matches = text.matchAll(pattern.pattern);
      
      for (const match of matches) {
        const value = match[0];
        const surroundingContext = this.extractContext(text, match.index ?? 0);
        
        // Check context requirements
        if (!this.matchesContext(pattern, surroundingContext)) {
          continue;
        }
        
        // False positive check
        if (isLikelyFalsePositive(value, surroundingContext)) {
          logger.debug(this.id, 'Filtered false positive', { pattern: pattern.name });
          continue;
        }
        
        const vulnerability = this.createSecretFinding(
          pattern.name,
          pattern.service,
          value,
          pattern.severity,
          source,
          match.index ?? 0,
          surroundingContext,
          context
        );
        
        findings.push(vulnerability);
        this.addVulnerability(vulnerability);
      }
    }
    
    // Entropy-based detection for unknown patterns
    const entropyFindings = this.scanWithEntropy(text, source, context);
    findings.push(...entropyFindings);
    
    this.incrementScanned();
    
    return findings;
  }
  
  /**
   * Scan using entropy analysis
   */
  private scanWithEntropy(
    text: string,
    source: string,
    context: ScanContext
  ): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    // Look for assignment patterns with high-entropy values
    const assignmentPattern = /(?:const|let|var|=|:)\s*['"]?([A-Za-z0-9_-]{20,})['"]?/g;
    let match;
    
    while ((match = assignmentPattern.exec(text)) !== null) {
      const value = match[1];
      if (!value) continue;
      
      const entropyResult = analyzeEntropy(value);
      
      if (entropyResult.isPotentialSecret) {
        const surroundingContext = this.extractContext(text, match.index);
        const confidence = calculateConfidence(entropyResult, surroundingContext);
        
        // Only report high-confidence entropy findings
        if (confidence >= 0.6) {
          const vulnerability = createVulnerability({
            type: 'high_entropy_secret',
            scannerType: 'secrets',
            severity: 'medium',
            title: 'Potential Secret Detected (High Entropy)',
            description: `A high-entropy string was detected that may be a secret or API key. Entropy: ${entropyResult.entropy.toFixed(2)}`,
            location: {
              type: 'script',
              url: source,
            },
            impact: {
              description: 'If this is a secret, it could be extracted by attackers',
              exploitScenario: 'An attacker could extract this value from client-side code',
              dataAtRisk: ['API access', 'Authentication credentials'],
            },
            remediation: {
              steps: [
                'Verify if this value is a secret or sensitive data',
                'If it is a secret, move it to server-side environment variables',
                'Rotate the secret if it has been exposed',
              ],
              references: [
                'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
              ],
              estimatedEffort: 'low',
            },
            environment: context.environment,
            metadata: {
              maskedValue: maskValue(value),
              entropy: entropyResult.entropy,
              confidence,
              stringType: entropyResult.type,
            },
          });
          
          findings.push(vulnerability);
          this.addVulnerability(vulnerability);
        }
      }
    }
    
    return findings;
  }
  
  /**
   * Extract surrounding context for a match
   */
  private extractContext(text: string, index: number, contextSize: number = 100): string {
    const start = Math.max(0, index - contextSize);
    const end = Math.min(text.length, index + contextSize);
    return text.slice(start, end);
  }
  
  /**
   * Check if match satisfies pattern context requirements
   */
  private matchesContext(
    pattern: (typeof SECRET_PATTERNS)[number],
    context: string
  ): boolean {
    const lowerContext = context.toLowerCase();
    
    // Check mustInclude requirements
    if (pattern.context.mustInclude) {
      const hasRequired = pattern.context.mustInclude.some((term) =>
        lowerContext.includes(term.toLowerCase())
      );
      if (!hasRequired) return false;
    }
    
    // Check mustExclude requirements
    if (pattern.context.mustExclude) {
      const hasExcluded = pattern.context.mustExclude.some((term) =>
        lowerContext.includes(term.toLowerCase())
      );
      if (hasExcluded) return false;
    }
    
    return true;
  }
  
  /**
   * Create a secret finding vulnerability
   */
  private createSecretFinding(
    patternName: string,
    service: string,
    value: string,
    severity: Vulnerability['severity'],
    source: string,
    position: number,
    context: string,
    scanContext: ScanContext
  ): Vulnerability {
    return createVulnerability({
      type: 'secret_exposure',
      scannerType: 'secrets',
      severity,
      title: `Exposed ${patternName}`,
      description: `A ${patternName} for ${service} was found exposed in client-side code. This could allow unauthorized access to the ${service} service.`,
      location: {
        type: 'script',
        url: source,
        column: position,
      },
      impact: {
        description: `Exposure of ${service} credentials can lead to unauthorized access`,
        exploitScenario: `An attacker could extract this ${patternName} from the client-side code and use it to access ${service} resources`,
        dataAtRisk: [`${service} account access`, 'Associated data and resources'],
      },
      remediation: {
        steps: [
          `Immediately rotate/revoke the exposed ${patternName}`,
          'Move the secret to server-side environment variables',
          'Use a secrets management solution',
          'Implement proper access controls on the server',
        ],
        codeExample: {
          vulnerable: `const apiKey = "${maskValue(value)}"; // Exposed in client code`,
          secure: `// Server-side only\nconst apiKey = process.env.${service.toUpperCase()}_API_KEY;`,
          language: 'javascript',
        },
        references: [
          'https://owasp.org/Top10/A01_2021-Broken_Access_Control/',
          `https://${service.toLowerCase()}.com/docs/security`,
        ],
        estimatedEffort: 'medium',
      },
      environment: scanContext.environment,
      cweId: 'CWE-798',
      owaspCategory: 'A01:2021 - Broken Access Control',
      metadata: {
        service,
        patternName,
        maskedValue: maskValue(value),
        contextSnippet: context.slice(0, 200),
      },
    });
  }
}