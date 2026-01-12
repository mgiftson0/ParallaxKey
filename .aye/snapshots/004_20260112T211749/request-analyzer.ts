/**
 * VaultGuard Request Analyzer
 * Analyzes HTTP requests for security issues
 */

import { BaseScanner } from '../base-scanner';
import type { ScanContext, Vulnerability, ScannerType, NetworkRequest } from '../../types';
import { createVulnerability } from '../../core/vulnerability';
import { logger } from '../../utils/logger';
import {
  isSensitiveParam,
  looksLikeEmail,
  looksLikePhone,
  looksLikeCreditCard,
  looksLikeSSN,
  getQueryParams,
  isSecureUrl,
} from '../../utils/url-utils';
import { calculateEntropy, maskValue } from '../../utils/crypto-utils';

export class RequestAnalyzer extends BaseScanner {
  readonly id = 'request-analyzer';
  readonly name = 'Request Analyzer';
  readonly type: ScannerType = 'network';
  readonly description = 'Analyzes HTTP requests for sensitive data exposure and security issues';
  
  async scan(context: ScanContext): Promise<void> {
    logger.debug(this.id, 'Starting request analysis', { url: context.url });
    // Requests are analyzed via analyzeRequest method called by orchestrator
  }
  
  /**
   * Analyze a network request
   */
  analyzeRequest(request: NetworkRequest, context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    // Check for insecure HTTP
    if (!isSecureUrl(request.url)) {
      const vuln = createVulnerability({
        type: 'insecure_transport',
        scannerType: 'network',
        severity: 'high',
        title: 'Insecure HTTP Request',
        description: `A request is being made over HTTP instead of HTTPS: ${request.url}`,
        location: {
          type: 'network',
          url: request.url,
          requestId: request.id,
        },
        impact: {
          description: 'HTTP traffic can be intercepted and modified by attackers',
          exploitScenario: 'An attacker on the same network could intercept sensitive data or modify the response',
          dataAtRisk: ['Request data', 'Response data', 'User credentials'],
        },
        remediation: {
          steps: [
            'Use HTTPS for all requests',
            'Enable HSTS on the server',
            'Redirect HTTP to HTTPS',
          ],
          estimatedEffort: 'medium',
          references: ['https://owasp.org/www-project-web-security-testing-guide/'],
        },
        environment: context.environment,
        cweId: 'CWE-319',
        owaspCategory: 'A02:2021 - Cryptographic Failures',
      });
      
      findings.push(vuln);
      this.addVulnerability(vuln);
    }
    
    // Check URL parameters for sensitive data
    const urlFindings = this.analyzeUrlParams(request.url, request.id, context);
    findings.push(...urlFindings);
    
    // Check request headers
    const headerFindings = this.analyzeRequestHeaders(request.headers, request.url, request.id, context);
    findings.push(...headerFindings);
    
    // Check request body if present
    if (request.body) {
      const bodyFindings = this.analyzeRequestBody(request.body, request.url, request.id, context);
      findings.push(...bodyFindings);
    }
    
    this.incrementScanned();
    
    return findings;
  }
  
  /**
   * Analyze URL parameters for sensitive data
   */
  private analyzeUrlParams(
    url: string,
    requestId: string,
    context: ScanContext
  ): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const params = getQueryParams(url);
    
    for (const [name, value] of params.entries()) {
      // Check for sensitive parameter names
      if (isSensitiveParam(name)) {
        const vuln = createVulnerability({
          type: 'sensitive_data_in_url',
          scannerType: 'network',
          severity: 'high',
          title: `Sensitive Data in URL: ${name}`,
          description: `A potentially sensitive parameter "${name}" is being transmitted in the URL. URLs are logged by servers, proxies, and browsers.`,
          location: {
            type: 'url',
            url,
            requestId,
          },
          impact: {
            description: 'Sensitive data in URLs can be logged and exposed in browser history, server logs, and referrer headers',
            exploitScenario: 'An attacker with access to logs could retrieve sensitive tokens or keys',
            dataAtRisk: ['API keys', 'Tokens', 'Credentials'],
          },
          remediation: {
            steps: [
              'Move sensitive data to request headers (Authorization header)',
              'Use POST requests with data in the body',
              'Never include secrets in URLs',
            ],
            codeExample: {
              vulnerable: `fetch('/api?api_key=${maskValue(value)}')`,
              secure: `fetch('/api', {\n  headers: { 'Authorization': 'Bearer ' + apiKey }\n})`,
              language: 'javascript',
            },
            estimatedEffort: 'low',
            references: ['https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url'],
          },
          environment: context.environment,
          cweId: 'CWE-598',
          metadata: {
            paramName: name,
            maskedValue: maskValue(value),
          },
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
      
      // Check for PII in URL
      const piiType = this.detectPII(value);
      if (piiType) {
        const vuln = createVulnerability({
          type: 'pii_in_url',
          scannerType: 'network',
          severity: 'medium',
          title: `PII in URL: ${piiType}`,
          description: `Potential ${piiType} found in URL parameter "${name}"`,
          location: {
            type: 'url',
            url,
            requestId,
          },
          impact: {
            description: 'PII in URLs can be logged and may violate privacy regulations',
            exploitScenario: 'Personal information could be exposed through logs or browser history',
            dataAtRisk: [piiType],
          },
          remediation: {
            steps: [
              'Move PII to POST request body',
              'Encrypt sensitive data before transmission',
              'Minimize collection of PII',
            ],
            estimatedEffort: 'medium',
            references: ['https://owasp.org/www-project-web-security-testing-guide/'],
          },
          environment: context.environment,
          cweId: 'CWE-359',
          metadata: {
            piiType,
            paramName: name,
          },
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
      
      // Check for high-entropy values (potential secrets)
      if (value.length >= 20 && calculateEntropy(value) > 4.5) {
        const vuln = createVulnerability({
          type: 'high_entropy_url_param',
          scannerType: 'network',
          severity: 'medium',
          title: 'High-Entropy Value in URL',
          description: `A high-entropy value in parameter "${name}" may be a secret or token`,
          location: {
            type: 'url',
            url,
            requestId,
          },
          impact: {
            description: 'If this is a secret, it could be exposed through logs',
            exploitScenario: 'Tokens in URLs can be captured and reused by attackers',
            dataAtRisk: ['Tokens', 'Session identifiers'],
          },
          remediation: {
            steps: [
              'Review if this value is sensitive',
              'Move sensitive values to headers or POST body',
            ],
            estimatedEffort: 'low',
          },
          environment: context.environment,
          metadata: {
            paramName: name,
            maskedValue: maskValue(value),
          },
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
    }
    
    return findings;
  }
  
  /**
   * Analyze request headers
   */
  private analyzeRequestHeaders(
    headers: Record<string, string>,
    url: string,
    requestId: string,
    context: ScanContext
  ): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    for (const [name, value] of Object.entries(headers)) {
      const lowerName = name.toLowerCase();
      
      // Check for custom headers that might contain secrets
      if (
        (lowerName.includes('key') || lowerName.includes('token') || lowerName.includes('auth')) &&
        !['authorization', 'x-csrf-token', 'x-xsrf-token'].includes(lowerName)
      ) {
        // Log for review but don't flag as vulnerability
        // Custom auth headers are often legitimate
        logger.debug(this.id, `Custom auth header: ${name}`, { url });
      }
    }
    
    return findings;
  }
  
  /**
   * Analyze request body
   */
  private analyzeRequestBody(
    body: string,
    url: string,
    requestId: string,
    context: ScanContext
  ): Vulnerability[] {
    const findings: Vulnerability[] = [];
    
    try {
      const parsed = JSON.parse(body);
      
      // Check for sensitive fields in JSON body
      const sensitiveFields = this.findSensitiveFields(parsed);
      
      for (const field of sensitiveFields) {
        const vuln = createVulnerability({
          type: 'sensitive_field_in_request',
          scannerType: 'network',
          severity: 'info',
          title: `Sensitive Field in Request: ${field.path}`,
          description: `Request contains field "${field.path}" which may contain sensitive data`,
          location: {
            type: 'network',
            url,
            requestId,
          },
          impact: {
            description: 'Ensure sensitive data is properly protected in transit and at rest',
            exploitScenario: 'If not using HTTPS, this data could be intercepted',
            dataAtRisk: [field.path],
          },
          remediation: {
            steps: [
              'Verify HTTPS is used',
              'Ensure data is encrypted at rest on the server',
            ],
            estimatedEffort: 'low',
          },
          environment: context.environment,
        });
        
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
    } catch {
      // Not JSON, skip deep analysis
    }
    
    return findings;
  }
  
  /**
   * Detect PII in a value
   */
  private detectPII(value: string): string | null {
    if (looksLikeEmail(value)) return 'Email Address';
    if (looksLikePhone(value)) return 'Phone Number';
    if (looksLikeCreditCard(value)) return 'Credit Card Number';
    if (looksLikeSSN(value)) return 'Social Security Number';
    return null;
  }
  
  /**
   * Find sensitive fields in an object
   */
  private findSensitiveFields(
    obj: unknown,
    path: string = ''
  ): Array<{ path: string; value: unknown }> {
    const results: Array<{ path: string; value: unknown }> = [];
    
    if (typeof obj !== 'object' || obj === null) return results;
    
    const sensitivePatterns = [
      'password',
      'secret',
      'token',
      'api_key',
      'apikey',
      'credit_card',
      'creditcard',
      'ssn',
      'social_security',
    ];
    
    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;
      const lowerKey = key.toLowerCase();
      
      if (sensitivePatterns.some((p) => lowerKey.includes(p))) {
        results.push({ path: currentPath, value });
      }
      
      if (typeof value === 'object' && value !== null) {
        results.push(...this.findSensitiveFields(value, currentPath));
      }
    }
    
    return results;
  }
}