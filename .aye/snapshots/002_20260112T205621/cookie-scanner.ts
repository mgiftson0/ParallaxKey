/**
 * VaultGuard Cookie Scanner
 * Analyzes cookies for security issues
 */

import { BaseScanner } from '../base-scanner';
import type { ScanContext, Vulnerability, ScannerType, CookieAnalysis } from '../../types';
import { createVulnerability } from '../../core/vulnerability';
import { logger } from '../../utils/logger';

export class CookieScanner extends BaseScanner {
  readonly id = 'cookie-scanner';
  readonly name = 'Cookie Scanner';
  readonly type: ScannerType = 'storage';
  readonly description = 'Analyzes cookies for security best practices';
  
  async scan(context: ScanContext): Promise<void> {
    logger.debug(this.id, 'Starting cookie scan', { url: context.url });
    // Cookies are analyzed via analyzeCookies method
  }
  
  /**
   * Parse and analyze cookies
   */
  analyzeCookies(cookieString: string, context: ScanContext): Vulnerability[] {
    const findings: Vulnerability[] = [];
    const cookies = this.parseCookies(cookieString);
    
    for (const cookie of cookies) {
      this.incrementScanned();
      const analysis = this.analyzeCookie(cookie.name, cookie.value, context);
      
      for (const issue of analysis.issues) {
        const vuln = this.createCookieVulnerability(analysis, issue, context);
        findings.push(vuln);
        this.addVulnerability(vuln);
      }
    }
    
    return findings;
  }
  
  /**
   * Parse cookie string into individual cookies
   */
  private parseCookies(cookieString: string): Array<{ name: string; value: string }> {
    if (!cookieString) return [];
    
    return cookieString.split(';').map((cookie) => {
      const [name = '', ...valueParts] = cookie.trim().split('=');
      return {
        name: name.trim(),
        value: valueParts.join('=').trim(),
      };
    }).filter(c => c.name);
  }
  
  /**
   * Analyze a single cookie
   */
  private analyzeCookie(
    name: string,
    value: string,
    context: ScanContext
  ): CookieAnalysis {
    const issues: string[] = [];
    
    // Note: From JavaScript, we can only see cookie names and values
    // We cannot see the flags (HttpOnly, Secure, SameSite) directly
    // Those would need to be checked via Set-Cookie headers
    
    // Check for session-like cookies stored without HttpOnly (if accessible, they're not HttpOnly)
    const sessionPatterns = [
      'session',
      'sid',
      'auth',
      'token',
      'jwt',
      'access',
      'refresh',
    ];
    
    const lowerName = name.toLowerCase();
    const isSessionCookie = sessionPatterns.some((p) => lowerName.includes(p));
    
    if (isSessionCookie) {
      // If we can read it from JavaScript, it's not HttpOnly
      issues.push('Session cookie accessible to JavaScript (missing HttpOnly flag)');
    }
    
    // Check for potentially sensitive data in cookies
    const sensitivePatterns = ['password', 'credit', 'ssn', 'secret'];
    if (sensitivePatterns.some((p) => lowerName.includes(p))) {
      issues.push('Cookie name suggests sensitive data storage');
    }
    
    // Check for JWT in cookie
    if (/^eyJ[A-Za-z0-9_-]*\.eyJ/.test(value)) {
      issues.push('JWT token stored in cookie - verify HttpOnly and Secure flags via headers');
    }
    
    // Check for very long cookie values (potential data leakage)
    if (value.length > 4096) {
      issues.push('Cookie value exceeds recommended size');
    }
    
    return {
      name,
      value,
      domain: context.origin,
      path: '/',
      secure: false, // Can't determine from JS
      httpOnly: false, // If we can read it, it's not httpOnly
      sameSite: undefined,
      issues,
    };
  }
  
  /**
   * Create vulnerability from cookie analysis
   */
  private createCookieVulnerability(
    analysis: CookieAnalysis,
    issue: string,
    context: ScanContext
  ): Vulnerability {
    let severity: Vulnerability['severity'] = 'low';
    let cweId = 'CWE-614';
    
    if (issue.includes('HttpOnly')) {
      severity = 'medium';
      cweId = 'CWE-1004';
    } else if (issue.includes('sensitive')) {
      severity = 'high';
      cweId = 'CWE-315';
    }
    
    return createVulnerability({
      type: 'insecure_cookie',
      scannerType: 'storage',
      severity,
      title: `Cookie Security Issue: ${analysis.name}`,
      description: `${issue}. Cookie: ${analysis.name}`,
      location: {
        type: 'cookie',
        storageKey: analysis.name,
      },
      impact: {
        description: 'Insecure cookie configuration can lead to session hijacking or data theft',
        exploitScenario: 'XSS attacks could steal cookies without HttpOnly flag; MITM could intercept cookies without Secure flag',
        dataAtRisk: ['Session tokens', 'Authentication state'],
      },
      remediation: {
        steps: [
          'Set HttpOnly flag on session cookies',
          'Set Secure flag on all cookies',
          "Set SameSite to 'Strict' or 'Lax'",
          'Review what data is stored in cookies',
        ],
        codeExample: {
          vulnerable: `Set-Cookie: ${analysis.name}=value`,
          secure: `Set-Cookie: ${analysis.name}=value; HttpOnly; Secure; SameSite=Strict`,
          language: 'http',
        },
        references: [
          'https://owasp.org/www-community/controls/SecureCookieAttribute',
        ],
        estimatedEffort: 'low',
      },
      environment: context.environment,
      cweId,
    });
  }
}