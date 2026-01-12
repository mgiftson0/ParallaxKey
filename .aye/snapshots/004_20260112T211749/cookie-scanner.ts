import { BaseScanner } from '../base-scanner';
import { ScanContext, ScannerCategory } from '../../types/scanner';
import { maskSecret } from '../../utils/crypto-utils';
import { isSecureProtocol } from '../../utils/url-utils';

export class CookieScanner extends BaseScanner {
  readonly id = 'cookie-scanner';
  readonly name = 'Cookie Security Scanner';
  readonly description = 'Analyzes cookies for security issues';
  readonly category: ScannerCategory = 'storage';
  readonly version = '1.0.0';

  private sensitivePatterns = [/session/i, /token/i, /auth/i, /login/i, /jwt/i, /access/i, /refresh/i];

  protected async performScan(context: ScanContext): Promise<void> {
    const ext = context as ScanContext & { domData?: { cookies?: string } };
    if (!ext.domData?.cookies) return;

    const cookies = ext.domData.cookies.split(';').map(c => {
      const [name, ...rest] = c.trim().split('=');
      return { name: name?.trim() || '', value: rest.join('=').trim() };
    }).filter(c => c.name);

    for (const cookie of cookies) {
      if (this.isAborted()) return;
      const isSensitive = this.sensitivePatterns.some(p => p.test(cookie.name));
      if (!isSensitive) continue;

      // Note: document.cookie can't access httpOnly cookies, so if we see them they're NOT httpOnly
      this.addFinding(this.createFinding({
        type: 'insecure_cookie', severity: 'high', title: `Cookie accessible to JS: ${cookie.name}`,
        description: `Sensitive cookie "${cookie.name}" is accessible to JavaScript (not httpOnly).`,
        location: { type: 'cookie', url: context.url }, evidence: cookie.name, maskedEvidence: `${cookie.name}=${maskSecret(cookie.value)}`,
        context: 'Cookie visible to document.cookie', environment: context.environment,
        impact: { description: 'Cookie can be stolen via XSS', exploitScenario: 'XSS attack reads document.cookie', dataAtRisk: ['Session', 'Auth'] },
        remediation: { summary: 'Set httpOnly flag', steps: [{ order: 1, title: 'Add httpOnly', description: 'Set httpOnly: true when creating cookie' }], references: ['https://owasp.org/www-community/HttpOnly'], timeEstimate: '15 min', difficulty: 'easy' },
        tags: ['cookie', 'httponly']
      }));

      if (isSecureProtocol(context.url)) {
        // We can't check Secure flag from JS, but we warn about general best practices
        this.addFinding(this.createFinding({
          type: 'insecure_cookie', severity: 'info', title: `Verify Secure flag: ${cookie.name}`,
          description: `Ensure "${cookie.name}" has the Secure flag set.`,
          location: { type: 'cookie', url: context.url }, evidence: cookie.name, maskedEvidence: cookie.name,
          context: 'Review cookie security attributes', environment: context.environment,
          impact: { description: 'Without Secure flag, cookie sent over HTTP', exploitScenario: 'MITM intercepts cookie', dataAtRisk: ['Session'] },
          remediation: { summary: 'Set Secure flag', steps: [{ order: 1, title: 'Add Secure', description: 'Set secure: true' }], references: [], timeEstimate: '15 min', difficulty: 'easy' },
          tags: ['cookie', 'secure']
        }));
      }
    }
  }
}