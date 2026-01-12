import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { isHTTPS } from '../../utils/url';

export class CookieScanner extends BaseScanner {
  readonly name = 'CookieScanner';
  readonly category = 'storage_security' as const;

  private sensitive = [/session/i, /token/i, /auth/i, /login/i];

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const responses = context.networkResponses || [];
      const isSecure = isHTTPS(context.url);

      const cookies = context.domAnalysis?.cookies || [];
      for (const cookie of cookies) {
        const isSens = this.sensitive.some(p => p.test(cookie.name));

        if (isSecure && !cookie.secure && isSens) {
          vulns.push(new VulnerabilityBuilder()
            .setType('cookie_no_secure').setCategory('storage_security').setSeverity('high')
            .setTitle('Cookie Missing Secure Flag').setDescription(`Cookie "${cookie.name}" lacks Secure.`)
            .setLocation({ type: 'cookie', storageKey: cookie.name }).setEvidence(`${cookie.name} (Secure: false)`)
            .setImpact({ description: 'Cookie sent over HTTP', exploitScenario: 'MITM', dataAtRisk: ['Session'], businessImpact: 'High' })
            .setRemediation({ steps: ['Add Secure flag'], references: [], priority: 'immediate', effort: 'low' })
            .addTag('cookie').build());
        }

        if (!cookie.httpOnly && isSens) {
          vulns.push(new VulnerabilityBuilder()
            .setType('cookie_no_httponly').setCategory('storage_security').setSeverity('high')
            .setTitle('Cookie Missing HttpOnly').setDescription(`Cookie "${cookie.name}" accessible to JS.`)
            .setLocation({ type: 'cookie', storageKey: cookie.name }).setEvidence(`${cookie.name} (HttpOnly: false)`)
            .setImpact({ description: 'XSS can steal cookie', exploitScenario: 'XSS theft', dataAtRisk: ['Session'], businessImpact: 'High' })
            .setRemediation({ steps: ['Add HttpOnly flag'], references: [], priority: 'immediate', effort: 'low' })
            .addTag('cookie').build());
        }
      }
      return vulns;
    });
  }
}
