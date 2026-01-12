import { Vulnerability, Severity, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { createMissingHeaderVulnerability } from '../../core/vulnerability';

export class HeaderSecurityScanner extends BaseScanner {
  readonly name = 'HeaderSecurityScanner';
  readonly category = 'misconfiguration' as const;

  private rules = [
    { name: 'Strict-Transport-Security', severity: 'high' as Severity },
    { name: 'Content-Security-Policy', severity: 'high' as Severity },
    { name: 'X-Frame-Options', severity: 'medium' as Severity },
    { name: 'X-Content-Type-Options', severity: 'medium' as Severity },
  ];

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const responses = context.networkResponses || [];
      if (!responses.length) return vulns;

      const checked = new Set<string>();
      for (const resp of responses) {
        if (checked.has(resp.url)) continue;
        checked.add(resp.url);
        const headers: Record<string, string> = {};
        Object.entries(resp.headers).forEach(([k, v]) => { headers[k.toLowerCase()] = v; });
        for (const rule of this.rules) {
          if (!headers[rule.name.toLowerCase()]) {
            vulns.push(createMissingHeaderVulnerability(rule.name, resp.url, rule.severity));
          }
        }
      }
      return vulns;
    });
  }
}