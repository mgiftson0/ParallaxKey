import { Vulnerability, SecretPattern, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { createSecretExposureVulnerability } from '../../core/vulnerability';
import { maskSecret } from '../../utils/crypto';
import { logger } from '../../utils/logger';
import { SECRET_PATTERNS } from './patterns';

export class APIKeyScanner extends BaseScanner {
  readonly name = 'APIKeyScanner';
  readonly category = 'secret_exposure' as const;

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const seen = new Set<string>();

      const check = (content: string, loc: any) => {
        for (const p of SECRET_PATTERNS) {
          p.pattern.lastIndex = 0;
          let m;
          while ((m = p.pattern.exec(content)) !== null) {
            const secret = m[0];
            if (seen.has(secret) || this.isPlaceholder(secret)) continue;
            seen.add(secret);
            vulns.push(createSecretExposureVulnerability(p.name, p.service, maskSecret(secret), loc, p.severity));
            logger.debug(this.name, `Found ${p.name}`);
          }
        }
      };

      context.domAnalysis?.scripts?.forEach(s => s.content && check(s.content, { type: 'script', url: s.src || context.url } as any));
      context.domAnalysis?.localStorage?.forEach(i => check(i.value, { type: 'storage', storageKey: i.key } as any));
      context.domAnalysis?.sessionStorage?.forEach(i => check(i.value, { type: 'storage', storageKey: i.key } as any));
      context.networkRequests?.forEach(r => check(r.url, { type: 'url', url: r.url } as any));

      return vulns;
    });
  }

  private isPlaceholder(s: string): boolean {
    return ['example', 'your-key', 'xxx', 'placeholder', 'test', 'sample'].some(p => s.toLowerCase().includes(p));
  }
}
