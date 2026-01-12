import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { isJWT, decodeJWT, maskSecret, base64Decode } from '../../utils/crypto';

export class JWTAnalyzer extends BaseScanner {
  readonly name = 'JWTAnalyzer';
  readonly category = 'authentication' as const;

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const seen = new Set<string>();

      const check = (token: string, loc: any) => {
        if (!isJWT(token) || seen.has(token)) return;
        seen.add(token);
        const payload = decodeJWT(token);
        if (!payload) return;

        try {
          const header = JSON.parse(base64Decode(token.split('.')[0].replace(/-/g, '+').replace(/_/g, '/')));
          if (header.alg === 'none' || header.alg === 'None') {
            vulns.push(new VulnerabilityBuilder()
              .setType('jwt_none_alg').setCategory('authentication').setSeverity('critical')
              .setTitle('JWT Using "none" Algorithm').setDescription('No cryptographic protection.')
              .setLocation(loc).setEvidence(token)
              .setImpact({ description: 'Anyone can forge tokens', exploitScenario: 'Auth bypass', dataAtRisk: ['All'], businessImpact: 'Critical' })
              .setRemediation({ steps: ['Use RS256/ES256'], references: [], priority: 'immediate', effort: 'low' })
              .addTag('jwt').build());
          }
        } catch { }

        if (!payload.exp) {
          vulns.push(new VulnerabilityBuilder()
            .setType('jwt_no_exp').setCategory('authentication').setSeverity('high')
            .setTitle('JWT Without Expiration').setDescription('Token never expires.')
            .setLocation(loc).setEvidence(token)
            .setImpact({ description: 'Stolen tokens valid forever', exploitScenario: 'Permanent access', dataAtRisk: ['Session'], businessImpact: 'High' })
            .setRemediation({ steps: ['Add exp claim'], references: [], priority: 'immediate', effort: 'medium' })
            .addTag('jwt').build());
        }
      };

      context.domAnalysis?.localStorage?.forEach(i => check(i.value, { type: 'storage', storageKey: i.key } as any));
      context.domAnalysis?.sessionStorage?.forEach(i => check(i.value, { type: 'storage', storageKey: i.key } as any));

      return vulns;
    });
  }
}
