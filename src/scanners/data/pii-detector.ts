import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { maskSecret } from '../../utils/crypto';

export class PIIDetector extends BaseScanner {
  readonly name = 'PIIDetector';
  readonly category = 'data_exposure' as const;

  private patterns = [
    { name: 'Email', pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'medium' as const },
    { name: 'SSN', pattern: /\b\d{3}-\d{2}-\d{4}\b/g, severity: 'critical' as const },
    { name: 'Credit Card', pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b/g, severity: 'critical' as const },
  ];

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const seen = new Set<string>();

      const detect = (content: string, source: string, key?: string) => {
        for (const { name, pattern, severity } of this.patterns) {
          pattern.lastIndex = 0;
          const matches = content.match(pattern);
          if (matches) {
            const unique = matches.filter(m => { const k = `${name}:${m}`; if (seen.has(k)) return false; seen.add(k); return true; });
            if (unique.length > 0) {
              vulns.push(new VulnerabilityBuilder()
                .setType('pii_exposure').setCategory('data_exposure').setSeverity(severity)
                .setTitle(`${name} Detected`).setDescription(`Found ${unique.length} ${name}(s).`)
                .setLocation({ type: source === 'response' ? 'network' : 'storage', url: source === 'response' ? key : undefined, storageKey: source !== 'response' ? key : undefined })
                .setEvidence(unique.join(', ')) // VulnerabilityBuilder masks it
                .setImpact({ description: `${name} exposed`, exploitScenario: 'Data harvesting', dataAtRisk: [name], businessImpact: 'Regulatory' })
                .setRemediation({ steps: ['Remove from client'], references: [], priority: severity === 'critical' ? 'immediate' : 'short-term', effort: 'medium' })
                .addTag('pii').build());
            }
          }
        }
      };

      context.networkResponses?.forEach(r => r.body && detect(r.body, 'response', r.url));
      context.domAnalysis?.localStorage?.forEach(i => detect(i.value, 'localStorage', i.key));
      context.domAnalysis?.sessionStorage?.forEach(i => detect(i.value, 'sessionStorage', i.key));

      return vulns;
    });
  }
}
