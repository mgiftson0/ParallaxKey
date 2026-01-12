import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { calculateEntropy, maskSecret } from '../../utils/crypto';

export class EntropyAnalyzer extends BaseScanner {
  readonly name = 'EntropyAnalyzer';
  readonly category = 'secret_exposure' as const;

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const seen = new Set<string>();
      const pattern = /["'`]([A-Za-z0-9+/=_-]{20,})["'`]/g;

      const analyze = (content: string, source: string) => {
        pattern.lastIndex = 0;
        let m;
        while ((m = pattern.exec(content)) !== null) {
          const candidate = m[1];
          if (!candidate || seen.has(candidate) || candidate.length < 20 || candidate.length > 500) continue;
          seen.add(candidate);
          const entropy = calculateEntropy(candidate);
          if (entropy >= 4.5) {
            vulns.push(new VulnerabilityBuilder()
              .setType('high_entropy_string').setCategory('secret_exposure')
              .setSeverity(entropy >= 5.5 ? 'high' : 'medium')
              .setTitle('High-Entropy String Detected')
              .setDescription(`String with entropy ${entropy.toFixed(2)} may be a secret.`)
              .setLocation({ type: 'script', url: source })
              .setContext(`Entropy: ${entropy.toFixed(2)}`)
              .setEvidence(candidate) // VulnerabilityBuilder masks it
              .setImpact({ description: 'Potential secret', exploitScenario: 'Decode and use', dataAtRisk: ['Unknown'], businessImpact: 'Unknown' })
              .setRemediation({ steps: ['Investigate string'], references: [], priority: 'short-term', effort: 'low' })
              .addTag('entropy').build());
          }
        }
      };

      context.domAnalysis?.scripts?.forEach(s => s.content && analyze(s.content, s.src || context.url));
      context.domAnalysis?.localStorage?.forEach(i => analyze(i.value, `localStorage:${i.key}`));
      context.domAnalysis?.sessionStorage?.forEach(i => analyze(i.value, `sessionStorage:${i.key}`));

      return vulns;
    });
  }
}
