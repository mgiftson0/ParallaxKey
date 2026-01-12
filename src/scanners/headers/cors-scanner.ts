import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { hasSensitiveParams, isHTTPS, isLocalURL } from '../../utils/url';
import { maskSecret } from '../../utils/crypto';

export class CORSScanner extends BaseScanner {
  readonly name = 'CORSScanner';
  readonly category = 'misconfiguration' as const;

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

        const origin = headers['access-control-allow-origin'];
        const creds = headers['access-control-allow-credentials'];

        if (origin === '*' && creds?.toLowerCase() === 'true') {
          vulns.push(new VulnerabilityBuilder()
            .setType('cors_wildcard_credentials').setCategory('misconfiguration').setSeverity('critical')
            .setTitle('CORS Wildcard with Credentials')
            .setDescription('Dangerous CORS misconfiguration.')
            .setLocation({ type: 'header', url: resp.url })
            .setEvidence('Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true')
            .setImpact({ description: 'Any site can make authenticated requests', exploitScenario: 'Data theft', dataAtRisk: ['All'], businessImpact: 'Critical' })
            .setRemediation({ steps: ['Never use wildcard with credentials'], references: [], priority: 'immediate', effort: 'low' })
            .addTag('cors').build());
        } else if (origin === '*') {
          vulns.push(new VulnerabilityBuilder()
            .setType('cors_wildcard').setCategory('misconfiguration').setSeverity('medium')
            .setTitle('CORS Wildcard Origin')
            .setDescription('Server allows any origin.')
            .setLocation({ type: 'header', url: resp.url })
            .setEvidence('Access-Control-Allow-Origin: *')
            .setImpact({ description: 'Any site can read responses', exploitScenario: 'Data exposure', dataAtRisk: ['API data'], businessImpact: 'Medium' })
            .setRemediation({ steps: ['Whitelist specific origins'], references: [], priority: 'short-term', effort: 'low' })
            .addTag('cors').build());
        }
      }
      return vulns;
    });
  }
}
