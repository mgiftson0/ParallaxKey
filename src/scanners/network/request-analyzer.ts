import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { hasSensitiveParams, isHTTPS, isLocalURL } from '../../utils/url';
import { maskSecret } from '../../utils/crypto';

export class RequestAnalyzer extends BaseScanner {
  readonly name = 'RequestAnalyzer';
  readonly category = 'network_security' as const;

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const requests = context.networkRequests || [];

      for (const req of requests) {
        const sensitive = hasSensitiveParams(req.url);
        if (sensitive.hasSensitive) {
          vulns.push(new VulnerabilityBuilder()
            .setType('secret_in_url').setCategory('network_security').setSeverity('high')
            .setTitle('Sensitive Data in URL').setDescription(`Contains: ${sensitive.params.join(', ')}`)
            .setLocation({ type: 'url', url: req.url }).setEvidence(maskSecret(req.url))
            .setImpact({ description: 'Data in logs', exploitScenario: 'Credential leak', dataAtRisk: sensitive.params, businessImpact: 'High' })
            .setRemediation({ steps: ['Use request body'], references: [], priority: 'immediate', effort: 'medium' })
            .addTag('url').build());
        }

        if (!isHTTPS(req.url) && !isLocalURL(req.url)) {
          const method = req.method.toUpperCase();
          const hasAuth = req.headers && (req.headers['authorization'] || req.headers['Authorization']);
          if (['POST', 'PUT', 'DELETE'].includes(method) || hasAuth) {
            vulns.push(new VulnerabilityBuilder()
              .setType('insecure_request').setCategory('network_security').setSeverity('critical')
              .setTitle('Sensitive Request over HTTP').setDescription(`${method} over unencrypted HTTP.`)
              .setLocation({ type: 'network', url: req.url }).setEvidence(`HTTP: ${req.url}`)
              .setImpact({ description: 'Data exposed', exploitScenario: 'MITM', dataAtRisk: ['Credentials'], businessImpact: 'Critical' })
              .setRemediation({ steps: ['Use HTTPS'], references: [], priority: 'immediate', effort: 'low' })
              .addTag('http').build());
          }
        }
      }
      return vulns;
    });
  }
}
