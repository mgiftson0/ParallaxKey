import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { isHTTPS } from '../../utils/url';

export class FormSecurityScanner extends BaseScanner {
  readonly name = 'FormSecurityScanner';
  readonly category = 'misconfiguration' as const;

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const forms = context.domAnalysis?.forms || [];

      for (const form of forms) {
        if (form.hasPasswordField && !isHTTPS(context.url) && !isHTTPS(form.action)) {
          vulns.push(new VulnerabilityBuilder()
            .setType('insecure_form').setCategory('misconfiguration').setSeverity('critical')
            .setTitle('Password Form over HTTP').setDescription('Login form over unencrypted HTTP.')
            .setLocation({ type: 'html', url: context.url }).setEvidence(`Action: ${form.action}`)
            .setImpact({ description: 'Passwords in plaintext', exploitScenario: 'MITM', dataAtRisk: ['Passwords'], businessImpact: 'Critical' })
            .setRemediation({ steps: ['Use HTTPS'], references: [], priority: 'immediate', effort: 'low' })
            .addTag('form').build());
        }
      }
      return vulns;
    });
  }
}