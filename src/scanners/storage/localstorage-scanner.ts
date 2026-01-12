import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { isJWT, maskSecret } from '../../utils/crypto';
import { containsPII, isCreditCard } from '../../utils/validators';

export class LocalStorageScanner extends BaseScanner {
  readonly name = 'LocalStorageScanner';
  readonly category = 'storage_security' as const;

  private sensitiveKeys = [/token/i, /key/i, /secret/i, /password/i, /auth/i, /session/i, /jwt/i];

  async scan(context: ScanContext): Promise<ScannerResult> {
    return this.executeScan(context, async () => {
      const vulns: Vulnerability[] = [];
      const items = [
        ...(context.domAnalysis?.localStorage || []).map(i => ({ ...i, type: 'localStorage' })),
        ...(context.domAnalysis?.sessionStorage || []).map(i => ({ ...i, type: 'sessionStorage' })),
      ];

      for (const item of items) {
        if (this.sensitiveKeys.some(p => p.test(item.key))) {
          vulns.push(this.sensitiveVuln(item.key, item.value, item.type));
        }
        if (isJWT(item.value)) vulns.push(this.jwtVuln(item.key, item.value, item.type));
        const pii = containsPII(item.value);
        if (pii.hasPII) vulns.push(this.piiVuln(item.key, item.value, item.type, pii.types));
        if (isCreditCard(item.value)) vulns.push(this.ccVuln(item.key, item.value, item.type));
      }
      return vulns;
    });
  }

  private sensitiveVuln(key: string, value: string, type: string): Vulnerability {
    return new VulnerabilityBuilder()
      .setType('sensitive_in_storage').setCategory('storage_security').setSeverity('medium')
      .setTitle(`Sensitive Data in ${type}`).setDescription(`Key "${key}" contains sensitive data.`)
      .setLocation({ type: 'storage', storageKey: key }).setEvidence(maskSecret(value))
      .setImpact({ description: 'XSS can steal data', exploitScenario: 'XSS theft', dataAtRisk: ['Tokens'], businessImpact: 'Medium' })
      .setRemediation({ steps: ['Use httpOnly cookies'], references: [], priority: 'short-term', effort: 'medium' })
      .addTag('storage').build();
  }

  private jwtVuln(key: string, value: string, type: string): Vulnerability {
    return new VulnerabilityBuilder()
      .setType('jwt_in_storage').setCategory('authentication').setSeverity('high')
      .setTitle(`JWT in ${type}`).setDescription(`JWT in ${type} vulnerable to XSS.`)
      .setLocation({ type: 'storage', storageKey: key }).setEvidence(maskSecret(value))
      .setImpact({ description: 'JWT can be stolen', exploitScenario: 'Session hijacking', dataAtRisk: ['Session'], businessImpact: 'High' })
      .setRemediation({ steps: ['Use httpOnly cookies'], references: [], priority: 'immediate', effort: 'medium' })
      .addTag('jwt').build();
  }

  private piiVuln(key: string, value: string, type: string, types: string[]): Vulnerability {
    return new VulnerabilityBuilder()
      .setType('pii_in_storage').setCategory('data_exposure').setSeverity('high')
      .setTitle(`PII in ${type}`).setDescription(`Contains: ${types.join(', ')}`)
      .setLocation({ type: 'storage', storageKey: key }).setEvidence(value)
      .setImpact({ description: 'PII exposed', exploitScenario: 'Data theft', dataAtRisk: types, businessImpact: 'GDPR violation' })
      .setRemediation({ steps: ['Remove PII from client'], references: [], priority: 'immediate', effort: 'medium' })
      .addTag('pii').build();
  }

  private ccVuln(key: string, value: string, type: string): Vulnerability {
    return new VulnerabilityBuilder()
      .setType('credit_card_in_storage').setCategory('data_exposure').setSeverity('critical')
      .setTitle(`Credit Card in ${type}`).setDescription('PCI-DSS violation.')
      .setLocation({ type: 'storage', storageKey: key })
      .setEvidence(value)
      .setImpact({ description: 'CC data exposed', exploitScenario: 'Fraud', dataAtRisk: ['Credit card'], businessImpact: 'Critical - PCI violation' })
      .setRemediation({ steps: ['Remove immediately'], references: [], priority: 'immediate', effort: 'high' })
      .addTag('pci-dss').build();
  }
}
