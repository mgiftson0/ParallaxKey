import { BaseScanner } from '../base-scanner';
import { ScanContext, ScannerCategory } from '../../types/scanner';
import { Severity } from '../../types/vulnerability';
import { calculateEntropy, maskSecret, decodeJWT } from '../../utils/crypto-utils';
import { isLocalhost } from '../../utils/url-utils';

interface SecretPattern { name: string; service: string; pattern: RegExp; severity: Severity; validator?: (m: string) => boolean; }

const SECRET_PATTERNS: SecretPattern[] = [
  { name: 'Supabase Service Role Key', service: 'Supabase', pattern: /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/g, severity: 'critical', validator: m => { const d = decodeJWT(m); return (d?.payload as Record<string, unknown>)?.role === 'service_role'; } },
  { name: 'Stripe Secret Key', service: 'Stripe', pattern: /sk_(test|live)_[0-9a-zA-Z]{24,}/g, severity: 'critical' },
  { name: 'AWS Access Key ID', service: 'AWS', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'GitHub Token', service: 'GitHub', pattern: /gh[pousr]_[A-Za-z0-9]{36,}/g, severity: 'critical' },
  { name: 'Firebase API Key', service: 'Firebase', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'medium' },
  { name: 'Slack Bot Token', service: 'Slack', pattern: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/g, severity: 'high' },
  { name: 'OpenAI API Key', service: 'OpenAI', pattern: /sk-[A-Za-z0-9]{48}/g, severity: 'critical' },
  { name: 'SendGrid API Key', service: 'SendGrid', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: 'high' },
  { name: 'Private Key', service: 'Generic', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Generic API Key', service: 'Unknown', pattern: /['"][a-zA-Z0-9_-]*(?:api[_-]?key|apikey)['"]\s*[:=]\s*['"]([a-zA-Z0-9_-]{16,})['"/gi, severity: 'high' },
];

const PLACEHOLDER_PATTERNS = [/example/i, /placeholder/i, /your[_-]?key/i, /xxx+/i, /000+/, /test[_-]?key/i, /\$\{/, /\{\{/];

export class APIKeyScanner extends BaseScanner {
  readonly id = 'api-key-scanner';
  readonly name = 'API Key & Secrets Scanner';
  readonly description = 'Detects exposed API keys, tokens, and secrets';
  readonly category: ScannerCategory = 'secrets';
  readonly version = '1.0.0';

  protected async performScan(context: ScanContext): Promise<void> {
    const ext = context as ScanContext & { domData?: { scripts?: { src?: string; content: string }[]; localStorage?: Record<string, string>; sessionStorage?: Record<string, string>; html?: string } };
    if (ext.domData?.scripts) for (const s of ext.domData.scripts) if (s.content) await this.scanContent(s.content, { type: 'script', url: s.src || context.url }, context);
    if (ext.domData?.localStorage) for (const [k, v] of Object.entries(ext.domData.localStorage)) await this.scanContent(v, { type: 'storage', storageKey: `localStorage:${k}` }, context);
    if (ext.domData?.sessionStorage) for (const [k, v] of Object.entries(ext.domData.sessionStorage)) await this.scanContent(v, { type: 'storage', storageKey: `sessionStorage:${k}` }, context);
    if (ext.domData?.html) await this.scanContent(ext.domData.html, { type: 'html', url: context.url }, context);
  }

  private async scanContent(content: string, location: { type: 'script' | 'storage' | 'html'; url?: string; storageKey?: string }, context: ScanContext): Promise<void> {
    if (this.isAborted()) return;
    for (const pattern of SECRET_PATTERNS) {
      pattern.pattern.lastIndex = 0;
      let match;
      while ((match = pattern.pattern.exec(content)) !== null) {
        const secret = match[1] || match[0];
        if (PLACEHOLDER_PATTERNS.some(p => p.test(secret))) continue;
        if (pattern.validator && !pattern.validator(secret)) continue;
        let severity = pattern.severity;
        if (context.environment === 'development' || isLocalhost(context.url)) severity = severity === 'critical' ? 'high' : severity === 'high' ? 'medium' : 'low';
        this.addFinding(this.createFinding({
          type: 'api_key_exposed', severity, title: `${pattern.name} Exposed`,
          description: `A ${pattern.name} for ${pattern.service} was found exposed in client-side code.`,
          location: { type: location.type, url: location.url, storageKey: location.storageKey },
          evidence: secret, maskedEvidence: maskSecret(secret), context: content.substring(Math.max(0, match.index - 50), match.index + 50),
          environment: context.environment,
          impact: { description: `Exposed ${pattern.service} credentials`, exploitScenario: `Attacker can use this key to access ${pattern.service}`, dataAtRisk: ['API access', 'Account data'] },
          remediation: { summary: `Remove and rotate the ${pattern.name}`, steps: [{ order: 1, title: 'Rotate Key', description: `Revoke this key in ${pattern.service} dashboard` }, { order: 2, title: 'Move to Server', description: 'Move API calls to backend' }], references: [], timeEstimate: '1 hour', difficulty: 'medium' },
          tags: ['api-key', pattern.service.toLowerCase()], metadata: { service: pattern.service }
        }));
      }
    }
  }
}