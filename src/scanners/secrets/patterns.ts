/**
 * VaultGuard Secret Patterns Database
 * Regex patterns for detecting exposed secrets
 */

import type { SecretPattern, Severity } from '../../types';

export const SECRET_PATTERNS: SecretPattern[] = [
  // ============================================
  // Cloud Providers
  // ============================================
  {
    name: 'AWS Access Key ID',
    service: 'AWS',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: 'critical',
    context: {},
    description: 'AWS Access Key ID used for authenticating with AWS services.',
  },
  {
    name: 'AWS Secret Access Key',
    service: 'AWS',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    context: {
      mustInclude: ['aws', 'secret', 'key'],
    },
    description: 'AWS Secret Access Key used in conjunction with Access Key ID.',
  },
  {
    name: 'Google Cloud API Key',
    service: 'Google Cloud',
    pattern: /AIza[0-9A-Za-z_-]{35}/g,
    severity: 'high',
    context: {},
    description: 'Google Cloud API Key used for accessing GCP services.',
  },
  {
    name: 'Google OAuth Client ID',
    service: 'Google',
    pattern: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g,
    severity: 'medium',
    context: {},
    description: 'Google OAuth Client ID used for identifying applications in OAuth flows.',
  },
  {
    name: 'Azure Storage Account Key',
    service: 'Azure',
    pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{88}(?![A-Za-z0-9/+=])/g,
    severity: 'critical',
    context: {
      mustInclude: ['azure', 'storage', 'account'],
    },
    description: 'Azure Storage Account Key providing full access to storage resources.',
  },

  // ============================================
  // Databases
  // ============================================
  {
    name: 'Supabase Service Role Key',
    service: 'Supabase',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    severity: 'critical',
    context: {
      mustInclude: ['service_role', 'supabase'],
    },
    description: 'Supabase Service Role Key with bypass for RLS policies.',
  },
  {
    name: 'Supabase Anon Key',
    service: 'Supabase',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    severity: 'low',
    context: {
      mustInclude: ['anon'],
      mustExclude: ['service_role'],
    },
    description: 'Supabase Anonymous Key for client-side access with RLS.',
  },
  {
    name: 'Firebase Database URL',
    service: 'Firebase',
    pattern: /https:\/\/[a-z0-9-]+\.firebaseio\.com/g,
    severity: 'medium',
    context: {},
    description: 'Firebase Realtime Database URL.',
  },
  {
    name: 'MongoDB Connection String',
    service: 'MongoDB',
    pattern: /mongodb(\+srv)?:\/\/[^\s"']+/g,
    severity: 'critical',
    context: {},
    description: 'MongoDB connection string including potential credentials.',
  },
  {
    name: 'PostgreSQL Connection String',
    service: 'PostgreSQL',
    pattern: /postgres(ql)?:\/\/[^\s"']+/g,
    severity: 'critical',
    context: {},
    description: 'PostgreSQL connection string including potential credentials.',
  },

  // ============================================
  // Payment Providers
  // ============================================
  {
    name: 'Stripe Secret Key',
    service: 'Stripe',
    pattern: /sk_(test|live)_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    context: {},
    description: 'Stripe Secret Key used for server-side API calls.',
  },
  {
    name: 'Stripe Publishable Key',
    service: 'Stripe',
    pattern: /pk_(test|live)_[0-9a-zA-Z]{24,}/g,
    severity: 'low',
    context: {},
    description: 'Stripe Publishable Key for client-side integration.',
  },
  {
    name: 'PayPal Client Secret',
    service: 'PayPal',
    pattern: /EL[A-Za-z0-9_-]{60,}/g,
    severity: 'critical',
    context: {
      mustInclude: ['paypal', 'secret'],
    },
    description: 'PayPal Client Secret for API authentication.',
  },

  // ============================================
  // Version Control
  // ============================================
  {
    name: 'GitHub Personal Access Token',
    service: 'GitHub',
    pattern: /ghp_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    context: {},
    description: 'GitHub Personal Access Token (PAT).',
  },
  {
    name: 'GitHub OAuth Access Token',
    service: 'GitHub',
    pattern: /gho_[A-Za-z0-9]{36,}/g,
    severity: 'critical',
    context: {},
    description: 'GitHub OAuth Access Token.',
  },
  {
    name: 'GitHub App Token',
    service: 'GitHub',
    pattern: /ghu_[A-Za-z0-9]{36,}/g,
    severity: 'high',
    context: {},
    description: 'GitHub App Installation Token.',
  },
  {
    name: 'GitLab Personal Access Token',
    service: 'GitLab',
    pattern: /glpat-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    context: {},
    description: 'GitLab Personal Access Token.',
  },
  {
    name: 'Bitbucket App Password',
    service: 'Bitbucket',
    pattern: /ATBB[A-Za-z0-9]{32,}/g,
    severity: 'critical',
    context: {},
    description: 'Bitbucket App Password.',
  },

  // ============================================
  // Communication
  // ============================================
  {
    name: 'Slack Bot Token',
    service: 'Slack',
    pattern: /xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}/g,
    severity: 'high',
    context: {},
    description: 'Slack Bot User OAuth Token.',
  },
  {
    name: 'Slack User Token',
    service: 'Slack',
    pattern: /xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[a-f0-9]{32}/g,
    severity: 'critical',
    context: {},
    description: 'Slack User OAuth Token.',
  },
  {
    name: 'Slack Webhook URL',
    service: 'Slack',
    pattern: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
    severity: 'medium',
    context: {},
    description: 'Slack Incoming Webhook URL.',
  },
  {
    name: 'Discord Bot Token',
    service: 'Discord',
    pattern: /[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g,
    severity: 'high',
    context: {},
    description: 'Discord Bot Token.',
  },
  {
    name: 'Discord Webhook URL',
    service: 'Discord',
    pattern: /https:\/\/discord(?:app)?\.com\/api\/webhooks\/[0-9]+\/[A-Za-z0-9_-]+/g,
    severity: 'medium',
    context: {},
    description: 'Discord Webhook URL.',
  },
  {
    name: 'Twilio API Key',
    service: 'Twilio',
    pattern: /SK[0-9a-fA-F]{32}/g,
    severity: 'high',
    context: {},
    description: 'Twilio API Key Secret.',
  },
  {
    name: 'SendGrid API Key',
    service: 'SendGrid',
    pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g,
    severity: 'high',
    context: {},
    description: 'SendGrid API Key.',
  },
  {
    name: 'Mailgun API Key',
    service: 'Mailgun',
    pattern: /key-[0-9a-f]{32}/g,
    severity: 'high',
    context: {},
    description: 'Mailgun Private API Key.',
  },

  // ============================================
  // Authentication
  // ============================================
  {
    name: 'JSON Web Token',
    service: 'JWT',
    pattern: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g,
    severity: 'medium',
    context: {},
    description: 'JSON Web Token (JWT) - May contain sensitive session data.',
  },
  {
    name: 'Auth0 Client Secret',
    service: 'Auth0',
    pattern: /[a-zA-Z0-9_-]{64}/g,
    severity: 'critical',
    context: {
      mustInclude: ['auth0', 'client_secret'],
    },
    description: 'Auth0 Client Secret for application authentication.',
  },
  {
    name: 'Okta API Token',
    service: 'Okta',
    pattern: /00[a-zA-Z0-9_-]{40}/g,
    severity: 'critical',
    context: {
      mustInclude: ['okta'],
    },
    description: 'Okta API Token for managing Okta resources.',
  },

  // ============================================
  // Private Keys
  // ============================================
  {
    name: 'RSA Private Key',
    service: 'Crypto',
    pattern: /-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----/g,
    severity: 'critical',
    context: {},
    description: 'RSA Private Key.',
  },
  {
    name: 'SSH Private Key',
    service: 'SSH',
    pattern: /-----BEGIN (?:OPENSSH|EC|DSA) PRIVATE KEY-----[\s\S]+?-----END (?:OPENSSH|EC|DSA) PRIVATE KEY-----/g,
    severity: 'critical',
    context: {},
    description: 'SSH/EC/DSA Private Key.',
  },
  {
    name: 'PGP Private Key',
    service: 'PGP',
    pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----/g,
    severity: 'critical',
    context: {},
    description: 'PGP Private Key.',
  },

  // ============================================
  // API Keys (Generic)
  // ============================================
  {
    name: 'Generic API Key',
    service: 'Unknown',
    pattern: /(?:api[_-]?key|apikey|api[_-]?token)[\s]*[:=][\s]*['"]?([A-Za-z0-9_-]{20,})['"]?/gi,
    severity: 'high',
    context: {},
    description: 'Generic API key or token detected by standard naming conventions.',
  },
  {
    name: 'Generic Secret',
    service: 'Unknown',
    pattern: /(?:secret|password|passwd|pwd)[\s]*[:=][\s]*['"]?([^\s'"]{8,})['"]?/gi,
    severity: 'high',
    context: {
      mustExclude: ['example', 'your', 'placeholder', 'xxx', '***', '...'],
    },
    description: 'Generic secret or password detected by naming conventions.',
  },
  {
    name: 'Bearer Token',
    service: 'HTTP',
    pattern: /Bearer\s+([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|[A-Za-z0-9_-]{20,})/gi,
    severity: 'high',
    context: {},
    description: 'HTTP Bearer Token used for authorization.',
  },
];

/**
 * Get patterns by service
 */
export function getPatternsByService(service: string): SecretPattern[] {
  return SECRET_PATTERNS.filter(
    (p) => p.service.toLowerCase() === service.toLowerCase()
  );
}

/**
 * Get patterns by severity
 */
export function getPatternsBySeverity(severity: Severity): SecretPattern[] {
  return SECRET_PATTERNS.filter((p) => p.severity === severity);
}

/**
 * Get critical patterns only
 */
export function getCriticalPatterns(): SecretPattern[] {
  return getPatternsBySeverity('critical');
}