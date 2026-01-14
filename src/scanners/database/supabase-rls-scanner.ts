import { Vulnerability, ScanContext, ScannerResult } from '../../types';
import { BaseScanner } from '../base-scanner';
import { VulnerabilityBuilder } from '../../core/vulnerability';
import { logger } from '../../utils/logger';

/**
 * SupabaseRLSScanner - Detects Supabase tables without Row Level Security (RLS)
 * 
 * This scanner:
 * 1. Extracts Supabase project URLs and anon keys from the page
 * 2. Queries the Supabase REST API to discover accessible tables
 * 3. Reports vulnerabilities for tables accessible without proper authentication
 */
export class SupabaseRLSScanner extends BaseScanner {
    readonly name = 'SupabaseRLSScanner';
    readonly category = 'database' as const;

    // Patterns for detecting Supabase credentials
    private readonly SUPABASE_URL_PATTERN = /https:\/\/([a-z0-9-]+)\.supabase\.co/gi;
    private readonly SUPABASE_KEY_PATTERN = /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g;

    async scan(context: ScanContext): Promise<ScannerResult> {
        return this.executeScan(context, async () => {
            const vulns: Vulnerability[] = [];

            // Extract Supabase credentials from page content
            const credentials = this.extractSupabaseCredentials(context);

            if (credentials.length === 0) {
                logger.debug(this.name, 'No Supabase credentials detected on this page');
                return vulns;
            }

            logger.info(this.name, `Found ${credentials.length} Supabase project(s) to analyze`);

            for (const cred of credentials) {
                try {
                    const tableVulns = await this.checkRLSStatus(cred.url, cred.anonKey, context.url);
                    vulns.push(...tableVulns);
                } catch (e: any) {
                    logger.warn(this.name, `Failed to check RLS for ${cred.url}: ${e.message}`);
                }
            }

            return vulns;
        });
    }

    /**
     * Extract Supabase URLs and corresponding anon keys from page content
     */
    private extractSupabaseCredentials(context: ScanContext): Array<{ url: string; anonKey: string }> {
        const credentials: Array<{ url: string; anonKey: string }> = [];
        const seen = new Set<string>();

        // Collect all content to search
        const contentSources: string[] = [];

        // Scripts
        context.domAnalysis?.scripts?.forEach(s => {
            if (s.content) contentSources.push(s.content);
        });

        // LocalStorage
        context.domAnalysis?.localStorage?.forEach(i => {
            contentSources.push(`${i.key}=${i.value}`);
        });

        // SessionStorage
        context.domAnalysis?.sessionStorage?.forEach(i => {
            contentSources.push(`${i.key}=${i.value}`);
        });

        // Network requests
        context.networkRequests?.forEach(r => {
            contentSources.push(r.url);
            if (r.headers) {
                Object.values(r.headers).forEach(v => contentSources.push(String(v)));
            }
        });

        const allContent = contentSources.join('\n');

        // Find all Supabase URLs
        const urlMatches = allContent.matchAll(this.SUPABASE_URL_PATTERN);
        const supabaseUrls = [...new Set([...urlMatches].map(m => m[0].toLowerCase()))];

        // Find all JWT tokens (potential anon keys)
        const keyMatches = allContent.matchAll(this.SUPABASE_KEY_PATTERN);
        const jwtTokens = [...new Set([...keyMatches].map(m => m[0]))];

        // Match URLs with keys (heuristic: keys found near URLs in the same content block)
        for (const url of supabaseUrls) {
            if (seen.has(url)) continue;
            seen.add(url);

            // Find the best matching anon key (prefer those containing 'anon' context)
            let bestKey = '';
            for (const token of jwtTokens) {
                // Decode JWT payload to check role
                try {
                    const payload = JSON.parse(atob(token.split('.')[1]));
                    if (payload.role === 'anon' || payload.role === 'authenticated') {
                        bestKey = token;
                        break;
                    }
                } catch {
                    // If we can't decode, use the first token
                    if (!bestKey) bestKey = token;
                }
            }

            if (bestKey) {
                credentials.push({ url, anonKey: bestKey });
            }
        }

        return credentials;
    }

    /**
     * Check RLS status by attempting to access common table endpoints
     */
    private async checkRLSStatus(
        supabaseUrl: string,
        anonKey: string,
        sourceUrl: string
    ): Promise<Vulnerability[]> {
        const vulns: Vulnerability[] = [];

        // Common table names to check
        const commonTables = [
            'users', 'profiles', 'accounts', 'customers',
            'orders', 'products', 'items', 'posts',
            'comments', 'messages', 'notifications',
            'settings', 'configurations', 'secrets',
            'payments', 'transactions', 'invoices',
            'logs', 'events', 'sessions', 'tokens',
            'files', 'uploads', 'documents', 'attachments'
        ];

        const headers = {
            'apikey': anonKey,
            'Authorization': `Bearer ${anonKey}`,
            'Content-Type': 'application/json',
        };

        for (const table of commonTables) {
            try {
                const response = await fetch(`${supabaseUrl}/rest/v1/${table}?limit=1`, {
                    method: 'GET',
                    headers,
                });

                if (response.ok) {
                    const data = await response.json();

                    // If we got data back, the table is accessible without proper auth
                    if (Array.isArray(data)) {
                        vulns.push(this.createRLSVulnerability(table, supabaseUrl, sourceUrl, data.length > 0));
                        logger.warn(this.name, `Table "${table}" accessible without RLS!`);
                    }
                } else if (response.status === 200) {
                    // Empty response but accessible
                    vulns.push(this.createRLSVulnerability(table, supabaseUrl, sourceUrl, false));
                }
                // 401/403/404 are expected for protected or non-existent tables
            } catch (e: any) {
                // Network errors are expected for non-existent endpoints
                logger.debug(this.name, `Table ${table} check failed: ${e.message}`);
            }
        }

        return vulns;
    }

    /**
     * Create a vulnerability for a table without RLS
     */
    private createRLSVulnerability(
        tableName: string,
        supabaseUrl: string,
        sourceUrl: string,
        hasData: boolean
    ): Vulnerability {
        const projectId = supabaseUrl.match(/https:\/\/([a-z0-9-]+)\.supabase\.co/)?.[1] || 'unknown';

        return new VulnerabilityBuilder()
            .setType('supabase_no_rls')
            .setCategory('database')
            .setSeverity(hasData ? 'critical' : 'high')
            .setTitle(`Supabase Table Without RLS: ${tableName}`)
            .setDescription(
                `The table "${tableName}" in Supabase project "${projectId}" is accessible without proper Row Level Security (RLS). ` +
                `${hasData ? 'Data was retrieved from this table.' : 'The table exists and is queryable.'}`
            )
            .setLocation({
                type: 'database',
                table: tableName,
                project: projectId,
                url: supabaseUrl,
            } as any)
            .setEvidence(`Endpoint: ${supabaseUrl}/rest/v1/${tableName}`)
            .setImpact({
                description: 'Unauthorized users can read sensitive data from this table',
                exploitScenario: 'An attacker with the anon key can query all data from this table',
                dataAtRisk: ['User data', 'Sensitive records'],
                businessImpact: hasData ? 'Critical - Data breach risk' : 'High - Potential data exposure',
            })
            .setRemediation({
                steps: [
                    `Enable RLS on the "${tableName}" table: ALTER TABLE ${tableName} ENABLE ROW LEVEL SECURITY;`,
                    'Create appropriate RLS policies to restrict access',
                    'Test policies with different user roles',
                    'Consider using service_role key only on the server-side',
                ],
                references: [
                    'https://supabase.com/docs/guides/auth/row-level-security',
                    'https://supabase.com/docs/guides/database/postgres/row-level-security',
                ],
                priority: 'immediate',
                effort: 'medium',
            })
            .addTag('supabase')
            .addTag('rls')
            .addTag('database-security')
            .build();
    }
}
