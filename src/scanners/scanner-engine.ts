import { ScanResult, ScanOptions, ScanContext, Vulnerability, ScanSummary, DOMData } from '../types';
import { generateId, getDomain, detectEnvironment, severityToScore } from '../utils/helpers';
import { BaseScanner } from './base-scanner';
import { APIKeyScanner } from './secrets/api-key-scanner';
import { CORSScanner } from './headers/cors-scanner';
import { LocalStorageScanner } from './storage/localstorage-scanner';
import { CookieScanner } from './storage/cookie-scanner';
import { FormSecurityScanner } from './dom/form-scanner';
import { SupabaseRLSScanner } from './database/supabase-rls-scanner';

export class ScannerEngine {
  private scanners: BaseScanner[] = [
    new APIKeyScanner(),
    new CORSScanner(),
    new LocalStorageScanner(),
    new CookieScanner(),
    new FormSecurityScanner(),
    new SupabaseRLSScanner(),
  ];

  private status: 'idle' | 'scanning' = 'idle';
  private currentScan: ScanResult | null = null;

  getStatus() { return this.status; }
  getCurrentScan() { return this.currentScan; }

  stop() {
    this.status = 'idle';
    console.log('[ParallaxKey] Scanner stopped');
  }

  async scan(
    url: string,
    tabId: number,
    options: ScanOptions,
    domAnalysis?: DOMData,
    networkRequests?: any[],
    networkResponses?: any[]
  ): Promise<ScanResult> {
    console.log('[ParallaxKey] ScannerEngine.scan() called');
    console.log('[ParallaxKey] URL:', url);
    console.log('[ParallaxKey] DOM Analysis:', domAnalysis ? 'provided' : 'not provided');
    console.log('[ParallaxKey] Network Requests:', networkRequests?.length || 0);
    console.log('[ParallaxKey] Network Responses:', networkResponses?.length || 0);

    if (this.status === 'scanning') {
      throw new Error('Scan already in progress');
    }

    this.status = 'scanning';
    const startTime = Date.now();
    const domain = getDomain(url);
    const environment = detectEnvironment(url);

    console.log('[ParallaxKey] Domain:', domain);
    console.log('[ParallaxKey] Environment:', environment);

    const ctx: ScanContext = {
      url,
      domain,
      tabId,
      options,
      domAnalysis,
      networkRequests,
      networkResponses
    };

    const allVulns: Vulnerability[] = [];
    const enabledScanners = this.scanners.filter(s => s.isEnabled());

    console.log('[ParallaxKey] Running', enabledScanners.length, 'scanners');

    for (const scanner of enabledScanners) {
      try {
        console.log('[ParallaxKey] Running scanner:', scanner.name);
        await scanner.initialize();
        const result = await scanner.scan(ctx);
        console.log('[ParallaxKey]', scanner.name, 'found', result.vulnerabilities.length, 'issues');
        allVulns.push(...result.vulnerabilities);
        await scanner.cleanup();
      } catch (e: any) {
        console.error('[ParallaxKey] Scanner', scanner.name, 'failed:', e.message);
      }
    }

    console.log('[ParallaxKey] Total vulnerabilities found:', allVulns.length);

    // Calculate summary
    const summary: ScanSummary = {
      total: allVulns.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      },
      byCategory: {},
      riskScore: 0,
      grade: 'A'
    };

    allVulns.forEach(v => {
      if (summary.bySeverity[v.severity] !== undefined) {
        summary.bySeverity[v.severity]++;
      }
      summary.byCategory[v.category] = (summary.byCategory[v.category] || 0) + 1;
    });

    // Calculate risk score
    summary.riskScore = Math.min(100, allVulns.reduce((acc, v) => acc + severityToScore(v.severity) * 10, 0));
    summary.grade = this.getGrade(summary.riskScore);

    this.currentScan = {
      id: generateId(),
      url,
      domain,
      timestamp: startTime,
      vulnerabilities: allVulns,
      summary,
      environment
    };

    this.status = 'idle';

    console.log('[ParallaxKey] Scan complete. Summary:', summary);

    return this.currentScan;
  }

  private getGrade(riskScore: number): string {
    if (riskScore === 0) return 'A';
    if (riskScore < 20) return 'B';
    if (riskScore < 40) return 'C';
    if (riskScore < 60) return 'D';
    return 'F';
  }
}

export const scannerEngine = new ScannerEngine();