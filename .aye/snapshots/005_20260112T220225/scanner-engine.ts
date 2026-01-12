import { Vulnerability, ScanResult, ScanOptions, ScanSummary, ScanContext, ScannerResult, DOMAnalysisResult, NetworkRequest, NetworkResponse, VulnerabilityCategory, Severity } from '../types';
import { logger } from '../utils/logger';
import { generateId } from '../utils/crypto';
import { extractDomain } from '../utils/url';
import { detectEnvironment } from '../core/environment';
import { calculateRiskScore, getGrade } from '../core/severity';
import { APIKeyScanner } from './secrets/api-key-scanner';
import { EntropyAnalyzer } from './secrets/entropy-analyzer';
import { HeaderSecurityScanner } from './headers/security-headers';
import { CORSScanner } from './headers/cors-scanner';
import { LocalStorageScanner } from './storage/localstorage-scanner';
import { CookieScanner } from './storage/cookie-scanner';
import { JWTAnalyzer } from './auth/jwt-analyzer';
import { RequestAnalyzer } from './network/request-analyzer';
import { PIIDetector } from './data/pii-detector';
import { FormSecurityScanner } from './dom/form-scanner';
import { BaseScanner } from './base-scanner';

export class ScannerEngine {
  private scanners: Map<string, BaseScanner> = new Map();
  private currentScan: ScanResult | null = null;
  private status: 'idle' | 'scanning' | 'completed' | 'error' = 'idle';

  constructor() {
    const list: BaseScanner[] = [
      new APIKeyScanner(), new EntropyAnalyzer(), new HeaderSecurityScanner(), new CORSScanner(),
      new LocalStorageScanner(), new CookieScanner(), new JWTAnalyzer(), new RequestAnalyzer(),
      new PIIDetector(), new FormSecurityScanner(),
    ];
    list.forEach(s => this.scanners.set(s.name, s));
    logger.info('ScannerEngine', `Registered ${this.scanners.size} scanners`);
  }

  getStatus() { return this.status; }
  getCurrentScan() { return this.currentScan; }

  async scan(url: string, tabId: number, options: ScanOptions, domAnalysis?: DOMAnalysisResult, networkRequests?: NetworkRequest[], networkResponses?: NetworkResponse[]): Promise<ScanResult> {
    if (this.status === 'scanning') throw new Error('Scan in progress');
    this.status = 'scanning';
    const startTime = Date.now();
    const domain = extractDomain(url);
    const environment = detectEnvironment({ url, meta: domAnalysis?.meta });

    this.currentScan = {
      id: generateId(), url, domain, scanType: options.type, status: 'scanning', startTime, environment,
      vulnerabilities: [],
      summary: { total: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byCategory: {}, riskScore: 0, grade: 'A' },
      metadata: {
        userAgent: typeof navigator !== 'undefined' ? navigator.userAgent : 'unknown',
        pageTitle: '', scriptsAnalyzed: domAnalysis?.scripts?.length || 0,
        requestsAnalyzed: networkRequests?.length || 0,
        storageItemsAnalyzed: (domAnalysis?.localStorage?.length || 0) + (domAnalysis?.sessionStorage?.length || 0),
        cookiesAnalyzed: domAnalysis?.cookies?.length || 0,
      },
    };

    const context: ScanContext = { url, domain, origin: `https://${domain}`, tabId, options, domAnalysis, networkRequests, networkResponses };

    try {
      const results: ScannerResult[] = [];
      for (const scanner of this.scanners.values()) {
        if (scanner.isEnabled()) {
          await scanner.initialize();
          results.push(await scanner.scan(context));
          await scanner.cleanup();
        }
      }

      const allVulns: Vulnerability[] = [];
      results.forEach(r => allVulns.push(...r.vulnerabilities));

      this.currentScan.vulnerabilities = allVulns;
      this.currentScan.summary = this.calcSummary(allVulns);
      this.currentScan.status = 'completed';
      this.currentScan.endTime = Date.now();
      this.currentScan.duration = this.currentScan.endTime - startTime;
      this.status = 'completed';
      logger.info('ScannerEngine', `Complete: ${allVulns.length} findings`);
      return this.currentScan;
    } catch (e: any) {
      this.status = 'error';
      if (this.currentScan) this.currentScan.status = 'error';
      throw e;
    }
  }

  async runQuickScan(context: ScanContext): Promise<ScanSummary> {
    const result = await this.scan(context.url, context.tabId, { type: 'quick' }, context.domAnalysis, context.networkRequests, context.networkResponses);
    return result.summary;
  }

  async runFullScan(context: ScanContext): Promise<ScanSummary> {
    const result = await this.scan(context.url, context.tabId, { type: 'standard' }, context.domAnalysis, context.networkRequests, context.networkResponses);
    return result.summary;
  }

  cancelScan() {
    this.status = 'idle';
  }

  getScanner(name: string): BaseScanner | undefined {
    // Try to find by name or ID
    for (const scanner of this.scanners.values()) {
      if (scanner.name === name || (scanner as any).id === name) return scanner;
    }
    return undefined;
  }

  private calcSummary(vulns: Vulnerability[]): ScanSummary {
    const summary: ScanSummary = { total: vulns.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, byCategory: {}, riskScore: 0, grade: 'A' };
    for (const v of vulns) {
      summary.bySeverity[v.severity]++;
      summary.byCategory[v.category] = (summary.byCategory[v.category] || 0) + 1;
    }
    summary.riskScore = calculateRiskScore(vulns);
    summary.grade = getGrade(summary.riskScore);
    return summary;
  }
}

export const scannerEngine = new ScannerEngine();