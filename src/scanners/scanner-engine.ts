import { ScanResult, ScanOptions, ScanContext, Vulnerability, DOMAnalysisResult, NetworkRequest, NetworkResponse, ScanSummary } from '../types';
import { generateId, extractDomain, detectEnvironment, calculateRiskScore, getGrade } from '../utils/helpers';
import { BaseScanner } from './base-scanner';
import { APIKeyScanner } from './api-key-scanner';
import { HeaderScanner } from './header-scanner';
import { CORSScanner } from './cors-scanner';
import { StorageScanner } from './storage-scanner';
import { CookieScanner } from './cookie-scanner';
import { JWTScanner } from './jwt-scanner';
import { RequestScanner } from './request-scanner';
import { FormScanner } from './form-scanner';

export class ScannerEngine {
  private scanners: BaseScanner[] = [
    new APIKeyScanner(),
    new HeaderScanner(),
    new CORSScanner(),
    new StorageScanner(),
    new CookieScanner(),
    new JWTScanner(),
    new RequestScanner(),
    new FormScanner(),
  ];

  private status: 'idle' | 'scanning' = 'idle';
  private currentScan: ScanResult | null = null;

  getStatus() { return this.status; }
  getCurrentScan() { return this.currentScan; }
  
  stop() { 
    this.status = 'idle'; 
    console.log('[VaultGuard] Scanner stopped');
  }

  async scan(
    url: string,
    tabId: number,
    options: ScanOptions,
    domAnalysis?: DOMAnalysisResult,
    networkRequests?: NetworkRequest[],
    networkResponses?: NetworkResponse[]
  ): Promise<ScanResult> {
    console.log('[VaultGuard] ScannerEngine.scan() called');
    console.log('[VaultGuard] URL:', url);
    console.log('[VaultGuard] DOM Analysis:', domAnalysis ? 'provided' : 'not provided');
    console.log('[VaultGuard] Network Requests:', networkRequests?.length || 0);
    console.log('[VaultGuard] Network Responses:', networkResponses?.length || 0);
    
    if (this.status === 'scanning') {
      throw new Error('Scan already in progress');
    }
    
    this.status = 'scanning';
    const startTime = Date.now();
    const domain = extractDomain(url);
    const environment = detectEnvironment(url, domAnalysis?.meta);
    
    console.log('[VaultGuard] Domain:', domain);
    console.log('[VaultGuard] Environment:', environment);

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
    
    console.log('[VaultGuard] Running', enabledScanners.length, 'scanners');

    for (const scanner of enabledScanners) {
      try {
        console.log('[VaultGuard] Running scanner:', scanner.name);
        await scanner.initialize();
        const result = await scanner.scan(ctx);
        console.log('[VaultGuard]', scanner.name, 'found', result.vulnerabilities.length, 'issues');
        allVulns.push(...result.vulnerabilities);
        await scanner.cleanup();
      } catch (e: any) {
        console.error('[VaultGuard] Scanner', scanner.name, 'failed:', e.message);
      }
    }

    console.log('[VaultGuard] Total vulnerabilities found:', allVulns.length);

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
      riskScore: 0,
      grade: 'A'
    };
    
    allVulns.forEach(v => {
      if (summary.bySeverity[v.severity] !== undefined) {
        summary.bySeverity[v.severity]++;
      }
    });
    
    summary.riskScore = calculateRiskScore(allVulns);
    summary.grade = getGrade(summary.riskScore);

    this.currentScan = {
      id: generateId(),
      url,
      domain,
      scanType: options.type,
      status: 'completed',
      startTime,
      endTime: Date.now(),
      environment,
      vulnerabilities: allVulns,
      summary
    };

    this.status = 'idle';
    
    console.log('[VaultGuard] Scan complete. Summary:', summary);
    
    return this.currentScan;
  }
}

export const scannerEngine = new ScannerEngine();