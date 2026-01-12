import { Vulnerability, VulnerabilitySummary, Severity } from '../types/vulnerability';
import { compareSeverity } from '../core/severity-calculator';

export interface ReportOptions {
  format: 'json' | 'csv' | 'html' | 'markdown';
  includeRemediation: boolean;
  includeEvidence: boolean;
  groupBySeverity: boolean;
}

export class ReportGenerator {
  static generateSummary(findings: Vulnerability[]): VulnerabilitySummary {
    const summary: VulnerabilitySummary = {
      total: findings.length,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      byType: {},
      criticalCount: 0, highCount: 0, mediumCount: 0, lowCount: 0, infoCount: 0
    };

    findings.forEach(f => {
      summary.bySeverity[f.severity]++;
      summary.byType[f.type] = (summary.byType[f.type] || 0) + 1;
    });

    summary.criticalCount = summary.bySeverity.critical;
    summary.highCount = summary.bySeverity.high;
    summary.mediumCount = summary.bySeverity.medium;
    summary.lowCount = summary.bySeverity.low;
    summary.infoCount = summary.bySeverity.info;

    return summary;
  }

  static toJSON(findings: Vulnerability[], options?: Partial<ReportOptions>): string {
    const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
    const report = {
      generatedAt: new Date().toISOString(),
      summary: this.generateSummary(findings),
      findings: sorted.map(f => ({
        id: f.id,
        type: f.type,
        severity: f.severity,
        title: f.title,
        description: f.description,
        location: f.location,
        evidence: options?.includeEvidence ? f.maskedEvidence : undefined,
        remediation: options?.includeRemediation ? f.remediation : undefined,
        timestamp: f.timestamp
      }))
    };
    return JSON.stringify(report, null, 2);
  }

  static toCSV(findings: Vulnerability[]): string {
    const headers = ['ID', 'Severity', 'Type', 'Title', 'Description', 'Location', 'Timestamp'];
    const rows = findings.map(f => [
      f.id,
      f.severity,
      f.type,
      `"${f.title.replace(/"/g, '""')}"`,
      `"${f.description.replace(/"/g, '""').substring(0, 200)}"`,
      f.location.url || f.location.storageKey || '',
      new Date(f.timestamp).toISOString()
    ]);
    return [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
  }

  static toHTML(findings: Vulnerability[]): string {
    const summary = this.generateSummary(findings);
    const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));
    const severityColors: Record<Severity, string> = { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#2563eb', info: '#6b7280' };

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>VaultGuard Security Report</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 2rem; background: #f9fafb; }
    h1 { color: #111827; } h2 { color: #374151; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }
    .summary { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin: 2rem 0; }
    .summary-card { background: white; padding: 1.5rem; border-radius: 0.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); text-align: center; }
    .summary-card h3 { margin: 0; font-size: 2rem; } .summary-card p { margin: 0.5rem 0 0; color: #6b7280; }
    .finding { background: white; border-radius: 0.5rem; padding: 1.5rem; margin: 1rem 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid; }
    .badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; color: white; }
    pre { background: #1f2937; color: #f9fafb; padding: 1rem; border-radius: 0.5rem; overflow-x: auto; }
  </style>
</head>
<body>
  <h1>🔒 VaultGuard Security Report</h1>
  <p>Generated: ${new Date().toLocaleString()}</p>
  
  <div class="summary">
    ${(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(s => `
      <div class="summary-card" style="border-top: 3px solid ${severityColors[s]}"><h3>${summary.bySeverity[s]}</h3><p>${s.charAt(0).toUpperCase() + s.slice(1)}</p></div>
    `).join('')}
  </div>

  <h2>Findings (${findings.length})</h2>
  ${sorted.map(f => `
    <div class="finding" style="border-left-color: ${severityColors[f.severity]}">
      <div><span class="badge" style="background: ${severityColors[f.severity]}">${f.severity.toUpperCase()}</span></div>
      <h3>${this.escapeHtml(f.title)}</h3>
      <p>${this.escapeHtml(f.description)}</p>
      <p><strong>Location:</strong> ${this.escapeHtml(f.location.url || f.location.storageKey || 'N/A')}</p>
      ${f.maskedEvidence ? `<p><strong>Evidence:</strong></p><pre>${this.escapeHtml(f.maskedEvidence)}</pre>` : ''}
      <p><strong>Remediation:</strong> ${this.escapeHtml(f.remediation.summary)}</p>
    </div>
  `).join('')}
</body>
</html>`;
  }

  static toMarkdown(findings: Vulnerability[]): string {
    const summary = this.generateSummary(findings);
    const sorted = [...findings].sort((a, b) => compareSeverity(a.severity, b.severity));

    return `# 🔒 VaultGuard Security Report

**Generated:** ${new Date().toLocaleString()}

## Summary

| Severity | Count |
|----------|-------|
| Critical | ${summary.criticalCount} |
| High | ${summary.highCount} |
| Medium | ${summary.mediumCount} |
| Low | ${summary.lowCount} |
| Info | ${summary.infoCount} |
| **Total** | **${summary.total}** |

## Findings

${sorted.map(f => `### ${f.severity.toUpperCase()}: ${f.title}

**Type:** ${f.type}  
**Location:** ${f.location.url || f.location.storageKey || 'N/A'}

${f.description}

**Evidence:**
\`\`\`
${f.maskedEvidence}
\`\`\`

**Remediation:** ${f.remediation.summary}

---
`).join('\n')}`;
  }

  private static escapeHtml(str: string): string {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
}

export default ReportGenerator;