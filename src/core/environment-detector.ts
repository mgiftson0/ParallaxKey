import { Environment } from '../types/vulnerability';
import { isLocalhost } from '../utils/url-utils';

export function detectEnvironment(signals: { url: string; headers?: Record<string, string>; html?: string; scripts?: string[] }): Environment {
  const { url, headers, html, scripts } = signals;
  if (isLocalhost(url)) return 'development';
  const devIndicators = ['dev.', 'development.', 'staging.', 'stage.', 'test.', 'qa.', 'uat.', 'sandbox.', 'preview.', '-dev.', '-staging.'];
  const urlLower = url.toLowerCase();
  if (devIndicators.some(i => urlLower.includes(i))) return urlLower.includes('staging') ? 'staging' : 'development';
  if (headers) {
    for (const h of ['x-debug', 'x-development', 'x-env']) {
      const v = headers[h]?.toLowerCase();
      if (v === 'development' || v === 'dev' || v === 'true') return 'development';
      if (v === 'staging') return 'staging';
    }
  }
  if (html && [/<!--\s*DEBUG/i, /<!--\s*DEV/i, /data-env=["']dev/i, /window\.__DEV__\s*=\s*true/i].some(p => p.test(html))) return 'development';
  if (scripts?.some(s => [/react.*\.development/i, /vue\.js$/i, /\bsourceMappingURL=/, /localhost:\d+/].some(p => p.test(s)))) return 'development';
  return 'production';
}

export function getEnvironmentRiskMultiplier(env: Environment): number {
  return env === 'production' ? 1.5 : env === 'staging' ? 1.2 : env === 'development' ? 0.8 : 1.0;
}