import { Environment } from '../types';
import { isLocalURL } from '../utils/url';

export function detectEnvironment(signals: { url: string; meta?: Record<string, string> }): Environment {
  const { url, meta = {} } = signals;
  if (isLocalURL(url)) return 'development';
  const urlLower = url.toLowerCase();
  if (['localhost', 'dev.', 'staging.', 'test.', ':3000', ':8080'].some(p => urlLower.includes(p))) {
    return urlLower.includes('staging') ? 'staging' : 'development';
  }
  const env = meta['environment'] || meta['env'] || '';
  if (env.toLowerCase().includes('prod')) return 'production';
  if (env.toLowerCase().includes('stag')) return 'staging';
  if (env.toLowerCase().includes('dev')) return 'development';
  return 'unknown';
}