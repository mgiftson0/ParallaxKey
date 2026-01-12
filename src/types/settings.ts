import { Severity } from './vulnerability';
import { ScannerConfig } from './scanner';

export interface DomainSettings {
  domain: string;
  enabled: boolean;
  autoScan: boolean;
  scanProfile: string;
  addedAt: number;
  lastScanned?: number;
}

export interface ScanProfile {
  id: string;
  name: string;
  description: string;
  scanners: Record<string, Partial<ScannerConfig>>;
  isDefault: boolean;
  isBuiltIn: boolean;
}

export interface NotificationSettings {
  enabled: boolean;
  minSeverity: Severity;
  sound: boolean;
  desktop: boolean;
}

export interface PrivacySettings {
  collectAnonymousUsage: boolean;
  shareFindings: boolean;
  localStorageOnly: boolean;
}

export interface AppearanceSettings {
  theme: 'light' | 'dark' | 'system';
  compactMode: boolean;
  showBadgeCount: boolean;
  badgeCountSeverity: Severity;
}

export interface Settings {
  domains: DomainSettings[];
  profiles: ScanProfile[];
  activeProfileId: string;
  notifications: NotificationSettings;
  privacy: PrivacySettings;
  appearance: AppearanceSettings;
  autoScanOnNavigation: boolean;
  scanNewTabs: boolean;
  maxStoredFindings: number;
  findingsRetentionDays: number;
  developerMode: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  domains: [],
  profiles: [
    { id: 'quick', name: 'Quick Scan', description: 'Fast scan for critical issues', scanners: {}, isDefault: false, isBuiltIn: true },
    { id: 'standard', name: 'Standard Scan', description: 'Balanced scan', scanners: {}, isDefault: true, isBuiltIn: true },
    { id: 'deep', name: 'Deep Scan', description: 'Comprehensive scan', scanners: {}, isDefault: false, isBuiltIn: true },
  ],
  activeProfileId: 'standard',
  notifications: { enabled: true, minSeverity: 'high', sound: false, desktop: true },
  privacy: { collectAnonymousUsage: false, shareFindings: false, localStorageOnly: true },
  appearance: { theme: 'system', compactMode: false, showBadgeCount: true, badgeCountSeverity: 'high' },
  autoScanOnNavigation: false,
  scanNewTabs: false,
  maxStoredFindings: 1000,
  findingsRetentionDays: 30,
  developerMode: false,
};