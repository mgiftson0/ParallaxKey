import { Vulnerability } from './vulnerability';
import { ScanOptions, ScanProgress, ScanResult } from './scanner';
import { Settings } from './settings';

export type MessageType =
  | 'START_SCAN' | 'STOP_SCAN' | 'GET_SCAN_STATUS' | 'SCAN_PROGRESS' | 'SCAN_COMPLETE' | 'SCAN_ERROR'
  | 'GET_FINDINGS' | 'CLEAR_FINDINGS' | 'MARK_FALSE_POSITIVE' | 'GET_SETTINGS' | 'UPDATE_SETTINGS'
  | 'CONTENT_SCRIPT_READY' | 'DOM_DATA' | 'GET_DOM_DATA' | 'STORAGE_DATA' | 'NETWORK_REQUEST'
  | 'NETWORK_RESPONSE' | 'GET_TAB_INFO' | 'EXPORT_REPORT' | 'PING' | 'PONG'
  | 'GET_STATUS' | 'GET_RESULTS' | 'ANALYZE_DOM' | 'CONTENT_READY' | 'CLEAR_RESULTS' | 'GET_SCAN_HISTORY';

export interface BaseMessage<T = any> {
  type: MessageType;
  timestamp: number;
  tabId?: number;
  payload?: T;
}

export interface StartScanMessage extends BaseMessage<ScanOptions> {
  type: 'START_SCAN';
}

export interface ScanProgressMessage extends BaseMessage<ScanProgress> {
  type: 'SCAN_PROGRESS';
}

export interface ScanCompleteMessage extends BaseMessage<{ results: ScanResult[]; summary: { totalFindings: number; duration: number } }> {
  type: 'SCAN_COMPLETE';
}

export interface DOMDataMessage extends BaseMessage<{
  scripts: { src?: string; content: string }[];
  forms: { action: string; method: string; inputs: { name: string; type: string }[] }[];
  links: { href: string; rel: string }[];
  meta: { name: string; content: string }[];
  cookies: string;
  localStorage: Record<string, string>;
  sessionStorage: Record<string, string>;
}> {
  type: 'DOM_DATA';
}

export interface ExportReportMessage extends BaseMessage<Vulnerability[]> {
  type: 'EXPORT_REPORT';
  format: 'json' | 'csv' | 'html' | 'markdown' | 'pdf';
}

export type Message<T = any> = StartScanMessage | ScanProgressMessage | ScanCompleteMessage | DOMDataMessage | ExportReportMessage | BaseMessage<T>;