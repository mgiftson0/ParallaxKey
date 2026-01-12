/**
 * VaultGuard Logger Utility
 * Provides consistent logging across the extension
 */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  level: LogLevel;
  message: string;
  data?: unknown;
  timestamp: number;
  component: string;
}

class Logger {
  private static instance: Logger;
  private logLevel: LogLevel = 'info';
  private logs: LogEntry[] = [];
  private maxLogs = 1000;
  private isDev = false;

  private constructor() {
    this.isDev = !('update_url' in chrome.runtime.getManifest());
    this.logLevel = this.isDev ? 'debug' : 'info';
  }

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  setLevel(level: LogLevel): void {
    this.logLevel = level;
  }

  private shouldLog(level: LogLevel): boolean {
    const levels: LogLevel[] = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.logLevel);
  }

  private formatMessage(component: string, message: string): string {
    const timestamp = new Date().toISOString();
    return `[VaultGuard][${timestamp}][${component}] ${message}`;
  }

  private log(level: LogLevel, component: string, message: string, data?: unknown): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      level,
      message,
      data,
      timestamp: Date.now(),
      component,
    };

    this.logs.push(entry);
    if (this.logs.length > this.maxLogs) {
      this.logs.shift();
    }

    const formattedMessage = this.formatMessage(component, message);

    switch (level) {
      case 'debug':
        console.debug(formattedMessage, data ?? '');
        break;
      case 'info':
        console.info(formattedMessage, data ?? '');
        break;
      case 'warn':
        console.warn(formattedMessage, data ?? '');
        break;
      case 'error':
        console.error(formattedMessage, data ?? '');
        break;
    }
  }

  debug(component: string, message: string, data?: unknown): void {
    this.log('debug', component, message, data);
  }

  info(component: string, message: string, data?: unknown): void {
    this.log('info', component, message, data);
  }

  warn(component: string, message: string, data?: unknown): void {
    this.log('warn', component, message, data);
  }

  error(component: string, message: string, data?: unknown): void {
    this.log('error', component, message, data);
  }

  getLogs(level?: LogLevel, component?: string): LogEntry[] {
    return this.logs.filter((entry) => {
      if (level && entry.level !== level) return false;
      if (component && entry.component !== component) return false;
      return true;
    });
  }

  clearLogs(): void {
    this.logs = [];
  }

  exportLogs(): string {
    return JSON.stringify(this.logs, null, 2);
  }
}

export const logger = Logger.getInstance();
export default logger;