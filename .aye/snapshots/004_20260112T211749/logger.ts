export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

class Logger {
  private static instance: Logger;
  private enabled = true;
  private minLevel: LogLevel = 'info';
  private readonly levelPriority: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };
  private readonly levelColors: Record<LogLevel, string> = { debug: '#6B7280', info: '#3B82F6', warn: '#F59E0B', error: '#EF4444' };

  static getInstance(): Logger {
    if (!Logger.instance) Logger.instance = new Logger();
    return Logger.instance;
  }

  private shouldLog(level: LogLevel): boolean {
    return this.enabled && this.levelPriority[level] >= this.levelPriority[this.minLevel];
  }

  private log(level: LogLevel, source: string, message: string, data?: unknown): void {
    if (!this.shouldLog(level)) return;
    const formatted = `[VaultGuard:${source}] ${message}`;
    const style = `color: ${this.levelColors[level]}; font-weight: bold;`;
    if (level === 'debug') console.debug(`%c${formatted}`, style, data ?? '');
    else if (level === 'info') console.info(`%c${formatted}`, style, data ?? '');
    else if (level === 'warn') console.warn(`%c${formatted}`, style, data ?? '');
    else console.error(`%c${formatted}`, style, data ?? '');
  }

  debug(source: string, message: string, data?: unknown): void { this.log('debug', source, message, data); }
  info(source: string, message: string, data?: unknown): void { this.log('info', source, message, data); }
  warn(source: string, message: string, data?: unknown): void { this.log('warn', source, message, data); }
  error(source: string, message: string, data?: unknown): void { this.log('error', source, message, data); }
}

export const logger = Logger.getInstance();
export default logger;