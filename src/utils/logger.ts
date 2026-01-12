type LogLevel = 'debug' | 'info' | 'warn' | 'error';

class Logger {
  private static instance: Logger;
  private debugMode = false;

  static getInstance(): Logger {
    if (!Logger.instance) Logger.instance = new Logger();
    return Logger.instance;
  }

  setDebugMode(enabled: boolean) { this.debugMode = enabled; }

  private log(level: LogLevel, module: string, message: string, data?: any) {
    const prefix = `[VaultGuard][${module}]`;
    if (level === 'debug' && !this.debugMode) return;
    console[level](`${prefix}`, message, data || '');
  }

  debug(module: string, message: string, data?: any) { this.log('debug', module, message, data); }
  info(module: string, message: string, data?: any) { this.log('info', module, message, data); }
  warn(module: string, message: string, data?: any) { this.log('warn', module, message, data); }
  error(module: string, message: string, data?: any) { this.log('error', module, message, data); }
}

export const logger = Logger.getInstance();