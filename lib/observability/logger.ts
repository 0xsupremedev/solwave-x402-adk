export enum LogLevel {
  DEBUG = 'debug',
  INFO = 'info',
  WARN = 'warn',
  ERROR = 'error',
}

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: Date;
  metadata?: Record<string, any>;
  userId?: string;
  agentId?: string;
  invoiceId?: string;
}

class Logger {
  private logs: LogEntry[] = [];
  private maxLogs: number = 1000;

  log(entry: LogEntry) {
    this.logs.push(entry);
    
    // Keep only recent logs
    if (this.logs.length > this.maxLogs) {
      this.logs = this.logs.slice(-this.maxLogs);
    }

    // In production, send to logging service
    if (process.env.NODE_ENV === 'production') {
      // Send to external logging service (e.g., Sentry, LogRocket)
      console.log(entry);
    } else {
      console.log(`[${entry.level.toUpperCase()}]`, entry.message, entry.metadata || '');
    }
  }

  debug(message: string, metadata?: Record<string, any>) {
    this.log({
      level: LogLevel.DEBUG,
      message,
      timestamp: new Date(),
      metadata,
    });
  }

  info(message: string, metadata?: Record<string, any>) {
    this.log({
      level: LogLevel.INFO,
      message,
      timestamp: new Date(),
      metadata,
    });
  }

  warn(message: string, metadata?: Record<string, any>) {
    this.log({
      level: LogLevel.WARN,
      message,
      timestamp: new Date(),
      metadata,
    });
  }

  error(message: string, metadata?: Record<string, any>) {
    this.log({
      level: LogLevel.ERROR,
      message,
      timestamp: new Date(),
      metadata,
    });
  }

  getLogs(filters?: {
    level?: LogLevel;
    userId?: string;
    agentId?: string;
    invoiceId?: string;
    limit?: number;
  }): LogEntry[] {
    let filtered = this.logs;

    if (filters?.level) {
      filtered = filtered.filter((log) => log.level === filters.level);
    }
    if (filters?.userId) {
      filtered = filtered.filter((log) => log.userId === filters.userId);
    }
    if (filters?.agentId) {
      filtered = filtered.filter((log) => log.agentId === filters.agentId);
    }
    if (filters?.invoiceId) {
      filtered = filtered.filter((log) => log.invoiceId === filters.invoiceId);
    }

    if (filters?.limit) {
      filtered = filtered.slice(-filters.limit);
    }

    return filtered;
  }
}

export const logger = new Logger();

