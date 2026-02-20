import { Injectable } from '@nestjs/common';
import * as winston from 'winston';
import { ConfigService } from '@nestjs/config';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Winston-based application logger.
 * Writes to console and error log file; used for auth attempts and errors.
 */
@Injectable()
export class AppLoggerService {
  private readonly logger: winston.Logger;

  constructor(private readonly config: ConfigService) {
    const nodeEnv = this.config.get<string>('nodeEnv');
    const logDir = process.env.LOG_DIR || 'logs';
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    this.logger = winston.createLogger({
      level: nodeEnv === 'production' ? 'info' : 'debug',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json(),
      ),
      defaultMeta: { service: 'auth-microservice' },
      transports: [
        new winston.transports.Console({
          format: winston.format.combine(winston.format.colorize(), winston.format.simple()),
        }),
        new winston.transports.File({
          filename: path.join(logDir, 'error.log'),
          level: 'error',
        }),
      ],
    });
  }

  log(message: string, meta?: Record<string, unknown>): void {
    this.logger.info(message, meta);
  }

  error(message: string, trace?: string, meta?: Record<string, unknown>): void {
    this.logger.error(message, { trace, ...meta });
  }

  warn(message: string, meta?: Record<string, unknown>): void {
    this.logger.warn(message, meta);
  }

  debug(message: string, meta?: Record<string, unknown>): void {
    this.logger.debug(message, meta);
  }

  authAttempt(email: string, success: boolean, meta?: Record<string, unknown>): void {
    this.logger.info(success ? 'Login success' : 'Login failed', {
      event: 'auth_attempt',
      email,
      success,
      ...meta,
    });
  }

  suspiciousActivity(message: string, meta: Record<string, unknown>): void {
    this.logger.warn(message, { event: 'suspicious_activity', ...meta });
  }
}
