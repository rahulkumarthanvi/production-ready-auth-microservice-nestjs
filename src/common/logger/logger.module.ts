import { Global, Module } from '@nestjs/common';
import { AppLoggerService } from './logger.service';

/**
 * Global Winston logger module.
 * Injects AppLoggerService for structured logging (auth, errors, etc.).
 */
@Global()
@Module({
  providers: [AppLoggerService],
  exports: [AppLoggerService],
})
export class LoggerModule {}
