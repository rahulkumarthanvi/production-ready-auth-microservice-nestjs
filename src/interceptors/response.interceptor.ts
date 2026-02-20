import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiResponse } from '../common/interfaces/response.interface';

/**
 * Transforms all controller responses into the standard API format.
 * Wraps data in { success, message, data, timestamp }.
 */
@Injectable()
export class ResponseInterceptor<T> implements NestInterceptor<T, ApiResponse<T>> {
  intercept(context: ExecutionContext, next: CallHandler): Observable<ApiResponse<T>> {
    return next.handle().pipe(
      map((data: unknown) => {
        const response = context.switchToHttp().getResponse();
        const statusCode = response.statusCode;
        const success = statusCode >= 200 && statusCode < 300;

        const body: ApiResponse<T> = {
          success,
          message:
            typeof data === 'object' && data !== null && 'message' in (data as object)
              ? (data as { message: string }).message
              : success
                ? 'Success'
                : 'Error',
          data: this.extractData(data),
          timestamp: new Date().toISOString(),
        };

        return body;
      }),
    );
  }

  private extractData(data: unknown): T | null {
    if (data == null) return null;
    if (typeof data === 'object' && 'data' in (data as object))
      return (data as { data: T }).data as T;
    return data as T;
  }
}
