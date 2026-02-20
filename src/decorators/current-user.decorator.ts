import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Payload attached to JWT and set by Passport strategy.
 */
export interface JwtPayload {
  sub: string;
  email: string;
  role: string;
  type: 'access' | 'refresh';
  iat?: number;
  exp?: number;
}

/**
 * Param decorator to inject the current authenticated user from the request.
 * Use on protected routes after JwtAuthGuard.
 */
export const CurrentUser = createParamDecorator(
  (data: keyof JwtPayload | undefined, ctx: ExecutionContext): JwtPayload | string => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user as JwtPayload;
    if (data) return user?.[data] as string;
    return user;
  },
);
