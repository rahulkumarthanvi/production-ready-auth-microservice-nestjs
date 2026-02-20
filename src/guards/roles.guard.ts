import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../decorators/roles.decorator';
import { JwtPayload } from '../decorators/current-user.decorator';
import { UserRole } from '../database/schemas/user.schema';

/**
 * RBAC guard. Allows access only if user's role is in the @Roles() list.
 * Must be used after JwtAuthGuard so request.user is set.
 */
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles?.length) return true;

    const { user } = context.switchToHttp().getRequest<{ user: JwtPayload }>();
    const role = user?.role as UserRole;
    const allowed = requiredRoles.some((r) => r === role);
    if (!allowed) throw new ForbiddenException('Insufficient permissions');
    return true;
  }
}
