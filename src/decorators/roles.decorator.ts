import { SetMetadata } from '@nestjs/common';
import { UserRole } from '../database/schemas/user.schema';

export const ROLES_KEY = 'roles';

/**
 * Decorator to restrict route access by role.
 * Use with RolesGuard for RBAC.
 *
 * @example
 * @Roles(UserRole.ADMIN)
 * @Get('admin-only')
 * adminOnly() {}
 */
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
