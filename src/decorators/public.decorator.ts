import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic';

/**
 * Marks a route as public (no JWT required).
 * Use on login, register, refresh, forgot-password, reset-password.
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
