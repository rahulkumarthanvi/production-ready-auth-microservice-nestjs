/**
 * Application-wide constants.
 */

export const CACHE_KEYS = {
  USER_PROFILE: (userId: string) => `user:profile:${userId}`,
  BLACKLIST_PREFIX: 'blacklist:token:',
} as const;

export const CACHE_TTL = {
  USER_PROFILE_SECONDS: 300, // 5 minutes
} as const;
