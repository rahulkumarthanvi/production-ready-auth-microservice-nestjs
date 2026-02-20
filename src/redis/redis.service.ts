import { Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { CACHE_KEYS } from '../common/constants';

/**
 * Redis client service for blacklist, cache, and rate limiting.
 * Connects on module init and quits on shutdown.
 */
@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private client: Redis | null = null;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    this.client = new Redis({
      host: this.config.get<string>('redis.host'),
      port: this.config.get<number>('redis.port'),
      password: this.config.get<string>('redis.password') || undefined,
      db: this.config.get<number>('redis.db'),
    });
  }

  async onModuleDestroy(): Promise<void> {
    if (this.client) {
      await this.client.quit();
      this.client = null;
    }
  }

  getClient(): Redis {
    if (!this.client) throw new Error('Redis client not initialized');
    return this.client;
  }

  async get(key: string): Promise<string | null> {
    return this.getClient().get(key);
  }

  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds != null) {
      await this.getClient().setex(key, ttlSeconds, value);
    } else {
      await this.getClient().set(key, value);
    }
  }

  async del(key: string): Promise<void> {
    await this.getClient().del(key);
  }

  async exists(key: string): Promise<boolean> {
    return (await this.getClient().exists(key)) === 1;
  }

  async setBlacklistToken(jti: string, ttlSeconds: number): Promise<void> {
    await this.set(CACHE_KEYS.BLACKLIST_PREFIX + jti, '1', ttlSeconds);
  }

  async isTokenBlacklisted(jti: string): Promise<boolean> {
    return this.exists(CACHE_KEYS.BLACKLIST_PREFIX + jti);
  }

  async getCachedUserProfile(userId: string): Promise<string | null> {
    return this.get(CACHE_KEYS.USER_PROFILE(userId));
  }

  async setCachedUserProfile(userId: string, json: string, ttlSeconds: number): Promise<void> {
    await this.set(CACHE_KEYS.USER_PROFILE(userId), json, ttlSeconds);
  }

  async invalidateUserProfile(userId: string): Promise<void> {
    await this.del(CACHE_KEYS.USER_PROFILE(userId));
  }

  async incr(key: string): Promise<number> {
    return this.getClient().incr(key);
  }

  async expire(key: string, seconds: number): Promise<void> {
    await this.getClient().expire(key, seconds);
  }
}
