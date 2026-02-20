import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from '../database/schemas/user.schema';
import { RedisService } from '../redis/redis.service';
import { AppLoggerService } from '../common/logger/logger.service';
import { CACHE_TTL } from '../common/constants';
import { UserResponseDto } from './dto/user-response.dto';

/**
 * User business logic: find by id/email, profile with cache.
 */
@Injectable()
export class UsersService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<UserDocument>,
    private readonly redis: RedisService,
    private readonly logger: AppLoggerService,
  ) {}

  async findByEmail(email: string): Promise<UserDocument | null> {
    return this.userModel.findOne({ email: email.toLowerCase() }).exec();
  }

  async findById(id: string): Promise<UserDocument | null> {
    return this.userModel.findById(id).exec();
  }

  async getProfile(userId: string): Promise<UserResponseDto> {
    const cached = await this.redis.getCachedUserProfile(userId);
    if (cached) {
      try {
        return JSON.parse(cached) as UserResponseDto;
      } catch {
        await this.redis.invalidateUserProfile(userId);
      }
    }

    const user = await this.findById(userId);
    if (!user) throw new NotFoundException('User not found');

    const dto: UserResponseDto = {
      id: user.id,
      email: user.email,
      role: user.role,
      isEmailVerified: user.isEmailVerified,
      createdAt: user.createdAt.toISOString(),
      updatedAt: user.updatedAt.toISOString(),
    };

    await this.redis.setCachedUserProfile(
      userId,
      JSON.stringify(dto),
      CACHE_TTL.USER_PROFILE_SECONDS,
    );
    return dto;
  }

  async invalidateProfileCache(userId: string): Promise<void> {
    await this.redis.invalidateUserProfile(userId);
  }
}
