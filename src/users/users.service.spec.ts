import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { NotFoundException } from '@nestjs/common';
import { UsersService } from './users.service';
import { User } from '../database/schemas/user.schema';
import { RedisService } from '../redis/redis.service';
import { AppLoggerService } from '../common/logger/logger.service';
import { UserRole } from '../database/schemas/user.schema';

describe('UsersService', () => {
  let service: UsersService;
  let userModel: { findOne: jest.Mock; findById: jest.Mock };
  let redis: {
    getCachedUserProfile: jest.Mock;
    setCachedUserProfile: jest.Mock;
    invalidateUserProfile: jest.Mock;
  };

  const mockUser = {
    id: 'user-1',
    email: 'user@example.com',
    passwordHash: 'hashed',
    role: UserRole.USER,
    isEmailVerified: false,
    failedLoginAttempts: 0,
    lockedUntil: null,
    createdAt: new Date('2024-01-01'),
    updatedAt: new Date('2024-01-01'),
  };

  beforeEach(async () => {
    userModel = {
      findOne: jest.fn().mockReturnValue({ exec: jest.fn() }),
      findById: jest.fn().mockReturnValue({ exec: jest.fn() }),
    };
    redis = {
      getCachedUserProfile: jest.fn(),
      setCachedUserProfile: jest.fn(),
      invalidateUserProfile: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        UsersService,
        { provide: getModelToken(User.name), useValue: userModel },
        { provide: RedisService, useValue: redis },
        { provide: AppLoggerService, useValue: { log: jest.fn() } },
      ],
    }).compile();

    service = module.get<UsersService>(UsersService);
  });

  describe('findByEmail', () => {
    it('should return user when found', async () => {
      userModel.findOne.mockReturnValue({ exec: jest.fn().mockResolvedValue(mockUser) });

      const result = await service.findByEmail('user@example.com');

      expect(userModel.findOne).toHaveBeenCalledWith({ email: 'user@example.com' });
      expect(result).toEqual(mockUser);
    });

    it('should return null when not found', async () => {
      userModel.findOne.mockReturnValue({ exec: jest.fn().mockResolvedValue(null) });

      const result = await service.findByEmail('unknown@example.com');

      expect(result).toBeNull();
    });
  });

  describe('findById', () => {
    it('should return user when found', async () => {
      userModel.findById.mockReturnValue({ exec: jest.fn().mockResolvedValue(mockUser) });

      const result = await service.findById('user-1');

      expect(userModel.findById).toHaveBeenCalledWith('user-1');
      expect(result).toEqual(mockUser);
    });

    it('should return null when not found', async () => {
      userModel.findById.mockReturnValue({ exec: jest.fn().mockResolvedValue(null) });

      const result = await service.findById('unknown');

      expect(result).toBeNull();
    });
  });

  describe('getProfile', () => {
    it('should return cached profile when available', async () => {
      const cached = {
        id: mockUser.id,
        email: mockUser.email,
        role: mockUser.role,
        isEmailVerified: mockUser.isEmailVerified,
        createdAt: mockUser.createdAt.toISOString(),
        updatedAt: mockUser.updatedAt.toISOString(),
      };
      redis.getCachedUserProfile.mockResolvedValue(JSON.stringify(cached));

      const result = await service.getProfile('user-1');

      expect(result).toEqual(cached);
      expect(userModel.findById).not.toHaveBeenCalled();
    });

    it('should fetch from DB and cache when cache miss', async () => {
      redis.getCachedUserProfile.mockResolvedValue(null);
      userModel.findById.mockReturnValue({ exec: jest.fn().mockResolvedValue(mockUser) });

      const result = await service.getProfile('user-1');

      expect(result.id).toBe(mockUser.id);
      expect(result.email).toBe(mockUser.email);
      expect(result.role).toBe(mockUser.role);
      expect(redis.setCachedUserProfile).toHaveBeenCalledWith(
        'user-1',
        expect.any(String),
        expect.any(Number),
      );
    });

    it('should throw NotFoundException when user does not exist', async () => {
      redis.getCachedUserProfile.mockResolvedValue(null);
      userModel.findById.mockReturnValue({ exec: jest.fn().mockResolvedValue(null) });

      await expect(service.getProfile('unknown')).rejects.toThrow(NotFoundException);
    });
  });

  describe('invalidateProfileCache', () => {
    it('should call redis invalidateUserProfile', async () => {
      await service.invalidateProfileCache('user-1');

      expect(redis.invalidateUserProfile).toHaveBeenCalledWith('user-1');
    });
  });
});
