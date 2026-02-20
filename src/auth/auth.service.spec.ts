import { Test, TestingModule } from '@nestjs/testing';
import { getModelToken } from '@nestjs/mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { ConflictException, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { AuthService } from './auth.service';
import { User } from '../database/schemas/user.schema';
import { AuditLog } from '../database/schemas/audit-log.schema';
import { UsersService } from '../users/users.service';
import { TokensService } from '../tokens/tokens.service';
import { RedisService } from '../redis/redis.service';
import { AppLoggerService } from '../common/logger/logger.service';
import { UserRole } from '../database/schemas/user.schema';

describe('AuthService', () => {
  let service: AuthService;
  let userModel: { create: jest.Mock };
  let auditModel: { create: jest.Mock };
  let usersService: {
    findByEmail: jest.Mock;
    findById: jest.Mock;
    invalidateProfileCache: jest.Mock;
  };
  let tokensService: {
    hashToken: jest.Mock;
    createRefreshToken: jest.Mock;
    findRefreshTokenByHash: jest.Mock;
    deleteRefreshToken: jest.Mock;
    invalidateRefreshTokenByHash: jest.Mock;
    deleteAllRefreshTokensForUser: jest.Mock;
    createPasswordResetToken: jest.Mock;
    findPasswordResetTokenByHash: jest.Mock;
    markPasswordResetTokenUsed: jest.Mock;
  };
  let jwtService: { sign: jest.Mock; decode: jest.Mock };
  let config: ConfigService;
  let redis: { setBlacklistToken: jest.Mock };

  const mockUser = {
    id: 'user-1',
    email: 'user@example.com',
    passwordHash: 'hashed',
    role: UserRole.USER,
    isEmailVerified: false,
    failedLoginAttempts: 0,
    lockedUntil: null,
    createdAt: new Date(),
    updatedAt: new Date(),
    save: jest.fn().mockResolvedValue(undefined),
  };

  beforeEach(async () => {
    userModel = { create: jest.fn() };
    auditModel = { create: jest.fn().mockResolvedValue({}) };
    usersService = {
      findByEmail: jest.fn(),
      findById: jest.fn(),
      invalidateProfileCache: jest.fn(),
    };
    tokensService = {
      hashToken: jest.fn((t: string) => `hash-${t}`),
      createRefreshToken: jest.fn(),
      findRefreshTokenByHash: jest.fn(),
      deleteRefreshToken: jest.fn(),
      invalidateRefreshTokenByHash: jest.fn(),
      deleteAllRefreshTokensForUser: jest.fn(),
      createPasswordResetToken: jest.fn(),
      findPasswordResetTokenByHash: jest.fn(),
      markPasswordResetTokenUsed: jest.fn(),
    };
    jwtService = {
      sign: jest.fn().mockReturnValue('jwt-token'),
      decode: jest.fn().mockReturnValue({ exp: Math.floor(Date.now() / 1000) + 900 }),
    };
    config = {
      get: jest.fn((key: string) => {
        const map: Record<string, string | number> = {
          'bcrypt.saltRounds': 10,
          'jwt.accessSecret': 'access-secret',
          'jwt.accessExpiresIn': '15m',
          'jwt.refreshSecret': 'refresh-secret',
          'jwt.refreshExpiresIn': '7d',
          'security.maxLoginAttempts': 5,
          'security.lockoutDurationMinutes': 15,
          'security.passwordResetTokenExpiryMinutes': 60,
        };
        return map[key];
      }),
    } as unknown as ConfigService;
    redis = { setBlacklistToken: jest.fn() };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: getModelToken(User.name), useValue: userModel },
        { provide: getModelToken(AuditLog.name), useValue: auditModel },
        { provide: UsersService, useValue: usersService },
        { provide: TokensService, useValue: tokensService },
        { provide: JwtService, useValue: jwtService },
        { provide: ConfigService, useValue: config },
        { provide: RedisService, useValue: redis },
        {
          provide: AppLoggerService,
          useValue: { log: jest.fn(), authAttempt: jest.fn(), suspiciousActivity: jest.fn() },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashed' as never);
    jest.spyOn(bcrypt, 'compare').mockResolvedValue(true as never);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe('register', () => {
    it('should register a new user and return user and tokens', async () => {
      usersService.findByEmail.mockResolvedValue(null);
      userModel.create.mockResolvedValue(mockUser);

      const result = await service.register({
        email: 'new@example.com',
        password: 'SecureP@ss1',
      });

      expect(usersService.findByEmail).toHaveBeenCalledWith('new@example.com');
      expect(userModel.create).toHaveBeenCalled();
      expect(result.user).toBeDefined();
      expect(result.tokens).toHaveProperty('accessToken');
      expect(result.tokens).toHaveProperty('refreshToken');
    });

    it('should throw ConflictException when email already exists', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);

      await expect(
        service.register({ email: 'user@example.com', password: 'SecureP@ss1' }),
      ).rejects.toThrow(ConflictException);
    });
  });

  describe('login', () => {
    it('should return user and tokens on valid credentials', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);

      const result = await service.login('user@example.com', 'password');

      expect(result.user).toEqual(mockUser);
      expect(result.tokens.accessToken).toBe('jwt-token');
    });

    it('should throw UnauthorizedException when user not found', async () => {
      usersService.findByEmail.mockResolvedValue(null);

      await expect(service.login('unknown@example.com', 'pass')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw UnauthorizedException when password is wrong', async () => {
      usersService.findByEmail.mockResolvedValue(mockUser);
      (bcrypt.compare as jest.Mock).mockResolvedValue(false);
      mockUser.save.mockResolvedValue({ ...mockUser, failedLoginAttempts: 1 });

      await expect(service.login('user@example.com', 'wrong')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw ForbiddenException when account is locked', async () => {
      const lockedUser = {
        ...mockUser,
        lockedUntil: new Date(Date.now() + 60000),
      };
      usersService.findByEmail.mockResolvedValue(lockedUser);

      await expect(service.login('user@example.com', 'pass')).rejects.toThrow(ForbiddenException);
    });
  });

  describe('refresh', () => {
    it('should return new token pair when refresh token is valid', async () => {
      tokensService.findRefreshTokenByHash.mockResolvedValue({
        id: 'rt-1',
        userId: { id: mockUser.id },
        expiresAt: new Date(Date.now() + 86400),
      });
      usersService.findById.mockResolvedValue(mockUser);
      tokensService.createRefreshToken.mockResolvedValue({});

      const result = await service.refresh('valid-refresh-token');

      expect(tokensService.invalidateRefreshTokenByHash).toHaveBeenCalled();
      expect(result.accessToken).toBe('jwt-token');
      expect(result.refreshToken).toBeDefined();
    });

    it('should throw UnauthorizedException when refresh token is invalid', async () => {
      tokensService.findRefreshTokenByHash.mockResolvedValue(null);

      await expect(service.refresh('invalid')).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('should call redis setBlacklistToken when token is valid', async () => {
      jwtService.decode.mockReturnValue({
        jti: 'jti-1',
        exp: Math.floor(Date.now() / 1000) + 100,
      });

      await service.logout('Bearer jwt-token');

      expect(redis.setBlacklistToken).toHaveBeenCalledWith('jti-1', expect.any(Number));
    });
  });
});
