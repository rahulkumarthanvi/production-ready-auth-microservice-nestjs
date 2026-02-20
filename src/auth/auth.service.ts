import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';
import { User, UserDocument, UserRole } from '../database/schemas/user.schema';
import { AuditAction, AuditLog, AuditLogDocument } from '../database/schemas/audit-log.schema';
import { UsersService } from '../users/users.service';
import { TokensService } from '../tokens/tokens.service';
import { RedisService } from '../redis/redis.service';
import { AppLoggerService } from '../common/logger/logger.service';
import { RegisterDto } from './dto/register.dto';
import { JwtPayload } from '../decorators/current-user.decorator';

/** Token pair returned on login/refresh. */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

/** Parsed JWT payload with jti for blacklisting. */
interface JwtPayloadWithJti extends JwtPayload {
  jti?: string;
}

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name)
    private readonly userModel: Model<UserDocument>,
    @InjectModel(AuditLog.name)
    private readonly auditModel: Model<AuditLogDocument>,
    private readonly usersService: UsersService,
    private readonly tokensService: TokensService,
    private readonly jwtService: JwtService,
    private readonly config: ConfigService,
    private readonly redis: RedisService,
    private readonly logger: AppLoggerService,
  ) {}

  async register(
    dto: RegisterDto,
    ip?: string,
    userAgent?: string,
  ): Promise<{ user: UserDocument; tokens: TokenPair }> {
    const email = dto.email.toLowerCase();
    const existing = await this.usersService.findByEmail(email);
    if (existing) throw new ConflictException('Email already registered');

    const saltRounds = this.config.get<number>('bcrypt.saltRounds') ?? 12;
    const passwordHash = await bcrypt.hash(dto.password, saltRounds);

    const user = await this.userModel.create({
      email,
      passwordHash,
      role: dto.role ?? UserRole.USER,
    });

    await this.audit(AuditAction.REGISTER, user.id, ip, userAgent, { email });
    this.logger.log('User registered', { userId: user.id, email });

    const tokens = await this.issueTokenPair(user);
    return { user, tokens };
  }

  async login(
    email: string,
    password: string,
    ip?: string,
    userAgent?: string,
  ): Promise<{ user: UserDocument; tokens: TokenPair }> {
    const normalizedEmail = email.toLowerCase();
    const user = await this.usersService.findByEmail(normalizedEmail);
    if (!user) {
      await this.audit(AuditAction.LOGIN_FAILED, null, ip, userAgent, { email: normalizedEmail });
      this.logger.authAttempt(normalizedEmail, false, { reason: 'user_not_found' });
      throw new UnauthorizedException('Invalid credentials');
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      this.logger.suspiciousActivity('Login attempt on locked account', {
        email: normalizedEmail,
        userId: user.id,
      });
      await this.audit(AuditAction.ACCOUNT_LOCKED, user.id, ip, userAgent, {});
      throw new ForbiddenException(
        `Account locked. Try again after ${user.lockedUntil.toISOString()}`,
      );
    }

    const valid = await bcrypt.compare(password, user.passwordHash);
    if (!valid) {
      const maxAttempts = this.config.get<number>('security.maxLoginAttempts') ?? 5;
      const lockMinutes = this.config.get<number>('security.lockoutDurationMinutes') ?? 15;
      user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
      if (user.failedLoginAttempts >= maxAttempts) {
        user.lockedUntil = new Date(Date.now() + lockMinutes * 60 * 1000);
        await user.save();
        await this.audit(AuditAction.ACCOUNT_LOCKED, user.id, ip, userAgent, {});
        this.logger.authAttempt(normalizedEmail, false, { reason: 'account_locked' });
        throw new ForbiddenException(
          `Account locked after ${maxAttempts} failed attempts. Try again in ${lockMinutes} minutes.`,
        );
      }
      await user.save();
      await this.audit(AuditAction.LOGIN_FAILED, user.id, ip, userAgent, {});
      this.logger.authAttempt(normalizedEmail, false);
      throw new UnauthorizedException('Invalid credentials');
    }

    user.failedLoginAttempts = 0;
    user.lockedUntil = null;
    await user.save();

    await this.audit(AuditAction.LOGIN_SUCCESS, user.id, ip, userAgent, {});
    this.logger.authAttempt(normalizedEmail, true);

    const tokens = await this.issueTokenPair(user);
    return { user, tokens };
  }

  async logout(accessToken: string): Promise<void> {
    try {
      const decoded = this.jwtService.decode(accessToken) as JwtPayloadWithJti & { exp?: number };
      if (decoded?.jti && decoded.exp) {
        const ttl = Math.max(1, decoded.exp - Math.floor(Date.now() / 1000));
        await this.redis.setBlacklistToken(decoded.jti, ttl);
      }
    } catch {
      // ignore decode errors
    }
  }

  async refresh(refreshToken: string): Promise<TokenPair> {
    const tokenHash = this.tokensService.hashToken(refreshToken);
    const stored = await this.tokensService.findRefreshTokenByHash(tokenHash);
    if (!stored || stored.expiresAt < new Date()) {
      if (stored) await this.tokensService.deleteRefreshToken(stored.id);
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    await this.tokensService.invalidateRefreshTokenByHash(tokenHash);

    const userId =
      typeof stored.userId === 'object' &&
      stored.userId !== null &&
      'id' in stored.userId &&
      typeof (stored.userId as unknown as { id: string }).id === 'string'
        ? (stored.userId as unknown as { id: string }).id
        : String(stored.userId);
    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    const tokens = await this.issueTokenPair(user);
    return tokens;
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ip?: string,
    userAgent?: string,
  ): Promise<void> {
    const user = await this.usersService.findById(userId);
    if (!user) throw new UnauthorizedException('User not found');

    const valid = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!valid) throw new UnauthorizedException('Current password is incorrect');

    const saltRounds = this.config.get<number>('bcrypt.saltRounds') ?? 12;
    user.passwordHash = await bcrypt.hash(newPassword, saltRounds);
    await user.save();

    await this.usersService.invalidateProfileCache(userId);
    await this.tokensService.deleteAllRefreshTokensForUser(userId);
    await this.audit(AuditAction.PASSWORD_CHANGE, userId, ip, userAgent, {});
    this.logger.log('Password changed', { userId });
  }

  async forgotPassword(email: string, ip?: string, userAgent?: string): Promise<{ token: string }> {
    const normalizedEmail = email.toLowerCase();
    const user = await this.usersService.findByEmail(normalizedEmail);
    if (!user) {
      return { token: 'dummy-token-if-no-user' };
    }

    const expiryMinutes = this.config.get<number>('security.passwordResetTokenExpiryMinutes') ?? 60;
    const rawToken = uuidv4();
    const tokenHash = this.tokensService.hashToken(rawToken);
    const expiresAt = new Date(Date.now() + expiryMinutes * 60 * 1000);
    await this.tokensService.createPasswordResetToken(user.id, tokenHash, expiresAt);

    await this.audit(AuditAction.PASSWORD_RESET_REQUEST, user.id, ip, userAgent, {});
    this.logger.log('Password reset requested', { userId: user.id, email: normalizedEmail });

    return { token: rawToken };
  }

  async resetPassword(
    token: string,
    newPassword: string,
    ip?: string,
    userAgent?: string,
  ): Promise<void> {
    const tokenHash = this.tokensService.hashToken(token);
    const stored = await this.tokensService.findPasswordResetTokenByHash(tokenHash);
    if (!stored || stored.expiresAt < new Date()) {
      throw new BadRequestException('Invalid or expired reset token');
    }

    const user =
      typeof stored.userId === 'object' && stored.userId !== null && 'email' in stored.userId
        ? (stored.userId as unknown as UserDocument)
        : await this.usersService.findById(String(stored.userId));
    if (!user) throw new BadRequestException('User not found');

    const saltRounds = this.config.get<number>('bcrypt.saltRounds') ?? 12;
    user.passwordHash = await bcrypt.hash(newPassword, saltRounds);
    await user.save();

    await this.tokensService.markPasswordResetTokenUsed(stored.id);
    await this.usersService.invalidateProfileCache(user.id);
    await this.tokensService.deleteAllRefreshTokensForUser(user.id);
    await this.audit(AuditAction.PASSWORD_RESET_COMPLETE, user.id, ip, userAgent, {});
    this.logger.log('Password reset completed', { userId: user.id });
  }

  async isAccessTokenBlacklisted(jti: string): Promise<boolean> {
    return this.redis.isTokenBlacklisted(jti);
  }

  private async issueTokenPair(user: UserDocument): Promise<TokenPair> {
    const accessSecret = this.config.get<string>('jwt.accessSecret');
    const accessExpiresIn = this.config.get<string>('jwt.accessExpiresIn');
    const refreshSecret = this.config.get<string>('jwt.refreshSecret');
    const refreshExpiresIn = this.config.get<string>('jwt.refreshExpiresIn');

    const accessJti = uuidv4();
    const refreshJti = uuidv4();

    const accessPayload: JwtPayload & { jti: string } = {
      sub: user.id,
      email: user.email,
      role: user.role,
      type: 'access',
      jti: accessJti,
    };
    const accessToken = this.jwtService.sign(accessPayload, {
      secret: accessSecret,
      expiresIn: accessExpiresIn,
    });

    const refreshPayload: JwtPayload & { jti: string } = {
      sub: user.id,
      email: user.email,
      role: user.role,
      type: 'refresh',
      jti: refreshJti,
    };
    const refreshToken = this.jwtService.sign(refreshPayload, {
      secret: refreshSecret,
      expiresIn: refreshExpiresIn,
    });
    const decodedRefresh = this.jwtService.decode(refreshToken) as { exp: number };
    const expiresAt = new Date((decodedRefresh.exp as number) * 1000);
    const refreshHash = this.tokensService.hashToken(refreshToken);
    await this.tokensService.createRefreshToken(user.id, refreshHash, expiresAt);

    const decodedAccess = this.jwtService.decode(accessToken) as { exp: number };
    const expiresIn = (decodedAccess.exp as number) - Math.floor(Date.now() / 1000);

    return { accessToken, refreshToken, expiresIn };
  }

  private async audit(
    action: AuditAction,
    userId: string | null,
    ip?: string,
    userAgent?: string,
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    await this.auditModel.create({
      userId,
      action,
      ip: ip ?? null,
      userAgent: userAgent ?? null,
      metadata: metadata ?? null,
    });
  }
}
