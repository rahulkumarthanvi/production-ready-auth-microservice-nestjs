import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as crypto from 'crypto';
import { RefreshToken, RefreshTokenDocument } from '../database/schemas/refresh-token.schema';
import {
  PasswordResetToken,
  PasswordResetTokenDocument,
} from '../database/schemas/password-reset-token.schema';

/**
 * Token persistence: refresh tokens and password reset tokens.
 * Hashes stored in DB; rotation by deleting old and creating new.
 */
@Injectable()
export class TokensService {
  constructor(
    @InjectModel(RefreshToken.name)
    private readonly refreshTokenModel: Model<RefreshTokenDocument>,
    @InjectModel(PasswordResetToken.name)
    private readonly passwordResetModel: Model<PasswordResetTokenDocument>,
  ) {}

  hashToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  async createRefreshToken(
    userId: string,
    tokenHash: string,
    expiresAt: Date,
  ): Promise<RefreshTokenDocument> {
    const doc = await this.refreshTokenModel.create({ userId, tokenHash, expiresAt });
    return doc;
  }

  async findRefreshTokenByHash(tokenHash: string): Promise<RefreshTokenDocument | null> {
    return this.refreshTokenModel.findOne({ tokenHash }).populate('userId').exec();
  }

  async deleteRefreshToken(id: string): Promise<void> {
    await this.refreshTokenModel.findByIdAndDelete(id).exec();
  }

  async deleteAllRefreshTokensForUser(userId: string): Promise<void> {
    await this.refreshTokenModel.deleteMany({ userId }).exec();
  }

  async invalidateRefreshTokenByHash(tokenHash: string): Promise<void> {
    await this.refreshTokenModel.deleteOne({ tokenHash }).exec();
  }

  async createPasswordResetToken(
    userId: string,
    tokenHash: string,
    expiresAt: Date,
  ): Promise<PasswordResetTokenDocument> {
    const doc = await this.passwordResetModel.create({ userId, tokenHash, expiresAt });
    return doc;
  }

  async findPasswordResetTokenByHash(
    tokenHash: string,
  ): Promise<PasswordResetTokenDocument | null> {
    return this.passwordResetModel.findOne({ tokenHash, usedAt: null }).populate('userId').exec();
  }

  async markPasswordResetTokenUsed(id: string): Promise<void> {
    await this.passwordResetModel.findByIdAndUpdate(id, { usedAt: new Date() }).exec();
  }

  async deleteExpiredRefreshTokens(): Promise<void> {
    await this.refreshTokenModel.deleteMany({ expiresAt: { $lt: new Date() } }).exec();
  }
}
