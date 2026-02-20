import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

/**
 * Audit action types for logging sensitive operations.
 */
export enum AuditAction {
  LOGIN_SUCCESS = 'LOGIN_SUCCESS',
  LOGIN_FAILED = 'LOGIN_FAILED',
  LOGOUT = 'LOGOUT',
  REGISTER = 'REGISTER',
  PASSWORD_CHANGE = 'PASSWORD_CHANGE',
  PASSWORD_RESET_REQUEST = 'PASSWORD_RESET_REQUEST',
  PASSWORD_RESET_COMPLETE = 'PASSWORD_RESET_COMPLETE',
  REFRESH_TOKEN = 'REFRESH_TOKEN',
  ACCOUNT_LOCKED = 'ACCOUNT_LOCKED',
}

export type AuditLogDocument = AuditLog & Document;

@Schema({ collection: 'audit_logs', timestamps: { createdAt: true, updatedAt: false } })
export class AuditLog {
  @Prop({ type: String, default: null })
  userId: string | null;

  @Prop({ required: true, enum: AuditAction })
  action: AuditAction;

  @Prop({ type: String, default: null })
  ip: string | null;

  @Prop({ type: String, default: null })
  userAgent: string | null;

  @Prop({ type: Object, default: null })
  metadata: Record<string, unknown> | null;

  createdAt: Date;
}

export const AuditLogSchema = SchemaFactory.createForClass(AuditLog);

AuditLogSchema.virtual('id').get(function () {
  return this._id.toHexString();
});
