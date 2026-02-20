import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { JwtPayload } from '../decorators/current-user.decorator';
import { RedisService } from '../redis/redis.service';
import { CACHE_KEYS } from '../common/constants';

interface PayloadWithJti extends JwtPayload {
  jti?: string;
}

/**
 * Passport JWT strategy for access token validation.
 * Validates signature, expiry, and blacklist; attaches payload to request.user.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly config: ConfigService,
    private readonly redis: RedisService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: config.get<string>('jwt.accessSecret'),
    });
  }

  async validate(payload: PayloadWithJti): Promise<JwtPayload> {
    if (payload.type !== 'access') {
      throw new UnauthorizedException('Invalid token type');
    }
    if (payload.jti) {
      const blacklisted = await this.redis.exists(CACHE_KEYS.BLACKLIST_PREFIX + payload.jti);
      if (blacklisted) throw new UnauthorizedException('Token has been revoked');
    }
    return payload;
  }
}
