import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from '../auth.service';
import { AuthRequest } from '../interfaces/auth-request.interface';

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(
  Strategy,
  'jwt-refresh-token',
) {
  constructor(private readonly authService: AuthService) {
    super({
      passReqToCallback: true,
      secretOrKey: process.env.JWT_REFRESH_TOKEN_SECRET,
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request: Request) => {
          return request?.cookies?.Refresh;
        },
      ]),
    });
  }

  async validate(request: AuthRequest, payload: TokenPayload) {
    return this.authService.getUserIfRefreshTokenMatches(
      request.cookies?.Refresh,
      request.cookies?.DeviceId,
      payload.userId,
    );
  }
}
