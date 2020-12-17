import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { AuthRequest } from '../interfaces/auth-request.interface';
import { TokenPayload } from '../interfaces/token-payload.interface';

const JWT_REFRESH_TOKEN = 'jwt-refresh-token';

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(
  Strategy,
  JWT_REFRESH_TOKEN,
) {
  constructor(private readonly authService: AuthService) {
    super({
      passReqToCallback: true,
      secretOrKey: process.env.JWT_REFRESH_TOKEN_SECRET,
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return (request as AuthRequest).cookies.Refresh;
        },
      ]),
    });
  }

  async validate(request: AuthRequest, payload: TokenPayload) {
    return this.authService.jwtRefreshStrategy(request.cookies, payload.userId);
  }
}

@Injectable()
export class JwtAuthRefreshGuard extends AuthGuard(JWT_REFRESH_TOKEN) {}
