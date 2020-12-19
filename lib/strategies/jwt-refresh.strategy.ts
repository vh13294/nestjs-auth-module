import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { AuthRequest } from '../interfaces/auth-request.interface';
import { TokenPayload } from '../interfaces/token-payload.interface';
import { ENV_OPTIONS } from '../auth.constants';
import { EnvOptions } from '../interfaces/auth-option.interface';

const JWT_REFRESH_TOKEN = 'jwt-refresh-token';

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(
  Strategy,
  JWT_REFRESH_TOKEN,
) {
  constructor(
    @Inject(ENV_OPTIONS)
    readonly env: EnvOptions,
    private readonly authService: AuthService,
  ) {
    super({
      passReqToCallback: true,
      secretOrKey: env.jwtRefreshTokenSecret,
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
