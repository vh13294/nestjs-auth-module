import { ExtractJwt, Strategy } from 'passport-jwt';
import {
  AuthGuard,
  IAuthModuleOptions,
  PassportStrategy,
} from '@nestjs/passport';
import { Inject, Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import {
  AuthRequest,
  UserInRequest,
} from '../interfaces/auth-request.interface';
import { TokenPayload } from '../interfaces/token-payload.interface';
import { ENV_OPTIONS } from '../auth.constants';
import { EnvOptions } from '../interfaces/auth-option.interface';
import { nameOf } from '../helpers/types-helper';

const JWT_ACCESS_TOKEN = 'jwt-access-token';

@Injectable()
export class JwtAccessTokenStrategy extends PassportStrategy(
  Strategy,
  JWT_ACCESS_TOKEN,
) {
  constructor(
    @Inject(ENV_OPTIONS)
    readonly env: EnvOptions,
    private readonly authService: AuthService,
  ) {
    super({
      secretOrKey: env.jwtAccessTokenSecret,
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return (request as AuthRequest).cookies.Authentication;
        },
      ]),
    });
  }

  async validate(payload: TokenPayload): Promise<UserInRequest> {
    return this.authService.jwtAccessStrategy(payload.userId);
  }
}

@Injectable()
export class JwtAuthAccessGuard extends AuthGuard(JWT_ACCESS_TOKEN) {
  getAuthenticateOptions(): IAuthModuleOptions {
    return {
      property: nameOf<AuthRequest>('authUser'),
    };
  }
}
