import { ExtractJwt, Strategy } from 'passport-jwt';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { AuthRequest } from '../interfaces/auth-request.interface';
import { TokenPayload } from '../interfaces/token-payload.interface';

const JWT_ACCESS_TOKEN = 'jwt-access-token';

@Injectable()
export class JwtAccessTokenStrategy extends PassportStrategy(
  Strategy,
  JWT_ACCESS_TOKEN,
) {
  constructor(private readonly authService: AuthService) {
    super({
      secretOrKey: process.env.JWT_ACCESS_TOKEN_SECRET,
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return (request as AuthRequest).cookies.Authentication;
        },
      ]),
    });
  }

  async validate(payload: TokenPayload) {
    return this.authService.jwtAccessStrategy(payload.userId);
  }
}

@Injectable()
export class JwtAuthAccessGuard extends AuthGuard(JWT_ACCESS_TOKEN) {}
