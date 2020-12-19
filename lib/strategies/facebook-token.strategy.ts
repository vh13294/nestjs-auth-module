import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import {
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import FacebookTokenStrategy, { Profile } from 'passport-facebook-token';
import { Request } from 'express';

const FB_TOKEN = 'facebook-token';

export interface FacebookRequest extends Request {
  user: Profile;
}

@Injectable()
export class FacebookStrategy extends PassportStrategy(
  FacebookTokenStrategy,
  FB_TOKEN,
) {
  constructor() {
    super({
      clientID: '1',
      clientSecret: '1',
      fbGraphVersion: 'v9.0',
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    _done: Function,
  ) {
    return profile;
  }
}

@Injectable()
export class FacebookGuard extends AuthGuard(FB_TOKEN) {
  canActivate(context: ExecutionContext) {
    // ?access_token='123' query
    return super.canActivate(context);
  }

  handleRequest(err: any, profile: any) {
    if (err || !profile) {
      throw err || new UnauthorizedException(err.message);
    }
    // append { user: profile } to request
    return profile;
  }
}
