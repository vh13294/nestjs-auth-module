import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import FacebookTokenStrategy, { Profile } from 'passport-facebook-token';
import { Request } from 'express';
import { ENV_OPTIONS } from '../auth.constants';
import { EnvOptions } from '../interfaces/auth-option.interface';

const FB_TOKEN = 'facebook-token';

export interface FacebookRequest extends Request {
  user: Profile;
}

@Injectable()
export class FacebookStrategy extends PassportStrategy(
  FacebookTokenStrategy,
  FB_TOKEN,
) {
  constructor(
    @Inject(ENV_OPTIONS)
    readonly env: EnvOptions,
  ) {
    super({
      clientID: env.facebookClientId,
      clientSecret: env.facebookClientSecret,
      fbGraphVersion: env.facebookGraphVersion,
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    // _done: Function,
  ): Promise<Profile> {
    return profile;
  }
}

@Injectable()
export class FacebookGuard extends AuthGuard(FB_TOKEN) {
  // canActivate(context: ExecutionContext) {
  //   // ?access_token='123' query
  //   return super.canActivate(context);
  // }

  handleRequest<Profile>(err: Error, profile: Profile): Profile {
    if (err || !profile) {
      throw err || new UnauthorizedException('Unauthorized FB SDK access');
    }
    // append { user: profile } to request
    return profile;
  }
}
