import {
  AuthGuard,
  IAuthModuleOptions,
  PassportStrategy,
} from '@nestjs/passport';
import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import FacebookTokenStrategy, { Profile } from 'passport-facebook-token';
import { Request } from 'express';
import { ENV_OPTIONS } from '../auth.constants';
import { EnvOptions } from '../interfaces/auth-option.interface';
import { nameOf } from '../helpers/types-helper';

const FB_TOKEN = 'facebook-token';

export interface FacebookRequest extends Request {
  facebookProfile: Profile;
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
    // add object to Request
    return profile;
  }
}

@Injectable()
export class FacebookGuard extends AuthGuard(FB_TOKEN) {
  getAuthenticateOptions(): IAuthModuleOptions {
    return {
      property: nameOf<FacebookRequest>('facebookProfile'),
    };
  }

  handleRequest<Profile>(err: Error, profile: Profile): Profile {
    if (err) {
      throw new UnauthorizedException(err);
    } else if (!profile) {
      throw err || new UnauthorizedException('Facebook profile not found');
    }
    return profile;
  }
}
