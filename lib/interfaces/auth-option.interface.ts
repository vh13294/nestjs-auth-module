import { Type } from '@nestjs/common';
import { IUserService } from './user-service.interface';

export interface AuthModuleOptions {
  env: EnvOptions;
  userServiceImplementation: Type<IUserService>;
}

export interface EnvOptions {
  jwtAccessTokenSecret: string;
  jwtAccessTokenExpirationTimeMinute: number;
  jwtRefreshTokenSecret: string;
  jwtRefreshTokenAbsoluteExpirationTimeDay: number;
  jwtRefreshTokenInactiveExpirationTimeDay: number;
  jwtRefreshTokenMaxNumberIssued: number;

  facebookClientId: number;
  facebookClientSecret: string;
  facebookGraphVersion: string;
}
