import { AuthModuleOptions } from 'nestjs-auth-module';

export function authModuleOptions(): AuthModuleOptions {
  return {
    jwtAccessTokenSecret: '1',
    jwtAccessTokenExpirationSeconds: '1',
    jwtRefreshTokenSecret: '1',
    jwtRefreshTokenExpirationSeconds: '1',
  };
}
