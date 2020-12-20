import { AuthModuleOptions } from 'nestjs-auth-module';
import { UserServiceImplForAuth } from './user-service-implementation';

export function authModuleOptions(): AuthModuleOptions {
  return {
    env: {
      jwtAccessTokenSecret: process.env.JWT_ACCESS_TOKEN_SECRET,
      jwtAccessTokenExpirationTimeMinute: Number(
        process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE,
      ),
      jwtRefreshTokenSecret: process.env.JWT_REFRESH_TOKEN_SECRET,
      jwtRefreshTokenAbsoluteExpirationTimeDay: Number(
        process.env.JWT_REFRESH_TOKEN_ABSOLUTE_EXPIRATION_TIME_DAY,
      ),
      jwtRefreshTokenInactiveExpirationTimeDay: Number(
        process.env.JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY,
      ),
      jwtRefreshTokenMaxNumberIssued: Number(
        process.env.JWT_REFRESH_TOKEN_MAX_NUMBER_ISSUED,
      ),

      facebookClientId: Number(process.env.FACEBOOK_CLIENT_ID),
      facebookClientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      facebookGraphVersion: process.env.FACEBOOK_GRAPH_VERSION,

      isHttpsOnly: process.env.HTTPS_ONLY == 'TRUE',
    },
    userServiceImplementation: UserServiceImplForAuth,
  };
}
