export interface AuthModuleOptions {
  jwtAccessTokenSecret: string;
  jwtAccessTokenExpirationSeconds: string;
  jwtRefreshTokenSecret: string;
  jwtRefreshTokenExpirationSeconds: string;
}
