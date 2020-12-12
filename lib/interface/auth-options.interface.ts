import { ModuleMetadata, Type } from '@nestjs/common';

export interface AuthModuleOptions {
  jwtAccessTokenSecret: string;
  jwtAccessTokenExpirationSeconds: string;
  jwtRefreshTokenSecret: string;
  jwtRefreshTokenExpirationSeconds: string;
}

export interface AuthAsyncModuleOptions
  extends Pick<ModuleMetadata, 'imports'> {
  inject?: any[];
  useClass?: Type<AuthModuleOptionsFactory>;
  useExisting?: Type<AuthModuleOptionsFactory>;
  useFactory?: (
    ...args: any[]
  ) => Promise<AuthModuleOptions> | AuthModuleOptions;
}

export interface AuthModuleOptionsFactory {
  createAuthOptions(): Promise<AuthModuleOptions> | AuthModuleOptions;
}
