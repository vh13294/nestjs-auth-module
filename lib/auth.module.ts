import {
  ClassProvider,
  DynamicModule,
  Global,
  Module,
  Type,
  ValueProvider,
} from '@nestjs/common';
import { AuthModuleOptions } from './interfaces/auth-options.interface';
import { AUTH_MODULE_OPTIONS, USER_SERVICE_INTERFACE } from './auth.constants';
import { AuthService } from './services/auth.service';
import { IUserService } from '.';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { JwtAccessTokenStrategy } from './strategies/jwt-access.strategy';
import { JwtRefreshTokenStrategy } from './strategies/jwt-refresh.strategy';
import { LocalStrategy } from './strategies/local.strategy';

@Global()
@Module({})
export class AuthModule {
  public static forRoot(
    options: AuthModuleOptions,
    userService: Type<IUserService>,
  ): DynamicModule {
    const emailServiceOptionsProvider: ValueProvider<AuthModuleOptions> = {
      provide: AUTH_MODULE_OPTIONS,
      useValue: options,
    };

    const userServiceProvider: ClassProvider<IUserService> = {
      provide: USER_SERVICE_INTERFACE,
      useClass: userService,
    };

    return {
      controllers: [AuthController],
      imports: [PassportModule, JwtModule.register({})],
      module: AuthModule,
      providers: [
        emailServiceOptionsProvider,
        userServiceProvider,
        AuthService,
        JwtAccessTokenStrategy,
        JwtRefreshTokenStrategy,
        LocalStrategy,
      ],
      exports: [AuthService],
    };
  }
}
