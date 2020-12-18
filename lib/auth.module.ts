import { ClassProvider, DynamicModule, Global, Module } from '@nestjs/common';
import { AuthModuleOption } from './interfaces/auth-option.interface';
import { USER_SERVICE_INTERFACE } from './auth.constants';
import { AuthService } from './auth.service';
import { IUserService } from '.';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { JwtAccessTokenStrategy } from './strategies/jwt-access.strategy';
import { JwtRefreshTokenStrategy } from './strategies/jwt-refresh.strategy';
import { LocalStrategy } from './strategies/local.strategy';
import { FacebookStrategy } from './strategies/facebook-token.strategy';

@Global()
@Module({})
export class AuthModule {
  public static forRoot(option: AuthModuleOption): DynamicModule {
    const userServiceProvider: ClassProvider<IUserService> = {
      provide: USER_SERVICE_INTERFACE,
      useClass: option.userServiceImplementation,
    };

    return {
      controllers: [AuthController],
      imports: [PassportModule, JwtModule.register({})],
      module: AuthModule,
      providers: [
        userServiceProvider,
        AuthService,
        JwtAccessTokenStrategy,
        JwtRefreshTokenStrategy,
        LocalStrategy,
        FacebookStrategy,
      ],
      // Should we expose this service?
      // exports: [AuthService],
    };
  }
}
