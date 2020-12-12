import {
  DynamicModule,
  Global,
  Module,
  Provider,
} from '@nestjs/common';
import {
  AuthAsyncModuleOptions,
  AuthModuleOptionsFactory,
} from './interfaces/auth-options.interface';
import { AUTH_MODULE_OPTIONS } from './auth.constants';
import { AuthService } from './services/auth.service';

@Global()
@Module({})
export class AuthModule {
  public static forRootAsync(options: AuthAsyncModuleOptions): DynamicModule {
    const providers: Provider[] = this.createAsyncProviders(options);

    return {
      module: AuthModule,
      providers: [...providers, AuthService],
      imports: options.imports,
      exports: [AuthService],
    };
  }

  private static createAsyncProviders(
    options: AuthAsyncModuleOptions,
  ): Provider[] {
    const providers: Provider[] = [this.createAsyncOptionsProvider(options)];

    if (options.useClass) {
      providers.push({
        provide: options.useClass,
        useClass: options.useClass,
      });
    }

    return providers;
  }

  private static createAsyncOptionsProvider(
    options: AuthAsyncModuleOptions,
  ): Provider {
    if (options.useFactory) {
      return {
        name: AUTH_MODULE_OPTIONS,
        provide: AUTH_MODULE_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }

    return {
      name: AUTH_MODULE_OPTIONS,
      provide: AUTH_MODULE_OPTIONS,
      useFactory: async (optionsFactory: AuthModuleOptionsFactory) => {
        return optionsFactory.createAuthOptions();
      },
      inject: [options.useExisting! || options.useClass!],
    };
  }
}
