import {
  DynamicModule,
  Global,
  Module,
  Provider,
} from '@nestjs/common';
import {
  EmailAsyncModuleOptions,
  EmailModuleOptionsFactory,
} from './email-options.interface';
import { EmailService } from './email.service';
import { EMAIL_MODULE_OPTIONS } from './email.constants';

@Global()
@Module({})
export class EmailModule {
  public static forRootAsync(options: EmailAsyncModuleOptions): DynamicModule {
    const providers: Provider[] = this.createAsyncProviders(options);

    return {
      module: EmailModule,
      providers: [...providers, EmailService],
      imports: options.imports,
      exports: [EmailService],
    };
  }

  private static createAsyncProviders(
    options: EmailAsyncModuleOptions,
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
    options: EmailAsyncModuleOptions,
  ): Provider {
    if (options.useFactory) {
      return {
        name: EMAIL_MODULE_OPTIONS,
        provide: EMAIL_MODULE_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }

    return {
      name: EMAIL_MODULE_OPTIONS,
      provide: EMAIL_MODULE_OPTIONS,
      useFactory: async (optionsFactory: EmailModuleOptionsFactory) => {
        return optionsFactory.createEmailOptions();
      },
      inject: [options.useExisting! || options.useClass!],
    };
  }
}
