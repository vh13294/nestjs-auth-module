import { ModuleMetadata, Type } from '@nestjs/common';

export interface EmailModuleOptions {
  apiKey: string;
  // join(__dirname, 'email_templates')
  // join(process.env.PWD, 'src', 'email_templates')
  templateDir: string;
  partialsDir?: string;
}

export interface EmailAsyncModuleOptions
  extends Pick<ModuleMetadata, 'imports'> {
  inject?: any[];
  useClass?: Type<EmailModuleOptionsFactory>;
  useExisting?: Type<EmailModuleOptionsFactory>;
  useFactory?: (
    ...args: any[]
  ) => Promise<EmailModuleOptions> | EmailModuleOptions;
}

export interface EmailModuleOptionsFactory {
  createEmailOptions(): Promise<EmailModuleOptions> | EmailModuleOptions;
}
