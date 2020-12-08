import { EmailModuleOptions } from 'nestjs-email-service';
import { join } from 'path';

export function emailModuleOptions(): EmailModuleOptions {
  return {
    apiKey: 'SG._hc',
    templateDir: join(process.env.PWD, 'src', 'emailTemplate', 'pages'),
    partialsDir: join(process.env.PWD, 'src', 'emailTemplate', 'partials'),
  };
}
