import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { HttpsOptions } from '@nestjs/common/interfaces/external/https-options.interface';
import { readFileSync } from 'fs';
import { ServerModule } from './server.module';
import { ClientModule } from './client.module';

const httpsOptions: HttpsOptions =
  process.env.HTTPS_ONLY == 'TRUE'
    ? {
        key: readFileSync('./client/private-key.key'),
        cert: readFileSync('./client/public-certificate.pem'),
      }
    : {};

async function bootstrapServer() {
  const app = await NestFactory.create(ServerModule, { httpsOptions });
  app.use(cookieParser());
  app.enableCors({
    origin: 'https://localhost:3001',
    credentials: true,
  });
  await app.listen(3000);
}
bootstrapServer();

async function bootstrapClient() {
  const app = await NestFactory.create(ClientModule, { httpsOptions });
  await app.listen(3001);
}
bootstrapClient();
