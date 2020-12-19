import { NestFactory } from '@nestjs/core';
import * as cookieParser from 'cookie-parser';
import { HttpsOptions } from '@nestjs/common/interfaces/external/https-options.interface';
import { readFileSync } from 'fs';
import { ServerModule } from './server.module';
import { ClientModule } from './client.module';

const httpsOptions: HttpsOptions = {
  key: readFileSync('./client/private-key.key'),
  cert: readFileSync('./client/public-certificate.pem'),
};

async function bootstrapServer() {
  const app = await NestFactory.create(ServerModule, { httpsOptions, cors: true });
  app.use(cookieParser());
  await app.listen(3000);
}
bootstrapServer();

async function bootstrapClient() {
  const app = await NestFactory.create(ClientModule, { httpsOptions });
  await app.listen(3001);
}
bootstrapClient();
