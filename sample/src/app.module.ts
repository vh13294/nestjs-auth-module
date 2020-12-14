import { Module } from '@nestjs/common';
import { AuthModule } from 'nestjs-auth-module';
import { authModuleOptions } from './authModule/auth-module.config';
import { PrismaModule } from './prismaModule/prisma.module';
import { RegisterModule } from './registerModule/register.module';

@Module({
  imports: [
    PrismaModule,
    RegisterModule,
    AuthModule.forRoot(authModuleOptions()),
  ],
})
export class AppModule {}
