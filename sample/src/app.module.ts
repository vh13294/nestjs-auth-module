import { Module } from '@nestjs/common';
import { AuthModule } from 'nestjs-auth-module';
import { authModuleOptions } from './config/authModule.config';
import { PrismaModule } from './prismaModule/prisma.module';
import { RegisterModule } from './registerModule/register.module';
import { UserService } from './authModule/user.service';

@Module({
  imports: [
    PrismaModule,
    RegisterModule,
    AuthModule.forRoot(authModuleOptions(), UserService),
  ],
})
export class AppModule {}
