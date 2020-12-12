import { Module } from '@nestjs/common';
import { AuthModule, USER_SERVICE_INTERFACE } from 'nestjs-auth-module';
import { authModuleOptions } from './config/authModule.config';
import { PrismaModule } from './prismaModule/prisma.module';
import { PrismaService } from './prismaModule/prisma.service';
import { RegisterModule } from './registerModule/register.module';
import { UserModule } from './userModule/user.module';
import { UserService } from './userModule/user.service';

@Module({
  imports: [
    PrismaModule,
    RegisterModule,
    UserModule,
    AuthModule.forRoot(authModuleOptions(), new UserService(new PrismaService)),
  ],
})
export class AppModule {}
