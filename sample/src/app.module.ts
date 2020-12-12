import { Module } from '@nestjs/common';
import { PrismaModule } from './prismaModule/prisma.module';
import { RegisterModule } from './registerModule/register.module';

@Module({
  imports: [
    PrismaModule,
    RegisterModule,
  ],
  providers: [],
})
export class AppModule {}
