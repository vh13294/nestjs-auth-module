import { Module } from '@nestjs/common';
import { RegisterModule } from './registerModule/register.module';

@Module({
  imports: [
    RegisterModule,
  ],
  providers: [],
})
export class AppModule {}
