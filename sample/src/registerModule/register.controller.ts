import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import { JwtAuthAccessGuard } from 'nestjs-auth-module';

@Controller('register')
export class RegisterController {
  constructor() {}

  @UseGuards(JwtAuthAccessGuard)
  @Get('models')
  models(@Req() req: any) {
    return {
      models: ['a', 'b', 'c'],
    };
  }
}
