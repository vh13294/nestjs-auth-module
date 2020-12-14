import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import { JwtAuthAccessGuard } from 'nestjs-auth-module';

@Controller('register')
export class RegisterController {
  constructor() {}

  @UseGuards(JwtAuthAccessGuard)
  @Get('models')
  authenticate(@Req() req: any) {
    const { user } = req;
    return {
      user,
      models: ['a', 'b', 'c'],
    };
  }
}
