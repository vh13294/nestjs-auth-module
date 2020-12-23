import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import { JwtAuthAccessGuard } from 'nestjs-auth-module';
import { AuthRequest } from 'nestjs-auth-module';

@Controller('register')
export class RegisterController {
  @UseGuards(JwtAuthAccessGuard)
  @Get('models')
  models(@Req() req: AuthRequest): any {
    return {
      user: req.user,
      models: ['a', 'b', 'c'],
    };
  }
}
