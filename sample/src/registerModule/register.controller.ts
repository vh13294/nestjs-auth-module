import { Controller, Get, Req, UseGuards } from '@nestjs/common';

import { AuthService, JwtAuthAccessGuard } from 'nestjs-auth-module';

@Controller('register')
export class RegisterController {
  constructor(private readonly authService: AuthService) {}

  @UseGuards(JwtAuthAccessGuard)
  @Get('models')
  authenticate(@Req() req: any) {
    const { user } = req;
    return {
      user,
      models: ['a', 'b', 'c']
    };
  }
}
