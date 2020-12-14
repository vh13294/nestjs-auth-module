import {
  Controller,
  Post,
  Body,
  UseGuards,
  Res,
  Get,
  Req,
  MethodNotAllowedException,
} from '@nestjs/common';
import { Response } from 'express';
import { CreateUserDto } from './interfaces/create-user.dto';

import { AuthService } from './auth.service';

import { LocalAuthGuard } from './guards/local-auth.guard';
import { JwtAuthAccessGuard } from './guards/jwt-auth-access.guard';
import { JwtAuthRefreshGuard } from './guards/jwt-auth-refresh.guard';
import { AuthRequest } from './interfaces/auth-request.interface';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(@Body() registrationData: CreateUserDto) {
    return this.authService.register(registrationData);
  }

  @UseGuards(LocalAuthGuard)
  @Post('log-in')
  async logIn(@Req() req: AuthRequest, @Res() res: Response) {
    const { user, cookies } = req;

    if (this.authService.checkIfCookieHeaderPresented(cookies)) {
      throw new MethodNotAllowedException('The user is already logged in');
    } else {
      const loginCookie = await this.authService.generateLoginCookie(user.id);
      res.setHeader('Set-Cookie', loginCookie);
      return res.send(user);
    }
  }

  @UseGuards(JwtAuthAccessGuard)
  @Post('log-out')
  async logOut(@Req() req: AuthRequest, @Res() res: Response) {
    const { user, cookies } = req;

    await this.authService.removeRefreshToken(cookies.DeviceId, user.id);
    const logoutCookie = this.authService.getCookiesForLogOut();
    res.setHeader('Set-Cookie', logoutCookie);

    return res.sendStatus(200);
  }

  @UseGuards(JwtAuthRefreshGuard)
  @Get('renew-tokens')
  async refresh(@Req() req: AuthRequest, @Res() res: Response) {
    const { user, cookies } = req;

    await this.authService.removeRefreshToken(cookies.DeviceId, user.id);
    const loginCookie = await this.authService.generateLoginCookie(user.id);
    res.setHeader('Set-Cookie', loginCookie);

    return res.send(user);
  }
}
