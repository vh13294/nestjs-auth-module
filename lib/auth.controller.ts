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
  async register(@Body() userData: CreateUserDto, @Res() res: Response) {
    // todo add dto validation ? empty email/password/name/ valid email address?
    await this.authService.register(userData);
    return res.sendStatus(201);
  }

  @UseGuards(LocalAuthGuard)
  @Post('log-in')
  async logIn(@Req() req: AuthRequest, @Res() res: Response) {
    const { user, cookies } = req;

    if (this.authService.isRefreshTokenMatched(cookies, user.id)) {
      throw new MethodNotAllowedException('The user is already logged in');
    } else {
      const loginCookie = await this.authService.generateLoginCookie(user.id);

      res.setHeader('Set-Cookie', loginCookie);
      return res.sendStatus(200);
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

  @UseGuards(JwtAuthAccessGuard)
  @Post('log-out-all-devices')
  async logOutAllDevices(@Req() req: AuthRequest, @Res() res: Response) {
    const { user } = req;
    await this.authService.removeAllRefreshTokensOfUser(user.id);
    const logoutCookie = this.authService.getCookiesForLogOut();

    res.setHeader('Set-Cookie', logoutCookie);
    return res.sendStatus(200);
  }

  @UseGuards(JwtAuthRefreshGuard)
  @Post('new-access-token')
  async refresh(@Req() req: AuthRequest, @Res() res: Response) {
    const { user, cookies } = req;
    const newCookies = await this.authService.renewAccessToken(
      cookies,
      user.id,
    );

    res.setHeader('Set-Cookie', newCookies);
    return res.sendStatus(200);
  }
}
