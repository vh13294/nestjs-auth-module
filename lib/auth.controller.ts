import {
  Controller,
  Post,
  Body,
  UseGuards,
  Res,
  Req,
  MethodNotAllowedException,
  ValidationPipe,
} from '@nestjs/common';
import { Request, Response } from 'express';

import { AuthService } from './auth.service';
import { CreateUserDto } from './validators/create-user.dto';
import { AuthRequest } from './interfaces/auth-request.interface';

import { JwtAuthAccessGuard } from './strategies/jwt-access.strategy';
import { JwtAuthRefreshGuard } from './strategies/jwt-refresh.strategy';
import { LocalAuthGuard } from './strategies/local.strategy';
import {
  FacebookGuard,
  FacebookRequest,
} from './strategies/facebook-token.strategy';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body(new ValidationPipe()) userData: CreateUserDto,
    @Res() res: Response,
  ) {
    await this.authService.register(userData);
    return res.sendStatus(201);
  }

  @UseGuards(FacebookGuard)
  @Post('continue-with-facebook')
  async registerFacebook(@Req() req: FacebookRequest, @Res() res: Response) {
    const { user } = req;
    const email = user.emails[0].value;
    const profileId = user.id;

    let accountId = await this.authService.getUserByEmail(email);

    if (accountId) {
      if (!this.authService.doesUserHaveFacebookId(profileId, accountId)) {
        throw new MethodNotAllowedException(
          'The user registered via email not FB',
        );
      }
    } else {
      accountId = await this.authService.registerUserViaFacebook(
        user.name.givenName,
        user.name.familyName,
        email,
        profileId,
      );
    }

    const loginCookie = await this.authService.generateLoginCookie(accountId);
    res.setHeader('Set-Cookie', loginCookie);
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
    const newCookies = this.authService.renewAccessToken(cookies, user.id);

    res.setHeader('Set-Cookie', newCookies);
    return res.sendStatus(200);
  }
}
