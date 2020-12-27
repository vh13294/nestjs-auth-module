import {
  Controller,
  Post,
  Body,
  UseGuards,
  Res,
  Req,
  ValidationPipe,
  Get,
} from '@nestjs/common';
import { Response } from 'express';

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
import { UserObjectResponse } from './interfaces/user-object-response.interface';
import { UpdatePasswordDto } from './validators/update-password.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async register(
    @Body(new ValidationPipe()) userData: CreateUserDto,
    @Res() res: Response,
  ): Promise<Response> {
    await this.authService.register(userData);
    return res.sendStatus(201);
  }

  @UseGuards(FacebookGuard)
  @Post('continue-with-facebook')
  // For security reason please 'Post' accessToken
  async continueWithFacebook(
    @Req() req: FacebookRequest,
    @Res() res: Response,
  ): Promise<Response> {
    const { facebookProfile, cookies } = req;

    const userId = await this.authService.continueWithFacebook(
      facebookProfile.name.givenName,
      facebookProfile.name.familyName,
      facebookProfile.emails[0].value,
      facebookProfile.id,
    );

    const loginCookie = await this.authService.generateLoginCookie(
      cookies,
      userId,
    );

    const userForResponse = await this.authService.getUserForResponse(userId);
    res.setHeader('Set-Cookie', loginCookie);
    return res.send(userForResponse);
  }

  @UseGuards(LocalAuthGuard)
  @Post('log-in')
  // For security reason please 'Post' credentials
  async logIn(
    @Req() req: AuthRequest,
    @Res() res: Response,
  ): Promise<Response> {
    const { authUser, cookies } = req;

    const loginCookie = await this.authService.generateLoginCookie(
      cookies,
      authUser.id,
    );

    const userForResponse = await this.authService.getUserForResponse(
      authUser.id,
    );
    res.setHeader('Set-Cookie', loginCookie);
    return res.send(userForResponse);
  }

  @UseGuards(JwtAuthAccessGuard)
  @Get('log-out')
  async logOut(
    @Req() req: AuthRequest,
    @Res() res: Response,
  ): Promise<Response> {
    const { authUser, cookies } = req;
    await this.authService.removeRefreshToken(cookies.DeviceId, authUser.id);
    const logoutCookie = this.authService.getCookiesForLogOut();

    res.setHeader('Set-Cookie', logoutCookie);
    return res.sendStatus(200);
  }

  @UseGuards(JwtAuthAccessGuard)
  @Get('log-out-all-devices')
  async logOutAllDevices(
    @Req() req: AuthRequest,
    @Res() res: Response,
  ): Promise<Response> {
    const { authUser } = req;
    await this.authService.removeAllRefreshTokensOfUser(authUser.id);
    const logoutCookie = this.authService.getCookiesForLogOut();

    res.setHeader('Set-Cookie', logoutCookie);
    return res.sendStatus(200);
  }

  @UseGuards(JwtAuthRefreshGuard)
  @Get('new-access-token')
  async refresh(
    @Req() req: AuthRequest,
    @Res() res: Response,
  ): Promise<Response> {
    const { authUser, cookies } = req;
    const newCookies = this.authService.renewAccessToken(cookies, authUser.id);

    res.setHeader('Set-Cookie', newCookies);
    return res.sendStatus(200);
  }

  @UseGuards(JwtAuthAccessGuard)
  @Get('current-logged-in-user')
  async currentLoggedInUser(
    @Req() req: AuthRequest,
  ): Promise<UserObjectResponse> {
    const { authUser } = req;
    const userForResponse = await this.authService.getUserForResponse(
      authUser.id,
    );
    return userForResponse;
  }

  @UseGuards(JwtAuthAccessGuard)
  @Post('set-initial-password-for-social-sign-up')
  async setInitialPasswordForSocialSignUp(
    @Req() req: AuthRequest,
    @Body(new ValidationPipe()) userData: UpdatePasswordDto,
    @Res() res: Response,
  ): Promise<Response> {
    const { authUser } = req;
    await this.authService.setInitialPasswordForSocialSignUp(
      authUser.id,
      userData,
    );
    return res.sendStatus(200);
  }

  /**
   *
   * @UseGuards(JwtAuthAccessGuard)
   * sendPasswordResetLinkToUserViaEmail(req)
   * const { user } = req;
   * email = this.getEmail(user)
   *
   * const url = this.generateSignedUrl(
   * controller,
   * controller method,
   * validDuration = 10mn,
   * )
   *
   * this.userService.sendEmail(email, url)
   *
   *
   * @Post('resetPasswordLink')
   * @UseGuards(UrlGeneratorGuard, JwtAuthAccessGuard)
   * async resetPasswordLink(req: Body)
   *
   * const { user, oldPassword, newPassword } = req;
   * this.verifyOldPassword(oldPassword, currentPassword)
   *
   * this.updateUser(user.id, {
   * password: hashed-password
   * })
   *
   */
}
