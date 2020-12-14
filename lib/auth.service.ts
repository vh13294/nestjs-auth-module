import { hash, compare } from 'bcrypt';

import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { IUserService } from './interfaces/user-service.interface';
import { CreateUserDto } from './interfaces/create-user.dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { AUTH_MODULE_OPTIONS, USER_SERVICE_INTERFACE } from './auth.constants';
import { AuthModuleOptions } from './interfaces/auth-options.interface';
import { nanoid } from 'nanoid';
import { Cookies } from './interfaces/auth-request.interface';

@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_MODULE_OPTIONS)
    private readonly options: AuthModuleOptions,
    @Inject(USER_SERVICE_INTERFACE)
    private readonly userService: IUserService,
    private readonly jwtService: JwtService,
  ) {
    const isOptionMissing = [
      this.options.jwtAccessTokenSecret,
      this.options.jwtAccessTokenExpirationSeconds,
      this.options.jwtRefreshTokenSecret,
      this.options.jwtRefreshTokenExpirationSeconds,
    ].some((value) => !value);

    if (isOptionMissing) {
      throw new Error('Missing JWT option in env');
    }
  }

  async register(registrationData: CreateUserDto) {
    const hashedPassword = await hash(registrationData.password, 10);
    registrationData.password = hashedPassword;

    try {
      const { password, ...user } = await this.userService.createUser(
        registrationData,
      );
      return user;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const { password, ...user } = await this.userService.getUserByEmail(
        email,
      );
      await this.verifyPassword(plainTextPassword, password);
      return user;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  private async verifyPassword(
    plainTextPassword: string,
    hashedPassword: string,
  ) {
    const isPasswordMatching = await compare(plainTextPassword, hashedPassword);
    if (!isPasswordMatching) {
      throw new BadRequestException('Wrong credentials provided');
    }
  }

  private signPayloadToken(
    payload: TokenPayload,
    option: JwtSignOptions,
  ): string {
    const token = this.jwtService.sign(payload, option);
    return token;
  }

  getAccessTokenCookieHeader(userId: number) {
    const token = this.signPayloadToken(
      { userId },
      {
        secret: process.env.JWT_ACCESS_TOKEN_SECRET,
        expiresIn: `${process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_SECONDS}s`,
      },
    );
    return (
      `Authentication=${token}; ` +
      'HttpOnly; ' +
      'SameSite=Strict; ' +
      'Path=/; ' +
      `Max-Age=${process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_SECONDS}`
    );
  }

  async generateRefreshToken(userId: number, deviceId: string) {
    const token = this.signPayloadToken(
      { userId },
      {
        secret: process.env.JWT_REFRESH_TOKEN_SECRET,
        expiresIn: `${process.env.JWT_REFRESH_TOKEN_EXPIRATION_TIME_SECONDS}s`,
      },
    );

    await this.setCurrentRefreshToken(token, deviceId, userId);
    return token;
  }

  getRefreshCookieHeader(token: string) {
    return (
      `Refresh=${token}; ` +
      'HttpOnly; ' +
      'SameSite=Strict; ' +
      'Path=/; ' +
      `Max-Age=${process.env.JWT_REFRESH_TOKEN_EXPIRATION_TIME_SECONDS}`
    );
  }

  generateDeviceId() {
    return nanoid();
  }

  getDeviceIdCookieHeader(deviceId: string) {
    return (
      `DeviceId=${deviceId}; ` +
      'HttpOnly; ' +
      'SameSite=Strict; ' +
      'Path=/; ' +
      `Max-Age=${process.env.JWT_REFRESH_TOKEN_EXPIRATION_TIME_SECONDS}`
    );
  }

  public getCookiesForLogOut() {
    return [
      'Authentication=; HttpOnly; Path=/; Max-Age=0',
      'Refresh=; HttpOnly; Path=/; Max-Age=0',
      'DeviceId=; HttpOnly; Path=/; Max-Age=0',
    ];
  }

  async setCurrentRefreshToken(
    refreshToken: string,
    deviceId: string,
    userId: number,
  ) {
    const hashedToken = await hash(refreshToken, 10);
    await this.userService.setRefreshToken(hashedToken, deviceId, userId);
  }

  async getUserIfRefreshTokenMatches(
    incomingToken: string,
    deviceId: string,
    userId: number,
  ) {
    const hashToken = await this.userService.getRefreshToken(deviceId, userId);
    const isTokenMatched = compare(incomingToken, hashToken);
    if (isTokenMatched) {
      const { password, ...user } = await this.userService.getUserById(userId);
      return user;
    }
  }

  async removeRefreshToken(deviceId: string, userId: number) {
    await this.userService.removeRefreshToken(deviceId, userId);
  }

  async getUserById(userId: number) {
    const { password, ...user } = await this.userService.getUserById(userId);
    return user;
  }

  async generateLoginCookie(userId: number) {
    const deviceId = this.generateDeviceId();
    const refreshToken = await this.generateRefreshToken(userId, deviceId);

    const accessCookie = this.getAccessTokenCookieHeader(userId);
    const refreshCookie = this.getRefreshCookieHeader(refreshToken);
    const deviceIdCookie = this.getDeviceIdCookieHeader(deviceId);

    return [accessCookie, refreshCookie, deviceIdCookie];
  }

  checkIfCookieHeaderPresented(cookies: Cookies) {
    return Object.keys(cookies).some((cookie) => !!cookies);
  }
}
