import { hash, compare } from 'bcrypt';

import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { IUserService } from './interfaces/user-service.interface';
import { CreateUserDto } from './interfaces/create-user.dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { USER_SERVICE_INTERFACE } from './auth.constants';
import { nanoid } from 'nanoid';
import { Cookies, COOKIE_KEYS } from './interfaces/auth-request.interface';
import { generateCookie } from './helpers/cookie-generator';

@Injectable()
export class AuthService {
  constructor(
    @Inject(USER_SERVICE_INTERFACE)
    private readonly userService: IUserService,
    private readonly jwtService: JwtService,
  ) {
    const isOptionMissing = [
      process.env.JWT_ACCESS_TOKEN_SECRET,
      process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE,
      process.env.JWT_REFRESH_TOKEN_SECRET,
      process.env.JWT_REFRESH_TOKEN_ABSOLUTE_EXPIRATION_TIME_DAY,
      process.env.JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY,
      process.env.JWT_REFRESH_TOKEN_MAX_NUMBER_ISSUED,
    ].some((value) => !value);

    if (isOptionMissing) {
      throw new Error('Missing JWT option in env');
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

  private async handleNewRefreshToken(
    refreshToken: string,
    deviceId: string,
    userId: number,
  ) {
    const hashedToken = await hash(refreshToken, 10);
    await this.userService.createRefreshToken(hashedToken, deviceId, userId);

    await this.userService.removeEarliestRefreshTokenIfExceedLimit(
      userId,
      Number(process.env.JWT_REFRESH_TOKEN_MAX_NUMBER_ISSUED),
    );
  }

  async register(registrationData: CreateUserDto) {
    try {
      const hashedPassword = await hash(registrationData.password, 10);
      registrationData.password = hashedPassword;

      const { password, ...user } = await this.userService.createUser(
        registrationData,
      );
      return user;
    } catch (error) {
      // todo proper error message? email already exist?
      throw new BadRequestException(error.message);
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
      throw new BadRequestException(error.message);
    }
  }

  getAccessTokenCookie(userId: number) {
    const payload: TokenPayload = { userId };
    const options: JwtSignOptions = {
      secret: process.env.JWT_ACCESS_TOKEN_SECRET,
      expiresIn: `${process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE}m`,
    };

    const token = this.jwtService.sign(payload, options);
    return generateCookie(
      COOKIE_KEYS.Authentication,
      token,
      Number(process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE) * 60,
    );
  }

  async generateRefreshToken(userId: number, deviceId: string) {
    const payload: TokenPayload = { userId };
    const options: JwtSignOptions = {
      secret: process.env.JWT_REFRESH_TOKEN_SECRET,
      expiresIn: `${process.env.JWT_REFRESH_TOKEN_ABSOLUTE_EXPIRATION_TIME_DAY}d`,
    };

    const token = this.jwtService.sign(payload, options);
    await this.handleNewRefreshToken(token, deviceId, userId);
    return token;
  }

  getRefreshTokenCookie(token: string) {
    return generateCookie(
      COOKIE_KEYS.Refresh,
      token,
      Number(process.env.JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY) *
        86400,
    );
  }

  generateDeviceId() {
    return nanoid();
  }

  getDeviceIdCookie(deviceId: string) {
    return generateCookie(
      COOKIE_KEYS.DeviceId,
      deviceId,
      Number(process.env.JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY) *
        86400,
    );
  }

  public getCookiesForLogOut() {
    return [
      generateCookie(COOKIE_KEYS.Authentication, '', 0),
      generateCookie(COOKIE_KEYS.Refresh, '', 0),
      generateCookie(COOKIE_KEYS.DeviceId, '', 0),
    ];
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

  async removeAllRefreshTokensOfUser(userId: number) {
    await this.userService.removeAllRefreshTokensOfUser(userId);
  }

  async getUserById(userId: number) {
    const { password, ...user } = await this.userService.getUserById(userId);
    return user;
  }

  async generateLoginCookie(userId: number) {
    const deviceId = this.generateDeviceId();
    const refreshToken = await this.generateRefreshToken(userId, deviceId);

    const accessCookie = this.getAccessTokenCookie(userId);
    const refreshCookie = this.getRefreshTokenCookie(refreshToken);
    const deviceIdCookie = this.getDeviceIdCookie(deviceId);

    return [accessCookie, refreshCookie, deviceIdCookie];
  }

  checkIfCookiePresented(cookies: Cookies) {
    return Object.values(cookies).some((cookie) => !!cookie);
  }

  async renewAccessToken(cookies: Cookies, userId: number) {
    const accessCookie = this.getAccessTokenCookie(userId);
    const refreshCookie = this.getRefreshTokenCookie(cookies.Refresh);
    const deviceIdCookie = this.getDeviceIdCookie(cookies.DeviceId);

    // sending the same cookie will re-evaluate max-age
    // => Increase inactive time
    return [accessCookie, refreshCookie, deviceIdCookie];
  }
}
