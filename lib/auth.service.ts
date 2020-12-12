import { hash, compare } from 'bcrypt';

import { BadRequestException, Inject, Injectable } from '@nestjs/common';
import { IUserService } from './interfaces/user-service.interface';
import { UserDto } from './interfaces/user.dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { AUTH_MODULE_OPTIONS, USER_SERVICE_INTERFACE } from './auth.constants';
import { AuthModuleOptions } from './interfaces/auth-options.interface';

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

  async register(registrationData: UserDto) {
    const hashedPassword = await hash(registrationData.password, 10);
    registrationData.password = hashedPassword;

    try {
      const {
        refreshToken,
        password,
        ...user
      } = await this.userService.createUser(registrationData);
      return user;
    } catch (error) {
      throw new BadRequestException(error);
    }
  }

  async getAuthenticatedUser(email: string, plainTextPassword: string) {
    try {
      const {
        refreshToken,
        password,
        ...user
      } = await this.userService.getUserByEmail(email);
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

  getCookieWithJwtAccessToken(userId: number) {
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
      'Path=/; ' +
      `Max-Age=${process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_SECONDS}`
    );
  }

  getCookieWithJwtRefreshToken(userId: number) {
    const token = this.signPayloadToken(
      { userId },
      {
        secret: process.env.JWT_REFRESH_TOKEN_SECRET,
        expiresIn: `${process.env.JWT_REFRESH_TOKEN_EXPIRATION_TIME_SECONDS}s`,
      },
    );

    const cookie =
      `Refresh=${token}; ` +
      'HttpOnly; ' +
      'Path=/; ' +
      `Max-Age=${process.env.JWT_REFRESH_TOKEN_EXPIRATION_TIME_SECONDS}`;

    return {
      refreshCookie: cookie,
      refreshToken: token,
    };
  }

  public getCookiesForLogOut() {
    return [
      'Authentication=; HttpOnly; Path=/; Max-Age=0',
      'Refresh=; HttpOnly; Path=/; Max-Age=0',
    ];
  }

  async setCurrentRefreshToken(refreshToken: string, userId: number) {
    const currentHashedRefreshToken = await hash(refreshToken, 10);
    await this.userService.setRefreshToken(currentHashedRefreshToken, userId);
  }

  async getUserIfRefreshTokenMatches(token: string, userId: number) {
    const {
      refreshToken,
      password,
      ...user
    } = await this.userService.getUserById(userId);
    const isTokenMatching = await compare(token, refreshToken);
    if (isTokenMatching) {
      return user;
    }
  }

  async removeRefreshToken(userId: number) {
    await this.userService.removeRefreshToken(userId);
  }

  async getUserById(userId: number) {
    const {
      refreshToken,
      password,
      ...user
    } = await this.userService.getUserById(userId);
    return user;
  }
}
