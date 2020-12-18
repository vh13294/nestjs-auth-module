import { hash, compare } from 'bcrypt';
import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
} from '@nestjs/common';
import { IUserService } from './interfaces/user-service.interface';
import { CreateUserDto } from './validators/create-user.dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { USER_SERVICE_INTERFACE } from './auth.constants';
import { nanoid } from 'nanoid';
import {
  Cookies,
  COOKIE_KEYS,
  UserInRequest,
} from './interfaces/auth-request.interface';
import {
  dayToSecond,
  generateCookie,
  minuteToSecond,
} from './helpers/cookie-generator';
import { TokenPayload } from './interfaces/token-payload.interface';

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
  ): Promise<void> {
    const isPasswordMatching = await compare(plainTextPassword, hashedPassword);
    if (!isPasswordMatching) {
      throw new BadRequestException('Wrong credentials provided');
    }
  }

  private async handleNewRefreshToken(
    refreshToken: string,
    deviceId: string,
    userId: number,
  ): Promise<void> {
    const hashedToken = await hash(refreshToken, 10);
    await this.userService.createRefreshToken(hashedToken, deviceId, userId);

    await this.userService.removeEarliestRefreshTokenIfExceedLimit(
      userId,
      Number(process.env.JWT_REFRESH_TOKEN_MAX_NUMBER_ISSUED),
    );
  }

  async register(createUserData: CreateUserDto): Promise<void> {
    try {
      const hashedPassword = await hash(createUserData.password, 10);
      createUserData.password = hashedPassword;
      await this.userService.createUser(createUserData);
    } catch (error) {
      // todo proper error message?
      // email already exist?
      // when db is offline do not expose url
      throw new BadRequestException(error.message);
    }
  }

  async localStrategy(
    email: string,
    plainTextPassword: string,
  ): Promise<UserInRequest> {
    try {
      const user = await this.userService.getUserByEmail(email);
      await this.verifyPassword(plainTextPassword, user.password);
      return {
        id: user.id,
        email: user.email,
      };
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  async jwtAccessStrategy(userId: number): Promise<UserInRequest> {
    const user = await this.userService.getUserById(userId);
    return {
      id: user.id,
      email: user.email,
    };
  }

  async jwtRefreshStrategy(
    cookies: Cookies,
    userId: number,
  ): Promise<UserInRequest> {
    if (this.isRefreshTokenMatched(cookies, userId)) {
      const user = await this.userService.getUserById(userId);
      return {
        id: user.id,
        email: user.email,
      };
    } else {
      throw new ForbiddenException('Invalid token');
    }
  }

  async isRefreshTokenMatched(
    cookies: Cookies,
    userId: number,
  ): Promise<boolean> {
    const hashToken = await this.userService.getRefreshToken(
      cookies.DeviceId,
      userId,
    );
    const isTokenMatched = compare(cookies.Refresh, hashToken);
    return isTokenMatched;
  }

  getAccessTokenCookie(userId: number): string {
    const payload: TokenPayload = { userId };
    const options: JwtSignOptions = {
      secret: process.env.JWT_ACCESS_TOKEN_SECRET,
      expiresIn: `${process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE}m`,
    };

    const token = this.jwtService.sign(payload, options);
    return generateCookie(
      COOKIE_KEYS.Authentication,
      token,
      minuteToSecond(process.env.JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE),
    );
  }

  async generateRefreshToken(
    userId: number,
    deviceId: string,
  ): Promise<string> {
    const payload: TokenPayload = { userId };
    const options: JwtSignOptions = {
      secret: process.env.JWT_REFRESH_TOKEN_SECRET,
      expiresIn: `${process.env.JWT_REFRESH_TOKEN_ABSOLUTE_EXPIRATION_TIME_DAY}d`,
    };

    const token = this.jwtService.sign(payload, options);
    await this.handleNewRefreshToken(token, deviceId, userId);
    return token;
  }

  getRefreshTokenCookie(token: string): string {
    return generateCookie(
      COOKIE_KEYS.Refresh,
      token,
      dayToSecond(process.env.JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY),
    );
  }

  generateDeviceId(): string {
    return nanoid();
  }

  getDeviceIdCookie(deviceId: string): string {
    return generateCookie(
      COOKIE_KEYS.DeviceId,
      deviceId,
      dayToSecond(process.env.JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY),
    );
  }

  public getCookiesForLogOut(): string[] {
    return [
      generateCookie(COOKIE_KEYS.Authentication, '', 0),
      generateCookie(COOKIE_KEYS.Refresh, '', 0),
      generateCookie(COOKIE_KEYS.DeviceId, '', 0),
    ];
  }

  async removeRefreshToken(deviceId: string, userId: number): Promise<void> {
    await this.userService.removeRefreshToken(deviceId, userId);
  }

  async removeAllRefreshTokensOfUser(userId: number): Promise<void> {
    await this.userService.removeAllRefreshTokensOfUser(userId);
  }

  async generateLoginCookie(userId: number): Promise<string[]> {
    const deviceId = this.generateDeviceId();
    const refreshToken = await this.generateRefreshToken(userId, deviceId);

    const accessCookie = this.getAccessTokenCookie(userId);
    const refreshCookie = this.getRefreshTokenCookie(refreshToken);
    const deviceIdCookie = this.getDeviceIdCookie(deviceId);

    return [accessCookie, refreshCookie, deviceIdCookie];
  }

  async renewAccessToken(cookies: Cookies, userId: number): Promise<string[]> {
    const accessCookie = this.getAccessTokenCookie(userId);
    const refreshCookie = this.getRefreshTokenCookie(cookies.Refresh);
    const deviceIdCookie = this.getDeviceIdCookie(cookies.DeviceId);

    // sending the same cookie will re-evaluate max-age
    // => Increase inactive time
    return [accessCookie, refreshCookie, deviceIdCookie];
  }
}
