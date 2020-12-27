import { compare } from 'bcrypt';
import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  MethodNotAllowedException,
} from '@nestjs/common';
import { IUserService } from './interfaces/user-service.interface';
import { CreateUserDto } from './validators/create-user.dto';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ENV_OPTIONS, USER_SERVICE_INTERFACE } from './auth.constants';
import { Cookies, UserInRequest } from './interfaces/auth-request.interface';
import {
  dayToSecond,
  cookieFactory,
  minuteToSecond,
} from './helpers/cookie-generator';
import { TokenPayload } from './interfaces/token-payload.interface';
import { EnvOptions } from './interfaces/auth-option.interface';
import { UserObjectResponse } from './interfaces/user-object-response.interface';
import { UpdatePasswordDto } from './validators/update-password.dto';
import {
  generateDeviceId,
  saltHash,
  verifyPassword,
} from './helpers/auth-service.helper';
import { nameOf } from './helpers/types-helper';

@Injectable()
export class AuthService {
  constructor(
    @Inject(ENV_OPTIONS)
    private readonly env: EnvOptions,
    @Inject(USER_SERVICE_INTERFACE)
    private readonly userService: IUserService,
    private readonly jwtService: JwtService,
  ) {
    for (const [key, value] of Object.entries(this.env)) {
      if (value === '' || value === undefined) {
        throw new Error(`Missing ${key} in env`);
      }
    }
  }

  /**
   * Private
   */

  private async registerUserViaFacebook(
    firstName: string,
    lastName: string,
    email: string,
    socialId: string,
  ): Promise<number> {
    try {
      const user = await this.userService.createUserViaFacebook(
        firstName,
        lastName,
        email,
        socialId,
      );
      return user.id;
    } catch (error) {
      throw new BadRequestException(error.message);
    }
  }

  private getAccessTokenCookie(token: string): string {
    return this.generateCookie(
      nameOf<Cookies>('Authentication'),
      token,
      minuteToSecond(this.env.jwtAccessTokenExpirationTimeMinute),
    );
  }

  private getRefreshTokenCookie(token: string): string {
    return this.generateCookie(
      nameOf<Cookies>('Refresh'),
      token,
      dayToSecond(this.env.jwtRefreshTokenInactiveExpirationTimeDay),
    );
  }

  private getDeviceIdCookie(deviceId: string): string {
    return this.generateCookie(
      nameOf<Cookies>('DeviceId'),
      deviceId,
      dayToSecond(this.env.jwtRefreshTokenInactiveExpirationTimeDay),
    );
  }

  private generateAccessToken(userId: number) {
    const payload: TokenPayload = { userId };
    const options: JwtSignOptions = {
      secret: this.env.jwtAccessTokenSecret,
      expiresIn: `${this.env.jwtAccessTokenExpirationTimeMinute}m`,
    };

    const token = this.jwtService.sign(payload, options);
    return token;
  }

  private async generateRefreshToken(
    userId: number,
    deviceId: string,
  ): Promise<string> {
    const payload: TokenPayload = { userId };
    const options: JwtSignOptions = {
      secret: this.env.jwtRefreshTokenSecret,
      expiresIn: `${this.env.jwtRefreshTokenAbsoluteExpirationTimeDay}d`,
    };

    const token = this.jwtService.sign(payload, options);
    await this.handleNewRefreshToken(token, deviceId, userId);
    return token;
  }

  private async handleNewRefreshToken(
    refreshToken: string,
    deviceId: string,
    userId: number,
  ): Promise<void> {
    const hashedToken = await saltHash(refreshToken);
    await this.userService.createRefreshToken(hashedToken, deviceId, userId);

    await this.userService.removeEarliestRefreshTokenIfExceedLimit(
      userId,
      this.env.jwtRefreshTokenMaxNumberIssued,
    );
  }

  private async isRefreshTokenMatched(
    cookies: Cookies,
    userId: number,
  ): Promise<boolean> {
    const hashToken = await this.userService.getRefreshToken(
      cookies.DeviceId,
      userId,
    );
    if (cookies.Refresh && hashToken) {
      return await compare(cookies.Refresh, hashToken);
    }
    return false;
  }

  private generateCookie(key: string, value: string, maxAgeInSecond: number) {
    return cookieFactory(key, value, maxAgeInSecond, this.env.isHttpsOnly);
  }

  /**
   * End of Private
   */

  async register(createUserData: CreateUserDto): Promise<void> {
    try {
      const hashedPassword = await saltHash(createUserData.password);
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
    const user = await this.userService.getUserByEmail(email);
    if (user) {
      if (user.password) {
        await verifyPassword(plainTextPassword, user.password);
        return {
          id: user.id,
          email: user.email,
        };
      } else {
        throw new BadRequestException(
          'The password has not been set for this account, You may use social-login',
        );
      }
    }
    throw new BadRequestException('Invalid Credentials');
  }

  async jwtAccessStrategy(userId: number): Promise<UserInRequest> {
    const user = await this.userService.getUserById(userId);
    if (user) {
      return {
        id: user.id,
        email: user.email,
      };
    }
    throw new BadRequestException('Invalid token');
  }

  async jwtRefreshStrategy(
    cookies: Cookies,
    userId: number,
  ): Promise<UserInRequest> {
    if (await this.isRefreshTokenMatched(cookies, userId)) {
      const user = await this.userService.getUserById(userId);
      if (user) {
        return {
          id: user.id,
          email: user.email,
        };
      }
    }
    throw new ForbiddenException('Invalid token');
  }

  public getCookiesForLogOut(): string[] {
    return [
      this.generateCookie(nameOf<Cookies>('Authentication'), '', 0),
      this.generateCookie(nameOf<Cookies>('Refresh'), '', 0),
      this.generateCookie(nameOf<Cookies>('DeviceId'), '', 0),
    ];
  }

  async removeRefreshToken(deviceId: string, userId: number): Promise<void> {
    await this.userService.removeRefreshToken(deviceId, userId);
  }

  async removeAllRefreshTokensOfUser(userId: number): Promise<void> {
    await this.userService.removeAllRefreshTokensOfUser(userId);
  }

  async generateLoginCookie(
    cookies: Cookies,
    userId: number,
  ): Promise<string[]> {
    if (await this.isRefreshTokenMatched(cookies, userId)) {
      throw new MethodNotAllowedException('The user is already logged in');
    }

    const deviceId = generateDeviceId();
    const accessToken = this.generateAccessToken(userId);
    const refreshToken = await this.generateRefreshToken(userId, deviceId);

    const accessCookie = this.getAccessTokenCookie(accessToken);
    const refreshCookie = this.getRefreshTokenCookie(refreshToken);
    const deviceIdCookie = this.getDeviceIdCookie(deviceId);

    return [accessCookie, refreshCookie, deviceIdCookie];
  }

  renewAccessToken(cookies: Cookies, userId: number): string[] {
    const accessToken = this.generateAccessToken(userId);

    const accessCookie = this.getAccessTokenCookie(accessToken);
    const refreshCookie = this.getRefreshTokenCookie(cookies.Refresh);
    const deviceIdCookie = this.getDeviceIdCookie(cookies.DeviceId);

    // sending the same cookie will re-evaluate max-age
    // => Increase inactive time
    return [accessCookie, refreshCookie, deviceIdCookie];
  }

  async continueWithFacebook(
    firstName: string,
    lastName: string,
    email: string,
    socialId: string,
  ): Promise<number> {
    const user = await this.userService.getUserByEmail(email);

    if (user) {
      const doesFbIdExist = await this.userService.doesFacebookIdExist(
        socialId,
        user.id,
      );
      if (!doesFbIdExist) {
        const errMessage = 'The user registered via email not FB';
        throw new MethodNotAllowedException(errMessage);
      }
      return user.id;
    }

    return await this.registerUserViaFacebook(
      firstName,
      lastName,
      email,
      socialId,
    );
  }

  async getUserForResponse(userId: number): Promise<UserObjectResponse> {
    const user = await this.userService.getUserById(userId);
    if (user) {
      return {
        id: user.id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      };
    }
    throw new BadRequestException('Invalid Credentials');
  }

  async setInitialPasswordForSocialSignUp(
    authUserId: number,
    userData: UpdatePasswordDto,
  ): Promise<void> {
    if (authUserId !== userData.userId) {
      throw new ForbiddenException('Incorrect User');
    }
    // todo
    // await this.userService.setUserPassword(authUserId)
  }
}
