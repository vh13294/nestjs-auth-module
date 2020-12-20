import { Injectable } from '@nestjs/common';
import { IUserService, CreateUserDto } from 'nestjs-auth-module';
import { QueryUserDto } from 'nestjs-auth-module/dist/interfaces/query-user.dto';
import { PrismaService } from 'src/prismaModule/prisma.service';

@Injectable()
export class UserServiceImplForAuth implements IUserService {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(user: CreateUserDto): Promise<QueryUserDto> {
    return await this.prismaService.user.create({
      data: {
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        password: user.password,
      },
    });
  }

  async getUserById(id: number): Promise<QueryUserDto> {
    return await this.prismaService.user.findUnique({
      where: {
        id: id,
      },
    });
  }

  async getUserByEmail(email: string): Promise<QueryUserDto> {
    return await this.prismaService.user.findUnique({
      where: {
        email: email,
      },
    });
  }

  async createRefreshToken(
    refreshToken: string,
    deviceId: string,
    userId: number,
  ): Promise<void> {
    await this.prismaService.refreshToken.create({
      data: {
        userId: userId,
        deviceId: deviceId,
        token: refreshToken,
      },
    });
  }

  async getRefreshToken(
    deviceId: string,
    userId: number,
  ): Promise<string | undefined> {
    const refreshToken = await this.prismaService.refreshToken.findFirst({
      where: {
        deviceId: deviceId,
        userId: userId,
      },
    });

    return refreshToken?.token;
  }

  async removeRefreshToken(deviceId: string, userId: number): Promise<void> {
    await this.prismaService.refreshToken.deleteMany({
      where: {
        userId: userId,
        deviceId: deviceId,
      },
    });
  }

  async removeAllRefreshTokensOfUser(userId: number): Promise<void> {
    await this.prismaService.refreshToken.deleteMany({
      where: {
        userId: userId,
      },
    });
  }

  async removeEarliestRefreshTokenIfExceedLimit(
    userId: number,
    limit: number,
  ): Promise<void> {
    const tokens = await this.prismaService.refreshToken.findMany({
      select: {
        id: true,
      },
      where: {
        userId: userId,
      },
      orderBy: {
        createdAt: 'desc',
      },
      skip: limit,
    });

    if (tokens.length) {
      await this.prismaService.refreshToken.deleteMany({
        where: {
          id: {
            in: tokens.map((token) => token.id),
          },
        },
      });
    }
  }

  async doesFacebookIdExist(
    socialId: string,
    userId: number,
  ): Promise<boolean> {
    const social = await this.prismaService.socialAccount.findFirst({
      select: {
        id: true,
      },
      where: {
        userId: userId,
        socialId: socialId,
      },
    });

    return !!social;
  }

  async createUserViaFacebook(
    firstName: string,
    lastName: string,
    email: string,
    socialId: string,
  ): Promise<QueryUserDto> {
    return await this.prismaService.user.create({
      data: {
        firstName: firstName,
        lastName: lastName,
        email: email,
        password: null,
        socials: {
          create: {
            provider: 'FACEBOOK',
            socialId: socialId,
          },
        },
      },
    });
  }
}
