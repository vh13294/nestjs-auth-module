import { Injectable, NotFoundException } from '@nestjs/common';
import { IUserService, CreateUserDto } from 'nestjs-auth-module';
import { PrismaService } from 'src/prismaModule/prisma.service';

@Injectable()
export class UserServiceImplForAuth implements IUserService {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(user: CreateUserDto) {
    return await this.prismaService.user.create({
      data: {
        name: user.name,
        email: user.email,
        password: user.password,
      },
    });
  }

  async getUserById(id: number) {
    return await this.prismaService.user.findUnique({
      where: {
        id: id,
      },
    });
  }

  async getUserByEmail(email: string) {
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
  ) {
    await this.prismaService.refreshToken.create({
      data: {
        userId: userId,
        deviceId: deviceId,
        token: refreshToken,
      },
    });
  }

  async getRefreshToken(deviceId: string, userId: number) {
    const refreshToken = await this.prismaService.refreshToken.findFirst({
      where: {
        deviceId: deviceId,
        userId: userId,
      },
    });

    return refreshToken.token;
  }

  async removeRefreshToken(deviceId: string, userId: number) {
    await this.prismaService.refreshToken.deleteMany({
      where: {
        userId: userId,
        deviceId: deviceId,
      },
    });
  }

  async removeAllRefreshTokensOfUser(userId: number) {
    await this.prismaService.refreshToken.deleteMany({
      where: {
        userId: userId,
      },
    });
  }

  async removeEarliestRefreshTokenIfExceedLimit(userId: number, limit: number) {
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
            in: tokens.map(token => token.id),
          },
        },
      });
    }
  }
}
