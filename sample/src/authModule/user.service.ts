import { Injectable, NotFoundException } from '@nestjs/common';
import { IUserService, CreateUserDto } from 'nestjs-auth-module';
import { PrismaService } from 'src/prismaModule/prisma.service';

@Injectable()
export class UserService implements IUserService {
  constructor(private readonly prismaService: PrismaService) {}

  async createUser(user: CreateUserDto) {
    const newUser = await this.prismaService.user.create({
      data: {
        name: user.name,
        email: user.email,
        password: user.password,
      },
    });
    return newUser;
  }

  async getUserById(id: number) {
    const user = await this.prismaService.user.findUnique({
      where: {
        id: id,
      },
    });
    if (user) {
      return user;
    }
    throw new NotFoundException('User with this id does not exist');
  }

  async getUserByEmail(email: string) {
    const user = await this.prismaService.user.findUnique({
      where: {
        email: email,
      },
    });
    if (user) {
      return user;
    }
    throw new NotFoundException('User with this email does not exist');
  }

  async setRefreshToken(
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
}
