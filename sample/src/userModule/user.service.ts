import { Injectable, NotFoundException } from '@nestjs/common';
import { IUserService, UserDto } from 'nestjs-auth-module';
import { PrismaService } from 'src/prismaModule/prisma.service';

@Injectable()
export class UserService implements IUserService {
  constructor(private readonly prismaService: PrismaService) {}

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

  // todo dto replace fix? extend fullUser obj? fill other fields createAt...
  async createUser(user: UserDto) {
    const newUser = await this.prismaService.user.create({
      data: {
        name: user.name,
        email: user.email,
        password: user.password,
      },
    });
    return newUser;
  }

  async setRefreshToken(hashedRefreshToken: string, userId: number) {
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: hashedRefreshToken,
      },
    });
  }

  async removeRefreshToken(userId: number) {
    await this.prismaService.user.update({
      where: {
        id: userId,
      },
      data: {
        refreshToken: null,
      },
    });
  }
}
