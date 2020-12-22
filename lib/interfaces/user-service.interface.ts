import { CreateUserDto } from '../validators/create-user.dto';
import { QueryUserDto } from './query-user.dto';

export interface IUserService {
  createUser(user: CreateUserDto): Promise<QueryUserDto>;

  getUserById(userId: number): Promise<QueryUserDto | undefined>;
  getUserByEmail(email: string): Promise<QueryUserDto | undefined>;

  createRefreshToken(
    token: string,
    deviceId: string,
    userId: number,
  ): Promise<void>;
  getRefreshToken(
    deviceId: string,
    userId: number,
  ): Promise<string | undefined>;

  removeRefreshToken(deviceId: string, userId: number): Promise<void>;
  removeAllRefreshTokensOfUser(userId: number): Promise<void>;
  removeEarliestRefreshTokenIfExceedLimit(
    userId: number,
    limit: number,
  ): Promise<void>;

  doesFacebookIdExist(socialId: string, userId: number): Promise<boolean>;
  createUserViaFacebook(
    firstName: string,
    lastName: string,
    email: string,
    socialId: string,
  ): Promise<QueryUserDto>;
}
