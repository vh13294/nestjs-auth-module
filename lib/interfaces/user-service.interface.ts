import { UserDto } from './user.dto';

export interface IUserService {
  getUserById(id: number): Promise<UserDto>;
  getUserByEmail(email: string): Promise<UserDto>;
  createUser(user: UserDto): Promise<UserDto>;
  setRefreshToken(hashedRefreshToken: string, userId: number): Promise<UserDto>;
  removeRefreshToken(userId: number): Promise<UserDto>;
}
