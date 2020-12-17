import { IsEmail, IsString, Length, MinLength } from 'class-validator';

export class CreateUserDto {
  @MinLength(6)
  name!: string;

  @IsEmail()
  email!: string;

  @MinLength(6)
  password!: string;
}
