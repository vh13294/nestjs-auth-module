import { IsInt, MinLength } from 'class-validator';

export class SetPasswordDto {
  @IsInt()
  userId!: number;

  @MinLength(6)
  password!: string;
}

export class ChangePasswordDto {
  @IsInt()
  userId!: number;

  @MinLength(6)
  oldPassword!: string;

  @MinLength(6)
  newPassword!: string;
}
