import { IsInt, MinLength } from 'class-validator';

export class UpdatePasswordDto {
  @IsInt()
  userId!: number;

  @MinLength(6)
  password!: string;
}
