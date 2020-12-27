import { BadRequestException } from '@nestjs/common';
import { compare, hash } from 'bcrypt';
import { nanoid } from 'nanoid';

export async function verifyPassword(
  plainTextPassword: string,
  hashedPassword: string,
): Promise<void> {
  const isPasswordMatching = await compare(plainTextPassword, hashedPassword);
  if (!isPasswordMatching) {
    throw new BadRequestException('Wrong credentials provided');
  }
}

export function generateDeviceId(): string {
  return nanoid();
}

export async function saltHash(input: string): Promise<string> {
  if (input) {
    return await hash(input, 10);
  }
  throw new BadRequestException('The Field must not be empty');
}
