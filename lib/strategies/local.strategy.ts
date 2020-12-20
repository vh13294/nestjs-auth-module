import { Strategy } from 'passport-local';
import { AuthGuard, PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import { UserInRequest } from '../interfaces/auth-request.interface';

const LOCAL = 'local';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, LOCAL) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
    });
  }
  async validate(email: string, password: string): Promise<UserInRequest> {
    return this.authService.localStrategy(email, password);
  }
}

@Injectable()
export class LocalAuthGuard extends AuthGuard(LOCAL) {}
