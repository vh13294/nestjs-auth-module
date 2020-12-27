import { Strategy } from 'passport-local';
import {
  AuthGuard,
  IAuthModuleOptions,
  PassportStrategy,
} from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { AuthService } from '../auth.service';
import {
  AuthRequest,
  UserInRequest,
} from '../interfaces/auth-request.interface';
import { nameOf } from '../helpers/types-helper';

const LOCAL = 'local';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy, LOCAL) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
    });
  }

  // Get email/password from request, for security issue, please use post request
  async validate(email: string, password: string): Promise<UserInRequest> {
    return this.authService.localStrategy(email, password);
  }
}

@Injectable()
export class LocalAuthGuard extends AuthGuard(LOCAL) {
  getAuthenticateOptions(): IAuthModuleOptions {
    return {
      property: nameOf<AuthRequest>('authUser'),
    };
  }
}
