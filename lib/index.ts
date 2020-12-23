export { AuthModule } from './auth.module';

export { AuthModuleOptions } from './interfaces/auth-option.interface';
export { IUserService } from './interfaces/user-service.interface';
export { CreateUserDto } from './validators/create-user.dto';
export { AuthRequest } from './interfaces/auth-request.interface';

export { JwtAuthAccessGuard } from './strategies/jwt-access.strategy';

export { AuthService } from './auth.service';
