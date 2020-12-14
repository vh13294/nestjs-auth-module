import { Type } from '@nestjs/common';
import { IUserService } from './user-service.interface';

export interface AuthModuleOption {
  userServiceImplementation: Type<IUserService>;
}
