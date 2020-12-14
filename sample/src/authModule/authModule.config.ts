import { AuthModuleOption } from 'nestjs-auth-module';
import { UserServiceImplForAuth } from './user-service-implementation';

export function authModuleOptions(): AuthModuleOption {
  return {
    userServiceImplementation: UserServiceImplForAuth,
  };
}
