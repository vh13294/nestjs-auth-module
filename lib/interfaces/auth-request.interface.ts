import { Request } from 'express';

export interface AuthRequest extends Request {
  authUser: UserInRequest;
  cookies: Cookies;
}

export interface UserInRequest {
  id: number;
  email: string;
}

export interface Cookies {
  Authentication: string;
  Refresh: string;
  DeviceId: string;
}
