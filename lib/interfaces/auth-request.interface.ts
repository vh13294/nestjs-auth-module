import { Request } from 'express';

export interface AuthRequest extends Request {
  user: {
    id: number;
    email: string;
  };
  cookies: Cookies;
}

// cookies headers could be found in AuthService
export interface Cookies {
  Authentication: string;
  Refresh: string;
  DeviceId: string;
}
