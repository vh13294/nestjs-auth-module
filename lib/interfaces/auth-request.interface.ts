import { Request } from 'express';

export interface AuthRequest extends Request {
  user: UserInRequest;
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

type CookieMap = {
  [P in keyof Cookies]: P;
};

export const COOKIE_KEYS: CookieMap = {
  Authentication: 'Authentication',
  Refresh: 'Refresh',
  DeviceId: 'DeviceId',
};
