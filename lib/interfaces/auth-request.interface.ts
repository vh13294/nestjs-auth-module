import { Request } from 'express';

export interface AuthRequest extends Request {
  user: {
    id: number;
    email: string;
  };
  cookies: Cookies;
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
