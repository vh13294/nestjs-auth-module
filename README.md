## Auth
// header content ["Set-Cookie"]

### Cookie Parse
npm i @types/cookie-parser
npm i cookie-parser

import * as cookieParser from 'cookie-parser';
app.use(cookieParser());

UserService
(if use this service, please excluding password fields before returning)

AuthService
(every methods already excluded password)


```typescript
class UserService implements IUserService

AuthModule.forRoot(authModuleOptions(), UserService),
```

## Refresh token inactive policy
- Refresh Token Cookie Max-Age will be used as inactive time, 
  It will be reset when issuing new access-token,

- Absolute life time time will be stored in jwt.signToken(), which will be validated in Strategy


## Front-end handling
- Avoid or block login page while Authorization Header is present


## Back-end handling
- Run cronjob to clean expired refreshToken based on (createdAt)

## TODO
- Add ? Role authorization??
- Social Login (passport fb, google)
- Set a max refreshToken per user (10 maybe?) delete the oldest, before adding a new one?
- Add Logout all devices
- Add unit test in sample (for controller flows?)
- Handle when refresh-token expires (or no longer exist) update cookie header? logout?
- Handle when access-token expires, by rotating token?