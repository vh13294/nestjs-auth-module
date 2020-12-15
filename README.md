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

```ENV
JWT_ACCESS_TOKEN_SECRET=123
JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE=900
JWT_REFRESH_TOKEN_SECRET=abc
JWT_REFRESH_TOKEN_ABSOLUTE_EXPIRATION_TIME_DAY=90
JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY=14
JWT_REFRESH_TOKEN_MAX_NUMBER_ISSUED=15
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
- Add unit test in sample (for controller flows?)
- Handle when refresh-token expires (or no longer exist) update cookie header? logout?
- Handle when access-token expires, by rotating token?