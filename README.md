## Auth
// header content ["Set-Cookie"]

### Cookie Parse
npm i @types/cookie-parser
npm i cookie-parser

import * as cookieParser from 'cookie-parser';
app.use(cookieParser());

UserService
(if use this service, please excluding password/token fields before returning)

AuthService
(every methods already excluded password/token)


```typescript
class UserService implements IUserService

AuthModule.forRoot(authModuleOptions(), UserService),
```