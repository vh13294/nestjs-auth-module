## ["Set-Cookie"] Auth

- Require Cookie Parser

- Database / ORM agnostic

- Only need to implement IUserService

## Usage

```typescript
class UserServiceImplForAuth implements IUserService {}

AuthModule.forRoot({
  env: {}
  userServiceImplementation: UserServiceImplForAuth
}),
```

- Example user implementation using prisma

[user-service-implementation.ts](https://github.com/vh13294/nestjs-auth-module/blob/main/sample/src/authModule/user-service-implementation.ts)

- DB schema

[schema.prisma](https://github.com/vh13294/nestjs-auth-module/blob/main/sample/prisma/schema.prisma)

```ENV
JWT_ACCESS_TOKEN_SECRET=123
JWT_ACCESS_TOKEN_EXPIRATION_TIME_MINUTE=900
JWT_REFRESH_TOKEN_SECRET=abc
JWT_REFRESH_TOKEN_ABSOLUTE_EXPIRATION_TIME_DAY=90
JWT_REFRESH_TOKEN_INACTIVE_EXPIRATION_TIME_DAY=14
JWT_REFRESH_TOKEN_MAX_NUMBER_ISSUED=15

FACEBOOK_CLIENT_ID=1
FACEBOOK_CLIENT_SECRET=1
FACEBOOK_GRAPH_VERSION=v9.0

HTTPS_ONLY=TRUE
```

## Auth Flow

### Register

- Use email/password sign up

### Login (return cookies)

- For web cookies header automatically attach to request
- For mobile/flutter, we have to manually save cookie

### When Access Token Invalid (401)

- Call to renew Token which return new access token,
  and reset max-age of refresh Token
- Clear global state login=false
- If request token is valid, return new cookie, set login=true

### When Refresh Token Invalid (401)

- Redirect front-end to login page

### User Access Forbidden resource (403)

- Ex: User view manager Inventory
- Handling? Show error message and no redirect!

## Avoid 401 Loop

- We might need two instance of http client (avoid clashing interceptor)

  - User use Http1 to access protected route, but access token is expired (401)
  - Interceptor of Http1 is trigger
  - Http1 call to renew access token using refresh token
  - However refresh token is also invalid (401)
  - If we use Http1 instance we get in 401 Loop

- Solution

  - Using Http2 to renew token, if 401 occur redirect to login page
  - Pause all Http1 instance or lock until Http2 is resolved

  - Or send 403 for invalid refresh token (skip 401 loop)

## Social

- use front-end specific SDK, web/flutter
- Create a "Continue With FB" button, should trigger facebook login
- Get fb_access_token, => send it to continue-via-facebook
- Verify token, and get email/names
- If email exist in db, check if user have facebookID attach, return jwt cookies
- If email exist in db, but no facebookID, return warning ask user to use email/password instead
- If email does not exist in db,

  - Create new user via fb-email, names
  - Password should be empty
  - if success, return jwt cookies

- For FB, InternalOAuthError: Failed to fetch user profile, might also mean incorrect appKey/appID

## Refresh token inactive policy

- Refresh Token Cookie Max-Age will be used as inactive time,
  It will be reset when issuing new access-token,

- Absolute life time time will be stored in jwt.signToken(),
  which will be validated in Strategy

## Front-end handling

- On page load, that point to open route
  - get User obj using access token, ignore error such as 400+
  - if valid set global state login=true
  - otherwise set login=false
- On page load, that point to protected route
  - check access token, then refresh token,
  - Redirect to login page if 401
  - typically handle by front end router
- Avoid or block login page global state login=true

## Back-end handling

- Run cronjob to clean expired refreshToken based on (createdAt)

## TODO

- Add ? Role authorization??
- Add unit test in sample (for controller flows?)
- search for // todo
