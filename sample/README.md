## Installation

```bash
$ npm install
```

## Running the app

```bash
# watch mode
$ npm run start:dev
```

## Prisma

npx prisma init
npx prisma introspect // after database schema changes
npx prisma generate // after database schema changes
npx prisma studio

npx prisma db push // generate & sync db
npx prisma migrate reset // needed when push is blocked

## Docker

docker-compose up -d

## Test FB login https

npm install --save @nestjs/serve-static
https only work in safari

## Test HTTPS client on chrome

- Simply click anywhere on the denial page and type “thisisunsafe”.
- Disable ad-blocker
