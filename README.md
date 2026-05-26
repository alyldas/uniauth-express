# UniAuth Express

Express routes and middleware for UniAuth.

This package is a transport adapter.

## Runtime Boundary

This package does not create a UniAuth service, access a database, or implement authentication
rules. Applications pass a service with `auth.public`, `auth.account`, and `auth.admin` facades into
the adapter.

## Install

```sh
npm install @alyldas/uniauth-express @alyldas/uniauth-core express
```

## Usage

```ts
import express from "express";
import { createUniAuthExpressRouter } from "@alyldas/uniauth-express";

const app = express();

app.use(express.json());
app.use(
  "/auth",
  createUniAuthExpressRouter({
    auth,
    adminGuard: requireAdmin,
    session: {
      cookie: {
        name: "session",
        options: {
          httpOnly: true,
          sameSite: "lax",
          secure: true,
          path: "/",
        },
      },
    },
  }),
);
```

Session transport reads `Authorization: Bearer <token>` first and then a session cookie. Public
sign-in routes can write the returned session token to a cookie when cookie transport is enabled.

## Routes

Public routes:

- `POST /provider/sign-in`
- `POST /password/sign-in`
- `POST /otp/start`
- `POST /otp/resend`
- `POST /otp/sign-in`
- `POST /magic-link/start`
- `POST /magic-link/resend`
- `POST /magic-link/finish`
- `POST /password-recovery/start`
- `POST /password-recovery/resend`

Account routes require a bearer token or configured session cookie:

- `GET /account/session`
- `POST /account/session/refresh`
- `GET /account/security`
- `GET /account/inspection`
- `POST /account/inspection/audit`
- `GET /account/closure-export`
- `PATCH /account/profile`
- `POST /account/contact/start`
- `POST /account/contact/resend`
- `POST /account/contact/cancel`
- `POST /account/contact/finish`
- `POST /account/password/set`
- `POST /account/password/confirm`
- `POST /account/password/change`
- `POST /account/re-auth/status`
- `POST /account/re-auth/assert`
- `POST /account/re-auth/otp/start`
- `POST /account/re-auth/otp/resend`
- `POST /account/re-auth/otp/cancel`
- `POST /account/re-auth/otp/finish`
- `POST /account/re-auth/password/confirm`
- `POST /account/sessions/revoke-current`
- `POST /account/sessions/revoke-owned`
- `POST /account/sessions/revoke-other`
- `POST /account/identities/link`
- `POST /account/identities/unlink`
- `POST /account/closure/close`

Admin routes are mounted under `/admin` and require the supplied `adminGuard` middleware. The
adapter returns `403` when admin routes are used without a guard.

## Security Notes

- Configure secure, HTTP-only cookies when using cookie session transport.
- Keep CSRF protection application-owned and pass middleware into the adapter where needed.
- Do not pass database handles or persistence adapters into this package.

## Local Checks

```sh
npm run check
```
