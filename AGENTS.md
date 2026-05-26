# UniAuth Express Adapter Rules

## Ownership Boundary

This repository implements Express routes and middleware for UniAuth.

It may own:

- Express router composition
- request body validation
- cookie and bearer session transport
- HTTP error mapping
- CSRF integration points
- typed route contracts

It must not own:

- auth business logic
- database access
- Drizzle integration
- Nest/Fastify/Nuxt adapters
- UI

## Public API

Use public `@alyldas/uniauth-core` contracts and facades only. Applications own service construction
and pass `auth.public`, `auth.account`, and `auth.admin` facades into this adapter.

## Local Core Setup

Before running adapter tests against local UniAuth, build `../uniauth-core` first:

```sh
cd ../uniauth-core
npm install
npm run build
```

Then return to this repository and run:

```sh
npm install
npm run check
```

## Expected Checks

Run `npm run check` outside the sandbox when tests need to bind a local HTTP server.
