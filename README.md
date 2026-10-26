# Atomic Notes WebApp Server V0.3

Dedicated browser-specific backend workspace for Atomic Notes, maintained by DevBehindYou. The frontend is `DevBehindYou/Atomic-Notes-WebApp-V0.3` and continues in Flutter Web.

This public source-available repository separates browser session/authentication, origin/CSRF policy and browser gateway modules from Android Server optimization. Shared MongoDB/Drive/financial mutations still require one reviewed authoritative implementation. A second repository is not permission to run an independent competing writer against existing data.

The Node.js 22 / TypeScript / Hono foundation can be deployed independently to Vercel. `GET /api/health` confirms process liveness; `GET /api/ready` deliberately returns 503 because browser sessions and AppServer delegation are unimplemented. No browser authentication, note APIs, persistence or shared-data writes are enabled. See [architecture and acceptance](docs/ARCHITECTURE.md) and [staging deployment](docs/DEPLOYMENT.md).

For local verification, use Node.js 22, `npm ci --ignore-scripts`, then `npm run verify`. `npm run dev` serves only on `http://127.0.0.1:3001`; the deployed entrypoint is the default Hono export in `src/app.ts`.

Android readiness is tracked separately from WebApp progress. A green foundation build is not browser session, note-sync or Android acceptance. Final Server links require verified deployed endpoints.
