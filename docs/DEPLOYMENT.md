# Independent Vercel staging foundation

Suggested project name: `atomic-notes-webapp-server-staging`. Create a separate Vercel project for `DevBehindYou/Atomic-Notes-WebApp-Server-V0.3`, with this repository root as its Root Directory. Keep it independent from the AppServer staging project and all existing production projects.

## Build and runtime

- Runtime: Node.js `22.x`, also declared in `package.json`.
- Framework: Hono, using Vercel's recognized `src/app.ts` default Hono export. No custom rewrites, legacy API adapter or `vercel.json` is required.
- Install command: `npm ci --ignore-scripts`.
- Build command: `npm run build` (strict TypeScript compilation).
- Output Directory: leave unset; Vercel serves the Hono application, not a static `dist` directory.
- Required application environment variables: **none** for this foundation. Do not copy AppServer, OAuth, MongoDB, Drive or production credentials into it.

The source entrypoint starts no listener. `src/dev.ts` is a separate local-only adapter used by `npm run dev` at `http://127.0.0.1:3001`. To exercise Vercel's own default-export development path after installing a reviewed Vercel CLI, use `vercel dev` from this repository. Current platform behavior is documented in [Hono on Vercel](https://vercel.com/docs/frameworks/backend/hono).

Run `npm run verify` before deployment. CI installs the committed lockfile, typechecks runtime and tests, checks request behavior, builds, then probes the compiled default export. These checks do not invoke Vercel or require an account.

## Health is not browser readiness

`GET /api/health` returns 200 with exactly:

```json
{"status":"ok","service":"atomic-notes-webapp-server"}
```

`GET /api/ready` deliberately returns 503 with exactly:

```json
{"status":"not_ready","service":"atomic-notes-webapp-server","browser_session":"unimplemented","appserver_delegation":"unimplemented"}
```

HEAD probes preserve the corresponding status and headers without a body. Unsupported routes and methods return 404 with `{"error":"not_found"}`. Unexpected application errors return 500 with `{"error":"internal_server_error"}`. Responses include `Cache-Control: no-store, no-cache, must-revalidate` and `X-Content-Type-Options: nosniff`. No request URL, exception message, stack or environment value is returned. This app creates no cookies and grants no cross-origin access.

After the owner connects the intended Vercel team and project, deploy only to the isolated staging project and check those two endpoints against the actual URL. Confirm the reported service identity to distinguish it from AppServer. Record the deployed commit and URL. A successful deployment and a 200 health result prove only that this bounded foundation is serving; readiness must remain 503 at this stage. No deployment has been proven by the local build alone.

## Isolation and next acceptance gates

Use separate Vercel project settings and environment scopes for staging. Later OAuth clients, redirect URIs, browser origins, session configuration and disposable data/provider resources require explicit stage-specific configuration. A staging project's Vercel Production environment is still staging infrastructure; it must never inherit the existing production service's credentials or data targets. Keep Deployment Protection where available and account for it when probing.

Before readiness can change, agree the exact browser-session and delegation contract against the accepted AppServer main. AppServer remains the sole authority for note generations, operation identities, version/sequence publication, logout settlement and wallet accounting. This repository must not acquire independent MongoDB, Drive or financial writer paths.

Subsequent focused changes must prove session ownership, HttpOnly cookie lifecycle, CSRF/state/origin enforcement and revocation, followed by delegated mutation replay/fencing, retention and financial compatibility, safe logout, disposable integration and rollback. Browser acceptance requires those flows end to end against verified deployed endpoints; foundation CI cannot establish them.
