# Browser session lifecycle (C36)

Status: implemented behind a default-off capability and proven only against controlled
fixtures. No real OAuth provider, client secret, durable store or AppServer delegation is
wired. `GET /api/ready` still returns the same 503 body in every configuration.

## Capability gate

| `ATOMIC_BROWSER_SESSIONS_ENABLED` | `ATOMIC_BROWSER_ALLOWED_ORIGINS` | Session routes |
| --- | --- | --- |
| unset or anything other than `true` | ignored | Not registered. Every path returns the existing `404 {"error":"not_found"}` |
| `true` | missing, empty or any entry that is not an exact `https://host[:port]` origin | `503 {"error":"browser_sessions_unavailable"}` |
| `true` | one or more exact HTTPS origins, comma separated | Enabled |

`createApp()` with no options reads an empty environment, so every capability is off.
The deployed default export reads `process.env`. **Do not set the flag in any deployed
environment.** The default wiring uses a process-local memory store and has no identity
verifier, so login answers `503 {"error":"identity_unavailable"}`. Enabling it requires a
reviewed durable store, a reviewed identity verifier, C37 CSRF policy and an owner decision.

## Routes (enabled only)

| Route | Origin | Behavior |
| --- | --- | --- |
| `GET /api/session` | optional, allowlisted if present | Non-secret status. May rotate the id |
| `GET /api/session/accounts/:accountId` | optional, allowlisted if present | `200` status when the session owns `accountId`; `401 session_required`; `403 account_mismatch` |
| `POST /api/session/start` | required | Revokes any presented session and issues a pre-authentication session (10 minutes) |
| `POST /api/session/login` | required | JSON `{"assertion": "..."}` verified by the `IdentityVerifier` port. Always issues a new id |
| `POST /api/session/logout` | required | Deletes the session family server-side and clears the cookie. Idempotent |

The browser only ever receives `{"signedIn": false}` or
`{"signedIn": true, "accountHint"?: string, "expiresAt": ISO-8601}`. `expiresAt` is the earlier of the
absolute and idle deadlines. The fixed error bodies are `origin_rejected` (403), `invalid_request`
(400), `identity_rejected` (401), `identity_unavailable` (503), `session_required` (401) and
`account_mismatch` (403).

## Cookie

```
__Host-atomic_session=<43 base64url chars>; Path=/; Max-Age=<seconds to absolute expiry>; HttpOnly; Secure; SameSite=Strict
```

The cookie has no `Domain`. Clearing uses the same attributes with an empty value and `Max-Age=0`.
The value is a 256-bit random id from `crypto.randomBytes`. Malformed, empty or duplicated
session cookies are cleared and never interpreted.

## Server-side references

`SessionStore` is a port (`src/browser-sessions/store.ts`). A record holds the SHA-256 hash of the
current id, a random family id, the account id (or `null` before login), a bounded non-secret
account hint, the issuing origin and timestamps. Raw ids, provider tokens and AppServer
bearer tokens are never stored. A store leak cannot be replayed as a cookie.
`MemorySessionStore` is for tests and local development only. It is not shared across
serverless instances.

## Lifecycle rules

- **Fixation:** an id the store does not recognise is never adopted. It is cleared. Login and
  start revoke whatever id was presented (pre-authentication, another account or the same
  account) and always issue a fresh id.
- **Expiry:** authenticated sessions have a 12-hour absolute and a 30-minute idle limit.
  Pre-authentication sessions have a 10-minute absolute limit. Expired families are deleted
  when they are presented. The memory store also prunes expired families on insert.
- **Rotation:** an authenticated id older than 15 minutes is replaced on the next `GET` session
  request through an atomic compare-and-swap. The response sets the new cookie. The old id is
  retired immediately.
- **Replay:** presenting a retired id is treated as a theft signal. The whole family is revoked,
  including the current id, and the cookie is cleared.
- **Logout:** deletes the family, including retired ids, and clears the cookie.
- **Origin binding:** a session is bound to the allowlisted origin that created it. A request
  that presents a different Origin, even another allowlisted one, receives `403` and the
  session is left intact.
- **Account binding:** a session for account A gets `403` on account B's scope. Logging in as B
  while holding A's cookie revokes A's session.

## Origin policy (minimal; full CSRF is C37)

Unsafe methods require an `Origin` header in the allowlist. Any presented `Origin` must be
allowlisted. `Sec-Fetch-Site: cross-site` is rejected. Login also requires
`Content-Type: application/json` and a body of at most 8 KiB of valid UTF-8, counted on the
bytes actually read (a missing or false `Content-Length` cannot raise it; reading stops and
the stream is cancelled at the cap). C37 owns the complete
CSRF/state/fetch-metadata policy. No CORS headers are emitted. The browser app and this
gateway must be same-site, ideally same-origin, for `SameSite=Strict` cookies to be sent.

## Identity port

`IdentityVerifier.verify({assertion, origin})` returns `{accountId, accountHint?, credentials?}` or
`null`. Credentials a future real verifier might obtain are discarded in C36. They never reach a
response, a header or the store. Credential custody for AppServer delegation is C38. Tests use
`tests/support/identity-fixture.ts`, which returns canary token values to prove this.

## Dependencies and contract pins

C22 and C26 (AppServer) are merged. C30 (AppServer capability contract, Server PR #98) is
pinned by contract only: this gateway does not call the AppServer, and `delegation` remains
`unsupported`. Delegation is C38.

## Open decisions

1. A durable store (TTL index, atomic rotate) before any deployment enables the flag.
2. A rotation grace window for concurrent tabs. There is currently none, so a request racing a
   rotation can revoke the family. This is the strict choice.
3. The deployment topology. A same-origin rewrite or a shared registrable domain is needed for
   `SameSite=Strict`, and `vercel.app` subdomains are cross-site.
4. Whether `expiresAt` should also expose the absolute deadline separately.
5. Pre-authentication session binding to C37 OAuth `state`/PKCE.
