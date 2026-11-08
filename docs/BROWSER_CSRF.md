# Browser session origin and CSRF policy (C37)

Status: implemented inside the C36 default-off gate (`ATOMIC_BROWSER_SESSIONS_ENABLED`).
With the flag off every session path still returns `404 {"error":"not_found"}`, for every
method. Nothing here enables the capability in any deployed environment. Code:
`src/browser-sessions/csrf.ts` and `src/browser-sessions/routes.ts`. Tests:
`tests/browser-csrf.test.ts`.

## Topology assumption

The browser app and this gateway are **same-origin** (a same-origin rewrite in front of
the gateway). The gateway therefore never emits CORS headers. A cross-origin page cannot get
a preflight approved, cannot read a session response and cannot attach the JSON body or the
custom token header that unsafe requests need. Deployment topology is still an open
decision in `BROWSER_SESSIONS.md`.

## Request guard

One guard runs on each session route before its handler, in this order. Each check fails
closed and nothing reads, creates, touches or revokes a session first.

| Order | Check | Applies to | Failure |
| --- | --- | --- | --- |
| 1 | Method is exactly the route's method. HEAD, OPTIONS (preflight), PUT, PATCH and DELETE never reach a handler | all | `405 {"error":"method_not_allowed"}` with `Allow: GET` or `Allow: POST` |
| 2 | `Sec-Fetch-Site`, if present, is `same-origin`. `cross-site`, `same-site`, `none` and unknown values are refused | all | `403 {"error":"origin_rejected"}` |
| 3 | `Origin` is byte-for-byte one of the allowlisted origins. Required on POST. Checked on GET when present | all | `403 {"error":"origin_rejected"}` |
| 4 | `Content-Type` is `application/json` (parameters and case allowed). HTML forms can only send `application/x-www-form-urlencoded`, `multipart/form-data` or `text/plain` | POST | `415 {"error":"unsupported_media_type"}` |
| 5 | Anti-CSRF token in `X-Atomic-CSRF` matches the presented session. Checked in the route once the session is resolved, before any body is read | POST that presents a live session | `403 {"error":"csrf_rejected"}`, session untouched |

Exact matching means `null`, a missing header, another scheme (`http:`, `wss:`), another
port (including an explicit `:443`), a suffix or prefix look-alike (`app.atomic.test.evil.invalid`,
`evilapp.atomic.test`), a subdomain, a different case, a trailing path and a combined
duplicate header are all rejected. The allowlist itself only accepts exact HTTPS origins (C36).

Routes and methods:

| Route | Method | Token required |
| --- | --- | --- |
| `GET /api/session` | GET | no. Returns the token when a session is live |
| `GET /api/session/accounts/:accountId` | GET | no. Returns the token on `200` |
| `POST /api/session/start` | POST | yes, when a live session is presented (start revokes it) |
| `POST /api/session/login` | POST | yes, when a live session is presented (pre-auth or authenticated; login revokes it) |
| `POST /api/session/logout` | POST | yes, when a live session is presented |

An unknown, malformed, expired or retired cookie is not a session to protect. It is never
adopted, so a POST that presents one needs no token. Expired and retired ids are still
revoked as in C36.

## Anti-CSRF token

- **Value:** `base64url(HMAC-SHA-256(key = raw 256-bit session id, "atomic-notes/browser-session/csrf/v1"))`,
  43 characters. Only a holder of the HttpOnly session cookie can compute it, and the token
  does not reveal the id.
- **Storage:** none. Neither the token nor a hash of it is stored. A store leak (id hashes,
  family ids) yields no token. The C37 brief proposed storing a SHA-256 of a random token.
  That cannot be returned again by `GET /api/session` after a page reload, so the token is
  derived instead. This is a deliberate deviation for review.
- **Delivery:** only in JSON response bodies (`csrf` field) of `start`, `login` and the two
  GET status routes. It is never set in a cookie, a header or a URL. Cross-origin pages
  cannot read these bodies because no CORS approval is ever given.
- **Presentation:** only the `X-Atomic-CSRF` request header. A token in the query string
  or JSON body is ignored.
- **Comparison:** the format is checked, then SHA-256 digests of the expected and presented
  values are compared with `crypto.timingSafeEqual`.
- **Rotation and staleness:** the token changes whenever the id changes, through periodic
  rotation, login or start. It stops working when the session ends, through logout,
  revocation, replay detection or expiry. A client that receives a new `Set-Cookie` without
  a token calls `GET /api/session` to get the current one.
- **Rejected requests:** a token failure is decided before the identity verifier runs or the
  body is read, and unsafe routes resolve the session with `touch: false`. A forged request
  therefore does not consume a single-use assertion, extend the idle clock, or rotate or revoke the live session.

## Safe methods

GET routes never create a session, and a GET without a cookie never receives `Set-Cookie`.
HEAD is refused, so it cannot rotate. The only GET-side state changes are the C36 lifecycle
rules on the caller's own cookie: rotating an id that is due, and revoking expired or
replayed ids. Neither can be triggered cross-site, because `SameSite=Strict` withholds the
cookie and fetch metadata and Origin are checked first. State-changing routes refuse GET and
HEAD with `405` and do nothing.

## CORS and caching

- No `Access-Control-Allow-*` header is emitted on any response, including OPTIONS
  preflights from allowlisted or foreign origins. There is no wildcard and no
  `Access-Control-Allow-Credentials` anywhere. Tests check every response.
- `Cache-Control: no-store, no-cache, must-revalidate` stays global (C36).
- Every enabled session response, including errors, carries `Vary: Origin, Cookie`.

## Threats and tests

All in `tests/browser-csrf.test.ts` unless noted.

| Threat | Defence | Test |
| --- | --- | --- |
| Cross-site POST (fetch, form, `sendBeacon`) | Origin allowlist, fetch metadata, JSON media type, token | `unsafe requests need an exact allowlisted Origin…`, `fetch metadata…`, `cross-site form posts are refused…` |
| Forged, `null`, missing or look-alike Origin | Exact string membership | `unsafe requests need an exact allowlisted Origin…` |
| Same-site sibling (another subdomain) | `Sec-Fetch-Site: same-site` refused, Origin not allowlisted | `fetch metadata…` |
| CORS preflight to unlock credentialed calls | OPTIONS is `405` with no CORS headers | `OPTIONS preflight is never approved…` |
| Wildcard or credentialed CORS leak | No `Access-Control-*` on any response | response-policy assertion on every exchange, `the token is never stored…` |
| GET or HEAD mutation (`<img>`, link, prefetch) | `405` on state-changing routes, HEAD refused, GET never creates | `safe and other methods never mutate…` |
| Missing, malformed or forged token | Constant-time check, session left intact | `CSRF token: missing, malformed, forged…` |
| Stale token after rotation | Token derived from the current id | `CSRF token: a token is stale once its session id rotates` |
| Stale token after logout or re-login | Session gone or id replaced | `CSRF token: tokens are stale after logout…` |
| Login CSRF or session swap over a live session | Token required when a session is presented; checked before the verifier | `login and start that act on a presented session…` |
| Cross-origin reuse between two allowlisted origins | Session origin binding (C36) | `a session bound to one origin…` |
| Token leak through the store or cookies | Derived, not stored; body only | `the token is never stored…` |
| Shared-cache mix-up | `no-store` and `Vary: Origin, Cookie` | response-policy assertion on every exchange |
| Flag off | Nothing registered | `flag off…` in `tests/browser-sessions.test.ts` (now also OPTIONS, PUT and DELETE) |

## Client contract (for the future browser app)

1. `GET /api/session` on load. Keep `csrf` in memory only, not in `localStorage`.
2. Send every POST with `Content-Type: application/json` and `X-Atomic-CSRF: <csrf>`
   whenever a session cookie may exist. Use `credentials: 'same-origin'`.
3. Replace the token whenever a response carries a new `csrf`. After a `Set-Cookie` with
   no `csrf`, or after a `403 csrf_rejected`, call `GET /api/session` again.

## Open decisions

1. **OAuth `state` and PKCE.** No real provider exists, so no `state` nonce was added. The
   pre-authentication session from `start` is the natural binding: a future provider flow
   can derive `state` from the pre-auth id the same way as the token, and verify it at the
   callback against the presented pre-auth cookie. Needs the provider decision.
2. **Stored-hash versus derived token.** This PR derives the token. If reviewers prefer a
   random token with a stored hash, `GET /api/session` cannot re-deliver it, and the client
   must keep it across reloads (for example in `sessionStorage`).
3. **`Sec-Fetch-Site: none` on GET.** GETs from the address bar are refused. This is the
   strict choice for an API-only surface.
4. **Same-origin topology.** If the deployment ends up cross-origin, credentialed CORS needs
   a separate reviewed design. It is not supported here.
