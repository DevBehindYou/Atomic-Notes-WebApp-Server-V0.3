# AppServer delegation client (C38)

Status: implemented behind a default-off gate and proven only against a fake AppServer
transport and a test key generated at runtime. No signing key, AppServer URL or transport
is wired by default, so no outbound call is possible in any deployed configuration.
`GET /api/ready` is unchanged (`appserver_delegation: "unimplemented"`).

## Pinned AppServer contract

| Item | Value |
| --- | --- |
| Repository | DevBehindYou/Atomic-Notes-Server-V0.3, PR #100 (`claude/c38-delegation-validator`) |
| Pinned commit | `bc815942e60e21c37460674becaa092cb5b98ade` |
| Fixture | `tests/fixtures/delegation/assertion.v1.json`, copied byte for byte from that commit |
| Contract | `atomic-delegation` v1, header `atomic-delegation-v1`, Ed25519 |
| Verifier | `POST /api/delegation/verify` (AppServer gate `ATOMIC_DELEGATION_VERIFY_ENABLED`, default off) |

`tests/delegation.test.ts` asserts the copy is canonical, that `src/delegation/contract.ts`
matches every constant in it, that this client produces the fixture's exact signing input
and `sid`, and that this file records the pinned commit. If the AppServer fixture changes,
the fixture and the pin are updated together.

## Gate

| `ATOMIC_BROWSER_SESSIONS_ENABLED` | `ATOMIC_APPSERVER_DELEGATION_ENABLED` | `POST /api/session/delegation` |
| --- | --- | --- |
| not `true` | any | Not registered (`404 not_found`) |
| `true` | not `true` | Not registered (`404 not_found`) |
| `true`, sessions misconfigured | `true` | `503 browser_sessions_unavailable` |
| `true` | `true`, but `ATOMIC_APPSERVER_DELEGATION_AUDIENCE`, `ATOMIC_GATEWAY_DELEGATION_ISSUER` or `ATOMIC_GATEWAY_DELEGATION_KEY_ID` invalid | `503 delegation_unavailable` |
| `true` | `true`, valid, but no injected signer and transport (the default export) | `503 delegation_unavailable` |
| `true` | `true`, valid, with ports injected by code (tests only) | Enabled |

None of these variables is a secret. The signer and transport are code-injected ports
(`createApp({delegation: {signer, transport}})`), never read from the environment.
**Do not set either flag in any deployed environment.**

## Route (enabled only)

`POST /api/session/delegation`, behind the C37 guard (exact allowlisted `Origin`,
`Content-Type: application/json`, the session's `X-Atomic-CSRF` token, `405` for other
methods). The request body is never read.

| Case | Response | Outbound call |
| --- | --- | --- |
| Authenticated session, AppServer confirms | `200 {"delegated": true, "scope": ["notes:read"], "expiresAt": ISO-8601}` | one |
| No, pre-auth or expired session | `401 session_required` | none |
| Missing or wrong token / origin | `403 csrf_rejected` / `403 origin_rejected` | none |
| Session account is not an AppServer account id (UUID) | `503 delegation_unavailable` | none |
| AppServer refuses, or confirms a different `iss`/`sub`/`scope`/`exp` | `502 delegation_rejected` | one |
| Transport unavailable or throws | `503 delegation_unavailable` | one |

## Assertion construction

`DelegationClient` (`src/delegation/client.ts`) builds claims from the server-side
`SessionRecord` only:

- `sub` is the record's `accountId`. No browser field, header or path parameter is an input.
- `sid` is `base64url(sha256("atomic-delegation/sid/v1" 0x00 familyId))`, so the AppServer never
  sees the family id, the session id or its hash.
- `aud`, `iss` and `kid` come from the gate, and `scope` is `["notes:read"]` (the only v1 scope).
- `iat` is now. `exp` is the earlier of `iat + 300 s` and the session's absolute or idle deadline.
  `jti` is 128 random bits.

The assertion is signed through `DelegationSigner`, sent through `DelegationTransport`, and is
never returned to the browser or stored. The session store still holds no provider token,
AppServer bearer, assertion or key. `httpDelegationTransport` (not wired) posts only
`{"assertion"}` with no cookie or Authorization header, `redirect: "error"` and a 3 s timeout.

## Open decisions

1. Signing key custody and rotation (KMS or platform secret, `kid` rollover), and publishing
   the public key to the AppServer.
2. AppServer audience naming per deployment.
3. Scope set beyond `notes:read`. Wallet, Energy and billing stay out.
4. AppServer replay store durability.
5. How the AppServer records the `(iss, sid) -> account` binding it re-checks, for example
   during a login exchange that replaces the C36 fixture verifier, and revokes it at logout.
6. Which gateway feature consumes a confirmed delegation (this route only proves the path).
