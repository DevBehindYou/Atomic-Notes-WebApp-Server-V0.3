# Browser backend boundary

Owner decision, 16 October 2026: create an independent WebApp backend repository and continue Android optimization in its existing repositories.

## Intended responsibility

Browser sessions and OAuth gateway, HttpOnly cookie lifecycle, CSRF/state/origin checks, owner/session context, browser-safe read-only integration and reviewed adapters to shared domain authority. Reuse the existing Node.js/TypeScript/Hono ecosystem where compatible; do not add an identity store or persistence service merely to separate repositories.

## Shared authority contract

One authoritative coordinator must own note generations, sync operation identities, version/sequence publication, safe-logout settlement and wallet accounting across Android and browser callers. A gateway must not duplicate the current Server's direct writer paths with divergent retention, coin-lot or lease behavior.

The hosting topology and mutation delegation must be documented and proven in disposable integration before any shared production database or Drive write. No production route is enabled by this initial repository. Never persist note plaintext, vault keys, recovery phrases or bearer credentials in project artifacts or diagnostics.

## Acceptance order

1. Agree the exact browser session/delegation contract against accepted Android Server main, using sanitized fixtures and no real credentials.
2. Establish locked dependency resolution, strict typechecks, bounded health/configuration behavior and CI in a focused PR.
3. Prove browser read-only auth, cookie/CSRF/origin/owner isolation and revocation.
4. Prove mutation delegation, replay/fencing, retained-operation/financial compatibility and rollback before exposing browser writes.
5. Verify real provider registrations and concrete deployment configuration only when supplied and approved by the owner.

Independent repositories and release schedules must preserve the same data invariants. Android Server 2.03.9 readiness is a separate decision, not implied by a green browser build.
