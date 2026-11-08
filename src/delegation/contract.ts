import { createHash } from 'node:crypto';

/**
 * AppServer delegation assertion, contract v1 (C38).
 *
 * Restated from the AppServer verifier (Atomic-Notes-Server-V0.3 `src/lib/delegation.ts`)
 * and pinned by the shared fixture `tests/fixtures/delegation/assertion.v1.json`, copied
 * byte for byte from the AppServer commit recorded in docs/APPSERVER_DELEGATION.md.
 *
 * Wire form: `atomic-delegation-v1.<base64url(canonical claims JSON)>.<base64url(Ed25519 signature)>`,
 * signed over the ASCII bytes `<header>.<payload>`.
 */
export const DELEGATION_CONTRACT = 'atomic-delegation';
export const DELEGATION_CONTRACT_VERSION = 1;
export const DELEGATION_HEADER = 'atomic-delegation-v1';
export const DELEGATION_ALGORITHM = 'Ed25519';
/** The only scope v1 defines. There is no wallet, Energy, billing or write scope. */
export const DELEGATION_SCOPES = ['notes:read'] as const;
export const MAX_ASSERTION_BYTES = 2048;
export const MAX_LIFETIME_SECONDS = 300;
export const CLOCK_SKEW_SECONDS = 30;
export const CLAIM_ORDER = ['v', 'aud', 'iss', 'kid', 'sub', 'sid', 'scope', 'iat', 'exp', 'jti'] as const;
export const SESSION_REFERENCE_CONTEXT = 'atomic-delegation/sid/v1';
export const VERIFY_PATH = '/api/delegation/verify';

export type DelegationScope = (typeof DELEGATION_SCOPES)[number];

export interface DelegationClaims {
  readonly v: typeof DELEGATION_CONTRACT_VERSION;
  readonly aud: string;
  readonly iss: string;
  readonly kid: string;
  readonly sub: string;
  readonly sid: string;
  readonly scope: readonly DelegationScope[];
  readonly iat: number;
  readonly exp: number;
  readonly jti: string;
}

/** AppServer account ids are lowercase UUIDs. Anything else cannot be delegated. */
export const APPSERVER_ACCOUNT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const GATEWAY_ISSUER = /^[a-z0-9][a-z0-9-]{0,62}$/;
export const KEY_ID = /^[A-Za-z0-9_-]{1,64}$/;
export const AUDIENCE = /^[\x21-\x7e]{1,256}$/;

/**
 * Opaque reference to a browser session family. The AppServer never learns the family
 * id, the session id or its hash; it only sees this derived value.
 */
export function sessionReference(familyId: string): string {
  return createHash('sha256').update(`${SESSION_REFERENCE_CONTEXT}\0${familyId}`, 'utf8').digest('base64url');
}

export function canonicalClaimsJson(claims: DelegationClaims): string {
  return JSON.stringify(Object.fromEntries(CLAIM_ORDER.map((key) => [key, claims[key]])));
}

export function signingInput(claims: DelegationClaims): string {
  return `${DELEGATION_HEADER}.${Buffer.from(canonicalClaimsJson(claims), 'utf8').toString('base64url')}`;
}
