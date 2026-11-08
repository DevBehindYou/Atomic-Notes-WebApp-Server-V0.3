import type { EnvironmentSource } from '../browser-sessions/config.js';
import { AUDIENCE, GATEWAY_ISSUER, KEY_ID } from './contract.js';

/**
 * AppServer delegation gate (C38).
 *
 * Off unless `ATOMIC_APPSERVER_DELEGATION_ENABLED` is exactly `true`, and only ever
 * reachable when browser sessions (C36) are enabled too. When on, the audience, gateway
 * issuer id and key id must all be valid, or the gate fails closed as `misconfigured`.
 * None of these values is a secret; the signing key and the HTTP transport are ports
 * injected by code, never read from the environment here.
 */
export type DelegationGate =
  | { readonly state: 'disabled' }
  | { readonly state: 'misconfigured' }
  | { readonly state: 'enabled'; readonly audience: string; readonly issuer: string; readonly keyId: string };

export const DELEGATION_FLAG = 'ATOMIC_APPSERVER_DELEGATION_ENABLED';
export const DELEGATION_AUDIENCE = 'ATOMIC_APPSERVER_DELEGATION_AUDIENCE';
export const DELEGATION_ISSUER = 'ATOMIC_GATEWAY_DELEGATION_ISSUER';
export const DELEGATION_KEY_ID = 'ATOMIC_GATEWAY_DELEGATION_KEY_ID';

export function readDelegationGate(env: EnvironmentSource): DelegationGate {
  if (env[DELEGATION_FLAG] !== 'true') return { state: 'disabled' };
  const audience = env[DELEGATION_AUDIENCE] ?? '';
  const issuer = env[DELEGATION_ISSUER] ?? '';
  const keyId = env[DELEGATION_KEY_ID] ?? '';
  if (!AUDIENCE.test(audience) || !GATEWAY_ISSUER.test(issuer) || !KEY_ID.test(keyId)) return { state: 'misconfigured' };
  return { state: 'enabled', audience, issuer, keyId };
}
