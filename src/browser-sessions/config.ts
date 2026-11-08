/**
 * Browser session capability gate (C36).
 *
 * The capability is off unless `ATOMIC_BROWSER_SESSIONS_ENABLED` is exactly `true`.
 * When enabled, `ATOMIC_BROWSER_ALLOWED_ORIGINS` must list one or more exact HTTPS
 * origins (comma separated). Any invalid entry fails closed as `misconfigured`.
 */
export type BrowserSessionGate =
  | { readonly state: 'disabled' }
  | { readonly state: 'misconfigured' }
  | { readonly state: 'enabled'; readonly allowedOrigins: ReadonlySet<string> };

export type EnvironmentSource = Readonly<Record<string, string | undefined>>;

export const BROWSER_SESSIONS_FLAG = 'ATOMIC_BROWSER_SESSIONS_ENABLED';
export const BROWSER_ALLOWED_ORIGINS = 'ATOMIC_BROWSER_ALLOWED_ORIGINS';

export function readBrowserSessionGate(env: EnvironmentSource): BrowserSessionGate {
  if (env[BROWSER_SESSIONS_FLAG] !== 'true') return { state: 'disabled' };

  const entries = (env[BROWSER_ALLOWED_ORIGINS] ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
  if (entries.length === 0) return { state: 'misconfigured' };

  const allowedOrigins = new Set<string>();
  for (const entry of entries) {
    const origin = parseExactHttpsOrigin(entry);
    if (origin === undefined) return { state: 'misconfigured' };
    allowedOrigins.add(origin);
  }
  return { state: 'enabled', allowedOrigins };
}

function parseExactHttpsOrigin(value: string): string | undefined {
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.origin !== value) return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

export interface BrowserSessionPolicy {
  /** Hard lifetime of an authenticated session family, regardless of activity. */
  readonly absoluteTtlMs: number;
  /** Maximum inactivity before an authenticated session expires. */
  readonly idleTtlMs: number;
  /** Age after which the session id is rotated on the next authenticated request. */
  readonly rotationIntervalMs: number;
  /** Lifetime of a pre-authentication session (login start). */
  readonly preAuthTtlMs: number;
}

export const DEFAULT_BROWSER_SESSION_POLICY: BrowserSessionPolicy = {
  absoluteTtlMs: 12 * 60 * 60 * 1000,
  idleTtlMs: 30 * 60 * 1000,
  rotationIntervalMs: 15 * 60 * 1000,
  preAuthTtlMs: 10 * 60 * 1000,
};
