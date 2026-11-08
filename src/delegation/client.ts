import { randomBytes } from 'node:crypto';
import type { SessionRecord } from '../browser-sessions/store.js';
import {
  APPSERVER_ACCOUNT_ID,
  DELEGATION_CONTRACT,
  DELEGATION_CONTRACT_VERSION,
  DELEGATION_SCOPES,
  MAX_ASSERTION_BYTES,
  MAX_LIFETIME_SECONDS,
  VERIFY_PATH,
  sessionReference,
  signingInput,
  type DelegationClaims,
  type DelegationScope,
} from './contract.js';

/**
 * Signing port. Holds the gateway's Ed25519 private key (or a KMS handle) outside the
 * session store. Returns the 64-byte signature over [input]. Tests use a key generated
 * at runtime.
 */
export interface DelegationSigner {
  sign(input: Uint8Array): Promise<Uint8Array>;
}

/** What the AppServer answered, as plain data. */
export type TransportResult =
  | { readonly kind: 'verified'; readonly body: unknown }
  | { readonly kind: 'rejected'; readonly error: string }
  | { readonly kind: 'unavailable' };

/** HTTP port to `POST /api/delegation/verify`. The only outbound call the client makes. */
export interface DelegationTransport {
  verify(assertion: string): Promise<TransportResult>;
}

export interface DelegationClientOptions {
  readonly audience: string;
  readonly issuer: string;
  readonly keyId: string;
  readonly signer: DelegationSigner;
  readonly transport: DelegationTransport;
  /** Idle limit of browser sessions, so an assertion never outlives its session. */
  readonly idleTtlMs: number;
  readonly clock?: () => number;
}

export type DelegationOutcome =
  | { readonly ok: true; readonly scope: readonly DelegationScope[]; readonly expiresAt: number }
  | { readonly ok: false; readonly reason: 'session_required' | 'account_unsupported' | 'appserver_rejected' | 'appserver_unavailable' };

/**
 * Builds a delegation assertion for one authenticated browser session from the
 * server-side session record ONLY: `sub` is the record's account id, `sid` is derived
 * from its family id. Nothing from the browser request is an input, so a request that
 * names another account cannot change `sub`. The assertion is sent to the AppServer and
 * never returned or stored; no provider token or AppServer bearer is involved.
 */
export class DelegationClient {
  readonly #options: DelegationClientOptions;
  readonly #clock: () => number;

  constructor(options: DelegationClientOptions) {
    this.#options = options;
    this.#clock = options.clock ?? Date.now;
  }

  /** The claims for [session] at the current instant, or the reason none can be issued. */
  claimsFor(session: SessionRecord, scope: readonly DelegationScope[] = DELEGATION_SCOPES):
    { readonly claims: DelegationClaims } | { readonly reason: 'session_required' | 'account_unsupported' } {
    const now = this.#clock();
    if (session.accountId === null) return { reason: 'session_required' };
    const deadline = Math.min(session.absoluteExpiresAt, session.lastSeenAt + this.#options.idleTtlMs);
    const iat = Math.floor(now / 1000);
    const exp = Math.min(iat + MAX_LIFETIME_SECONDS, Math.floor(deadline / 1000));
    if (now >= deadline || exp <= iat) return { reason: 'session_required' };
    if (!APPSERVER_ACCOUNT_ID.test(session.accountId)) return { reason: 'account_unsupported' };
    if (scope.length === 0 || !scope.every((s) => (DELEGATION_SCOPES as readonly string[]).includes(s))) {
      return { reason: 'account_unsupported' };
    }
    return {
      claims: {
        v: DELEGATION_CONTRACT_VERSION,
        aud: this.#options.audience,
        iss: this.#options.issuer,
        kid: this.#options.keyId,
        sub: session.accountId,
        sid: sessionReference(session.familyId),
        scope: [...scope],
        iat,
        exp,
        jti: randomBytes(16).toString('base64url'),
      },
    };
  }

  async delegate(session: SessionRecord, scope?: readonly DelegationScope[]): Promise<DelegationOutcome> {
    const built = this.claimsFor(session, scope);
    if (!('claims' in built)) return { ok: false, reason: built.reason };
    const { claims } = built;
    const input = signingInput(claims);
    const signature = Buffer.from(await this.#options.signer.sign(Buffer.from(input, 'ascii')));
    const assertion = `${input}.${signature.toString('base64url')}`;
    if (signature.length !== 64 || Buffer.byteLength(assertion) > MAX_ASSERTION_BYTES) return { ok: false, reason: 'appserver_unavailable' };

    let result: TransportResult;
    try {
      result = await this.#options.transport.verify(assertion);
    } catch {
      return { ok: false, reason: 'appserver_unavailable' };
    }
    if (result.kind === 'unavailable') return { ok: false, reason: 'appserver_unavailable' };
    if (result.kind === 'rejected') return { ok: false, reason: 'appserver_rejected' };
    // The AppServer must confirm exactly what was asked; anything else is a rejection.
    if (!confirms(result.body, claims)) return { ok: false, reason: 'appserver_rejected' };
    return { ok: true, scope: claims.scope, expiresAt: claims.exp * 1000 };
  }
}

function confirms(body: unknown, claims: DelegationClaims): boolean {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) return false;
  const b = body as Record<string, unknown>;
  return b['verified'] === true && b['contract'] === DELEGATION_CONTRACT && b['version'] === DELEGATION_CONTRACT_VERSION
    && b['iss'] === claims.iss && b['sub'] === claims.sub && b['exp'] === claims.exp
    && Array.isArray(b['scope']) && b['scope'].length === claims.scope.length
    && claims.scope.every((s, i) => (b['scope'] as unknown[])[i] === s);
}

/**
 * HTTP transport for a configured AppServer origin. Not wired by default: `createApp`
 * only uses a transport that code injects. It sends the assertion and nothing else: no
 * cookie, no Authorization header, no provider token, no redirects.
 */
export function httpDelegationTransport(options: {
  readonly appServerOrigin: string;
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
}): DelegationTransport {
  const url = new URL(VERIFY_PATH, options.appServerOrigin);
  if (url.protocol !== 'https:') throw new Error('AppServer origin must be https');
  const doFetch = options.fetch ?? fetch;
  return {
    async verify(assertion: string): Promise<TransportResult> {
      const response = await doFetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ assertion }),
        redirect: 'error',
        credentials: 'omit',
        signal: AbortSignal.timeout(options.timeoutMs ?? 3000),
      });
      let body: unknown;
      try {
        body = await response.json();
      } catch {
        return { kind: 'unavailable' };
      }
      if (response.status === 200) return { kind: 'verified', body };
      if (response.status === 401 && typeof body === 'object' && body !== null
        && typeof (body as Record<string, unknown>)['error'] === 'string') {
        return { kind: 'rejected', error: (body as Record<string, string>)['error'] as string };
      }
      return { kind: 'unavailable' };
    },
  };
}
