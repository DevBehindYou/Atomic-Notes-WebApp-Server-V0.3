import { createHash, randomBytes } from 'node:crypto';
import { DEFAULT_BROWSER_SESSION_POLICY, type BrowserSessionPolicy } from './config.js';
import type { IdentityVerifier, VerifiedIdentity } from './identity.js';
import type { SessionRecord, SessionStore } from './store.js';

export const SESSION_COOKIE_NAME = '__Host-atomic_session';
const SESSION_ID_BYTES = 32;
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ACCOUNT_ID_MAX_LENGTH = 128;
const ACCOUNT_HINT_MAX_LENGTH = 64;
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

export interface BrowserSessionDependencies {
  readonly store: SessionStore;
  /** Absent in deployed wiring until a reviewed provider integration exists. */
  readonly verifier?: IdentityVerifier;
  readonly clock?: () => number;
  readonly policy?: Partial<BrowserSessionPolicy>;
}

/** Non-secret session status: the only session data ever returned to the browser. */
export type SessionStatus =
  | { readonly signedIn: false }
  | { readonly signedIn: true; readonly accountHint?: string; readonly expiresAt: string };

export type Resolution =
  | { readonly kind: 'none'; readonly clearCookie: boolean }
  | { readonly kind: 'origin_mismatch' }
  | { readonly kind: 'active'; readonly session: SessionRecord; readonly issuedId?: string };

export interface IssuedSession {
  readonly id: string;
  readonly session: SessionRecord;
}

export function hashSessionId(id: string): string {
  return createHash('sha256').update(id, 'utf8').digest('hex');
}

export class BrowserSessionService {
  readonly #store: SessionStore;
  readonly #verifier: IdentityVerifier | undefined;
  readonly #clock: () => number;
  readonly policy: BrowserSessionPolicy;

  constructor(dependencies: BrowserSessionDependencies) {
    this.#store = dependencies.store;
    this.#verifier = dependencies.verifier;
    this.#clock = dependencies.clock ?? Date.now;
    this.policy = { ...DEFAULT_BROWSER_SESSION_POLICY, ...dependencies.policy };
  }

  get identityAvailable(): boolean {
    return this.#verifier !== undefined;
  }

  now(): number {
    return this.#clock();
  }

  /**
   * Resolves the presented session id. Unknown ids are never adopted (fixation);
   * expired ids are revoked; a replayed rotated id revokes its whole family.
   * `touch: false` leaves an active session's idle clock alone, for requests that
   * have not yet proved they are genuine (the C37 anti-CSRF check comes after).
   */
  async resolve(
    presentedId: string | undefined,
    requestOrigin: string | undefined,
    options: { rotate: boolean; touch?: boolean },
  ): Promise<Resolution> {
    if (presentedId === undefined) return { kind: 'none', clearCookie: false };
    if (!SESSION_ID_PATTERN.test(presentedId)) return { kind: 'none', clearCookie: true };

    const idHash = hashSessionId(presentedId);
    const found = await this.#store.lookup(idHash);
    if (found === undefined) return { kind: 'none', clearCookie: true };
    if (found.status === 'retired') {
      await this.#store.revokeFamily(found.familyId);
      return { kind: 'none', clearCookie: true };
    }

    const now = this.#clock();
    const session = found.session;
    if (now >= session.absoluteExpiresAt || (session.accountId !== null && now >= session.lastSeenAt + this.policy.idleTtlMs)) {
      await this.#store.revokeFamily(session.familyId);
      return { kind: 'none', clearCookie: true };
    }
    if (requestOrigin !== undefined && requestOrigin !== session.origin) return { kind: 'origin_mismatch' };

    if (options.rotate && session.accountId !== null && now >= session.rotatedAt + this.policy.rotationIntervalMs) {
      const nextId = newSessionId();
      const nextIdHash = hashSessionId(nextId);
      if (!(await this.#store.rotate(session.familyId, idHash, nextIdHash, now))) {
        await this.#store.revokeFamily(session.familyId);
        return { kind: 'none', clearCookie: true };
      }
      return { kind: 'active', session: { ...session, idHash: nextIdHash, rotatedAt: now, lastSeenAt: now }, issuedId: nextId };
    }

    if (options.touch === false) return { kind: 'active', session };
    await this.#store.touch(session.familyId, now);
    return { kind: 'active', session: { ...session, lastSeenAt: now } };
  }

  async revokeFamily(familyId: string): Promise<void> {
    await this.#store.revokeFamily(familyId);
  }

  async verifyIdentity(assertion: string, origin: string): Promise<{ accountId: string; accountHint: string | null } | null> {
    if (this.#verifier === undefined) throw new Error('identity verifier unavailable');
    const identity: VerifiedIdentity | null = await this.#verifier.verify({ assertion, origin });
    if (identity === null) return null;
    // Only the account binding survives; any credentials stay out of the store and responses.
    const { accountId, accountHint } = identity;
    if (typeof accountId !== 'string' || accountId.length === 0 || accountId.length > ACCOUNT_ID_MAX_LENGTH
      || CONTROL_CHARACTERS.test(accountId)) {
      return null;
    }
    return { accountId, accountHint: boundedHint(accountHint) };
  }

  async issue(origin: string, account: { accountId: string; accountHint: string | null } | null): Promise<IssuedSession> {
    const now = this.#clock();
    const id = newSessionId();
    const session: SessionRecord = {
      familyId: randomBytes(16).toString('hex'),
      idHash: hashSessionId(id),
      accountId: account?.accountId ?? null,
      accountHint: account?.accountHint ?? null,
      origin,
      createdAt: now,
      absoluteExpiresAt: now + (account === null ? this.policy.preAuthTtlMs : this.policy.absoluteTtlMs),
      rotatedAt: now,
      lastSeenAt: now,
    };
    await this.#store.insert(session);
    return { id, session };
  }

  status(session: SessionRecord): SessionStatus {
    if (session.accountId === null) return { signedIn: false };
    const expiresAt = new Date(Math.min(session.absoluteExpiresAt, session.lastSeenAt + this.policy.idleTtlMs)).toISOString();
    return session.accountHint === null
      ? { signedIn: true, expiresAt }
      : { signedIn: true, accountHint: session.accountHint, expiresAt };
  }
}

function newSessionId(): string {
  return randomBytes(SESSION_ID_BYTES).toString('base64url');
}

function boundedHint(hint: unknown): string | null {
  if (typeof hint !== 'string' || hint.length === 0 || hint.length > ACCOUNT_HINT_MAX_LENGTH || CONTROL_CHARACTERS.test(hint)) {
    return null;
  }
  return hint;
}

export function sessionCookie(id: string, maxAgeSeconds: number): string {
  return `${SESSION_COOKIE_NAME}=${id}; Path=/; Max-Age=${Math.max(0, maxAgeSeconds)}; HttpOnly; Secure; SameSite=Strict`;
}

export const CLEAR_SESSION_COOKIE = `${SESSION_COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`;

/**
 * Returns the single presented session cookie value. Duplicate or empty values are
 * treated as an invalid presentation so they are cleared rather than guessed at.
 */
export function readSessionCookie(header: string | undefined): { value: string | undefined; invalid: boolean } {
  if (header === undefined) return { value: undefined, invalid: false };
  const values: string[] = [];
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() === SESSION_COOKIE_NAME) values.push(part.slice(separator + 1).trim());
  }
  if (values.length === 0) return { value: undefined, invalid: false };
  if (values.length > 1 || values[0] === '') return { value: undefined, invalid: true };
  return { value: values[0], invalid: false };
}
