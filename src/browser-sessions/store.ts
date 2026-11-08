/**
 * Server-side session reference store port.
 *
 * Only the SHA-256 hash of a session id is ever stored. A session "family" is the
 * chain of ids produced by rotation; retired ids are remembered so that a replay
 * of a rotated id can be detected and the whole family revoked.
 */
export interface SessionRecord {
  readonly familyId: string;
  /** SHA-256 (hex) of the current session id. */
  readonly idHash: string;
  /** `null` for a pre-authentication session. */
  readonly accountId: string | null;
  readonly accountHint: string | null;
  /** Browser origin the session was issued to. */
  readonly origin: string;
  readonly createdAt: number;
  readonly absoluteExpiresAt: number;
  readonly rotatedAt: number;
  readonly lastSeenAt: number;
}

export type SessionLookup =
  | { readonly status: 'current'; readonly session: SessionRecord }
  | { readonly status: 'retired'; readonly familyId: string };

export interface SessionStore {
  insert(session: SessionRecord): Promise<void>;
  lookup(idHash: string): Promise<SessionLookup | undefined>;
  /** Atomically replaces the current id; false when `expectedIdHash` is no longer current. */
  rotate(familyId: string, expectedIdHash: string, nextIdHash: string, at: number): Promise<boolean>;
  touch(familyId: string, at: number): Promise<void>;
  revokeFamily(familyId: string): Promise<void>;
}

/**
 * Process-local store for tests and local development only. It is not shared across
 * serverless instances and must not back a deployed environment.
 */
export class MemorySessionStore implements SessionStore {
  readonly #families = new Map<string, SessionRecord>();
  readonly #current = new Map<string, string>();
  readonly #retired = new Map<string, string>();

  async insert(session: SessionRecord): Promise<void> {
    this.#prune(session.createdAt);
    if (this.#current.has(session.idHash) || this.#retired.has(session.idHash) || this.#families.has(session.familyId)) {
      throw new Error('session identifier collision');
    }
    this.#families.set(session.familyId, session);
    this.#current.set(session.idHash, session.familyId);
  }

  async lookup(idHash: string): Promise<SessionLookup | undefined> {
    const currentFamily = this.#current.get(idHash);
    if (currentFamily !== undefined) {
      const session = this.#families.get(currentFamily);
      return session === undefined ? undefined : { status: 'current', session };
    }
    const retiredFamily = this.#retired.get(idHash);
    return retiredFamily === undefined ? undefined : { status: 'retired', familyId: retiredFamily };
  }

  async rotate(familyId: string, expectedIdHash: string, nextIdHash: string, at: number): Promise<boolean> {
    const session = this.#families.get(familyId);
    if (session === undefined || session.idHash !== expectedIdHash) return false;
    if (this.#current.has(nextIdHash) || this.#retired.has(nextIdHash)) throw new Error('session identifier collision');
    this.#current.delete(expectedIdHash);
    this.#retired.set(expectedIdHash, familyId);
    this.#current.set(nextIdHash, familyId);
    this.#families.set(familyId, { ...session, idHash: nextIdHash, rotatedAt: at, lastSeenAt: at });
    return true;
  }

  async touch(familyId: string, at: number): Promise<void> {
    const session = this.#families.get(familyId);
    if (session !== undefined) this.#families.set(familyId, { ...session, lastSeenAt: at });
  }

  async revokeFamily(familyId: string): Promise<void> {
    this.#remove(familyId);
  }

  #remove(familyId: string): void {
    const session = this.#families.get(familyId);
    if (session !== undefined) this.#current.delete(session.idHash);
    for (const [idHash, owner] of this.#retired) {
      if (owner === familyId) this.#retired.delete(idHash);
    }
    this.#families.delete(familyId);
  }

  /** Test inspection: everything the store holds, as plain data. */
  snapshot(): { families: SessionRecord[]; retiredIdHashes: string[] } {
    return { families: [...this.#families.values()], retiredIdHashes: [...this.#retired.keys()] };
  }

  #prune(now: number): void {
    for (const session of [...this.#families.values()]) {
      if (session.absoluteExpiresAt <= now) this.#remove(session.familyId);
    }
  }
}
