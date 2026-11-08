/**
 * Identity verification port. C36 ships no real provider integration: production
 * wiring has no verifier, so login answers 503. Tests inject a controlled fixture.
 */
export interface IdentityAssertion {
  /** Opaque, single-use proof presented by the browser (a fixture value in tests). */
  readonly assertion: string;
  /** Allowlisted origin the login request came from. */
  readonly origin: string;
}

export interface VerifiedIdentity {
  readonly accountId: string;
  /** Non-secret display hint (for example a masked email). Bounded before use. */
  readonly accountHint?: string;
  /**
   * Provider or AppServer credentials a real verifier may obtain. They are server-side
   * only: C36 discards them and never serializes them to the browser or the session
   * store. Credential custody for delegation is decided in C38.
   */
  readonly credentials?: Readonly<Record<string, string>>;
}

export interface IdentityVerifier {
  verify(input: IdentityAssertion): Promise<VerifiedIdentity | null>;
}
