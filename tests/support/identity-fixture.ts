import type { IdentityAssertion, IdentityVerifier, VerifiedIdentity } from '../../src/browser-sessions/identity.js';

/** Canary credential values a real verifier might obtain. They must never reach the browser or the store. */
export const CANARY_PROVIDER_ACCESS_TOKEN = 'CANARY-provider-access-7f3a9c';
export const CANARY_PROVIDER_REFRESH_TOKEN = 'CANARY-provider-refresh-1b2d4e';
export const CANARY_APPSERVER_BEARER = 'CANARY-appserver-bearer-5e6f70';
export const CANARIES = [CANARY_PROVIDER_ACCESS_TOKEN, CANARY_PROVIDER_REFRESH_TOKEN, CANARY_APPSERVER_BEARER];

export const ALICE_ASSERTION = 'fixture-assertion-alice';
export const BOB_ASSERTION = 'fixture-assertion-bob';

const IDENTITIES: Readonly<Record<string, VerifiedIdentity>> = {
  [ALICE_ASSERTION]: {
    accountId: 'acct-alice',
    accountHint: 'a***@example.test',
    credentials: {
      providerAccessToken: CANARY_PROVIDER_ACCESS_TOKEN,
      providerRefreshToken: CANARY_PROVIDER_REFRESH_TOKEN,
      appServerBearer: CANARY_APPSERVER_BEARER,
    },
  },
  [BOB_ASSERTION]: {
    accountId: 'acct-bob',
    credentials: { appServerBearer: CANARY_APPSERVER_BEARER },
  },
};

/** Controlled identity fixture: no OAuth, no network, no client secrets. */
export class FixtureIdentityVerifier implements IdentityVerifier {
  readonly calls: IdentityAssertion[] = [];

  async verify(input: IdentityAssertion): Promise<VerifiedIdentity | null> {
    this.calls.push(input);
    return IDENTITIES[input.assertion] ?? null;
  }
}
