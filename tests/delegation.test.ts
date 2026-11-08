import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import test from 'node:test';
import defaultApp, { createApp } from '../src/app.js';
import type { IdentityAssertion, IdentityVerifier, VerifiedIdentity } from '../src/browser-sessions/identity.js';
import { MemorySessionStore, type SessionRecord } from '../src/browser-sessions/store.js';
import {
  DelegationClient, httpDelegationTransport, type DelegationSigner, type DelegationTransport, type TransportResult,
} from '../src/delegation/client.js';
import { readDelegationGate } from '../src/delegation/config.js';
import {
  CLAIM_ORDER, CLOCK_SKEW_SECONDS, DELEGATION_ALGORITHM, DELEGATION_CONTRACT, DELEGATION_CONTRACT_VERSION, DELEGATION_HEADER,
  DELEGATION_SCOPES, MAX_ASSERTION_BYTES, MAX_LIFETIME_SECONDS, VERIFY_PATH, canonicalClaimsJson, sessionReference, signingInput,
  type DelegationClaims,
} from '../src/delegation/contract.js';
import { CANARIES, CANARY_APPSERVER_BEARER, CANARY_PROVIDER_ACCESS_TOKEN } from './support/identity-fixture.js';

/** AppServer commit whose `tests/fixtures/delegation/assertion.v1.json` this copy pins. */
const SERVER_CONTRACT_SHA = 'bc815942e60e21c37460674becaa092cb5b98ade';
const FIXTURE_TEXT = readFileSync(new URL('./fixtures/delegation/assertion.v1.json', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
const fixture = JSON.parse(FIXTURE_TEXT) as Record<string, unknown> & {
  example: { gatewayFamilyId: string; claims: DelegationClaims; payload: string; signingInput: string };
  verifyRequest: { method: string; path: string; contentType: string };
  verifyResponse: { status: number; body: Record<string, unknown> };
};

const ORIGIN = 'https://app.atomic.test';
const AUDIENCE = fixture.example.claims.aud;
const ISSUER = fixture.example.claims.iss;
const KEY_ID = fixture.example.claims.kid;
const ALICE = fixture.example.claims.sub;
const BOB = '9b8a7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d';
const SESSIONS_ENV = { ATOMIC_BROWSER_SESSIONS_ENABLED: 'true', ATOMIC_BROWSER_ALLOWED_ORIGINS: ORIGIN };
const DELEGATION_ENV = {
  ATOMIC_APPSERVER_DELEGATION_ENABLED: 'true',
  ATOMIC_APPSERVER_DELEGATION_AUDIENCE: AUDIENCE,
  ATOMIC_GATEWAY_DELEGATION_ISSUER: ISSUER,
  ATOMIC_GATEWAY_DELEGATION_KEY_ID: KEY_ID,
};
const ENABLED_ENV = { ...SESSIONS_ENV, ...DELEGATION_ENV };
const MINUTE = 60 * 1000;
const CSRF_HEADER = 'x-atomic-csrf';

// Test-only key, generated per run. No key material is committed.
const keys = generateKeyPairSync('ed25519');
const signer: DelegationSigner = { sign: async (input) => sign(null, input, keys.privateKey) };

const ALICE_LOGIN = 'delegation-fixture-alice';
const LEGACY_LOGIN = 'delegation-fixture-legacy';
class Verifier implements IdentityVerifier {
  async verify(input: IdentityAssertion): Promise<VerifiedIdentity | null> {
    const credentials = { providerAccessToken: CANARY_PROVIDER_ACCESS_TOKEN, appServerBearer: CANARY_APPSERVER_BEARER };
    if (input.assertion === ALICE_LOGIN) return { accountId: ALICE, accountHint: 'a***@example.test', credentials };
    if (input.assertion === LEGACY_LOGIN) return { accountId: 'acct-legacy', credentials };
    return null;
  }
}

/** Decodes an assertion the way the AppServer would, after checking its signature. */
function open(assertion: string): DelegationClaims {
  const [header, payload, signature] = assertion.split('.') as [string, string, string];
  assert.equal(header, DELEGATION_HEADER);
  assert.equal(verify(null, Buffer.from(`${header}.${payload}`, 'ascii'), keys.publicKey, Buffer.from(signature, 'base64url')), true);
  const json = Buffer.from(payload, 'base64url').toString('utf8');
  const claims = JSON.parse(json) as DelegationClaims;
  assert.equal(json, canonicalClaimsJson(claims), 'canonical encoding');
  assert.deepEqual(Object.keys(claims), [...CLAIM_ORDER]);
  return claims;
}

/** Fake AppServer: answers like `POST /api/delegation/verify` would for an authentic assertion. */
class FakeTransport implements DelegationTransport {
  readonly assertions: string[] = [];
  answer: (claims: DelegationClaims) => TransportResult = (claims) => ({ kind: 'verified', body: {
    verified: true, contract: DELEGATION_CONTRACT, version: DELEGATION_CONTRACT_VERSION,
    iss: claims.iss, sub: claims.sub, scope: claims.scope, exp: claims.exp } });
  async verify(assertion: string): Promise<TransportResult> {
    this.assertions.push(assertion);
    return this.answer(open(assertion));
  }
}

function harness(env: Record<string, string> = ENABLED_ENV, ports: { signer?: boolean; transport?: boolean } = {}) {
  let now = Date.UTC(2026, 10, 8, 9, 0, 0);
  const store = new MemorySessionStore();
  const transport = new FakeTransport();
  const app = createApp({
    env,
    browserSessions: { store, verifier: new Verifier(), clock: () => now },
    delegation: { ...(ports.signer === false ? {} : { signer }), ...(ports.transport === false ? {} : { transport }) },
  });
  const request = (path: string, init: { method?: string; cookie?: string; csrf?: string; body?: string; headers?: Record<string, string> } = {}) => {
    const method = init.method ?? 'POST';
    const headers: Record<string, string> = { ...init.headers };
    if (method === 'POST') Object.assign(headers, { origin: ORIGIN, 'content-type': 'application/json' }, init.headers);
    if (init.cookie !== undefined) headers['cookie'] = `__Host-atomic_session=${init.cookie}`;
    if (init.csrf !== undefined) headers[CSRF_HEADER] = init.csrf;
    return app.request(path, { method, headers, ...(method === 'POST' ? { body: init.body ?? '{}' } : {}) });
  };
  async function login(assertion = ALICE_LOGIN): Promise<{ id: string; csrf: string }> {
    const response = await request('/api/session/login', { body: JSON.stringify({ assertion }) });
    assert.equal(response.status, 200);
    const id = /__Host-atomic_session=([A-Za-z0-9_-]{43})/.exec(response.headers.get('set-cookie') ?? '')?.[1];
    assert.ok(id);
    return { id, csrf: ((await response.json()) as { csrf: string }).csrf };
  }
  const delegate = (session: { id: string; csrf: string }, extra: { body?: string; headers?: Record<string, string> } = {}) =>
    request('/api/session/delegation', { cookie: session.id, csrf: session.csrf, ...extra });
  return { app, store, transport, request, login, delegate, advance: (ms: number) => { now += ms; }, now: () => now };
}

function assertNoSecrets(text: string): void {
  for (const canary of CANARIES) assert.equal(text.includes(canary), false, 'canary leaked');
  assert.equal(text.includes(`${DELEGATION_HEADER}.`), false, 'assertion leaked');
}

test('the copied AppServer fixture pins the v1 contract this client speaks', () => {
  assert.equal(`${JSON.stringify(fixture, null, 2)}\n`, FIXTURE_TEXT);
  assert.equal(fixture['contract'], DELEGATION_CONTRACT);
  assert.equal(fixture['version'], DELEGATION_CONTRACT_VERSION);
  assert.equal(fixture['header'], DELEGATION_HEADER);
  assert.equal(fixture['algorithm'], DELEGATION_ALGORITHM);
  assert.deepEqual(fixture['claimOrder'], [...CLAIM_ORDER]);
  assert.deepEqual(fixture['scopes'], [...DELEGATION_SCOPES]);
  assert.equal(fixture['maxAssertionBytes'], MAX_ASSERTION_BYTES);
  assert.equal(fixture['maxLifetimeSeconds'], MAX_LIFETIME_SECONDS);
  assert.equal(fixture['clockSkewSeconds'], CLOCK_SKEW_SECONDS);
  assert.equal(fixture.verifyRequest.path, VERIFY_PATH);
  assert.equal(sessionReference(fixture.example.gatewayFamilyId), fixture.example.claims.sid);
  assert.equal(signingInput(fixture.example.claims), fixture.example.signingInput);
  const doc = readFileSync(new URL('../docs/APPSERVER_DELEGATION.md', import.meta.url), 'utf8');
  assert.ok(doc.includes(SERVER_CONTRACT_SHA), 'docs record the pinned AppServer commit');
});

function record(patch: Partial<SessionRecord> = {}): SessionRecord {
  const at = Date.UTC(2026, 10, 8, 9, 0, 0);
  return { familyId: fixture.example.gatewayFamilyId, idHash: 'a'.repeat(64), accountId: ALICE, accountHint: null, origin: ORIGIN,
    createdAt: at, absoluteExpiresAt: at + 12 * 60 * MINUTE, rotatedAt: at, lastSeenAt: at, ...patch };
}
const client = (now: number, transport: DelegationTransport = new FakeTransport()) => new DelegationClient({
  audience: AUDIENCE, issuer: ISSUER, keyId: KEY_ID, signer, transport, idleTtlMs: 30 * MINUTE, clock: () => now });

test('claims come only from the server-side session record and never outlive it', () => {
  const at = Date.UTC(2026, 10, 8, 9, 0, 0);
  const built = client(at).claimsFor(record());
  assert.ok('claims' in built);
  assert.deepEqual({ ...built.claims, jti: fixture.example.claims.jti }, fixture.example.claims);
  assert.match(built.claims.jti, /^[A-Za-z0-9_-]{22}$/);
  // Bounded by the idle deadline when it is closer than five minutes.
  const late = client(at + 28 * MINUTE).claimsFor(record());
  assert.ok('claims' in late);
  assert.equal(late.claims.exp, (at + 30 * MINUTE) / 1000);
  for (const [session, now] of [[record({ accountId: null }), at], [record(), at + 30 * MINUTE],
    [record({ absoluteExpiresAt: at + MINUTE }), at + MINUTE], [record({ absoluteExpiresAt: at + 500 }), at]] as const) {
    assert.deepEqual(client(now).claimsFor(session), { reason: 'session_required' });
  }
  assert.deepEqual(client(at).claimsFor(record({ accountId: 'acct-alice' })), { reason: 'account_unsupported' });
  for (const scope of [['wallet:write'], ['notes:read', 'energy:spend'], []]) {
    assert.deepEqual(client(at).claimsFor(record(), scope as never), { reason: 'account_unsupported' });
  }
});

test('an authenticated session gets a verified delegation; browser-supplied account ids cannot change sub', async () => {
  const h = harness();
  const alice = await h.login();
  const response = await h.delegate(alice, {
    body: JSON.stringify({ accountId: BOB, sub: BOB, scope: ['wallet:write'], token: CANARY_PROVIDER_ACCESS_TOKEN }),
    headers: { 'x-account-id': BOB, authorization: `Bearer ${CANARY_APPSERVER_BEARER}` },
  });
  assert.equal(response.status, 200);
  const text = await response.text();
  assertNoSecrets(text);
  assert.deepEqual(JSON.parse(text), { delegated: true, scope: ['notes:read'],
    expiresAt: new Date(h.now() + MAX_LIFETIME_SECONDS * 1000).toISOString() });
  assert.equal(h.transport.assertions.length, 1);
  const claims = open(h.transport.assertions[0] as string);
  const family = h.store.snapshot().families[0] as SessionRecord;
  assert.equal(claims.sub, ALICE);
  assert.equal(claims.sid, sessionReference(family.familyId));
  assert.deepEqual(claims.scope, ['notes:read']);
  assert.equal(claims.aud, AUDIENCE);
  assert.equal(claims.iss, ISSUER);
  assertNoSecrets(JSON.stringify(Buffer.from((h.transport.assertions[0] as string).split('.')[1] as string, 'base64url').toString()));
  // The store holds no assertion, provider token or AppServer bearer.
  assertNoSecrets(JSON.stringify(h.store.snapshot()));
  // Each call is a fresh single-use assertion.
  assert.equal((await h.delegate(alice)).status, 200);
  assert.notEqual(open(h.transport.assertions[1] as string).jti, claims.jti);
});

test('no session, a pre-auth session, a missing token or an expired session makes no outbound call', async () => {
  const h = harness();
  assert.equal((await h.request('/api/session/delegation')).status, 401);
  const start = await h.request('/api/session/start');
  const preId = /__Host-atomic_session=([A-Za-z0-9_-]{43})/.exec(start.headers.get('set-cookie') ?? '')?.[1] as string;
  const preCsrf = ((await start.json()) as { csrf: string }).csrf;
  assert.deepEqual(await (await h.request('/api/session/delegation', { cookie: preId, csrf: preCsrf })).json(), { error: 'session_required' });
  const alice = await h.login();
  const forged = await h.request('/api/session/delegation', { cookie: alice.id });
  assert.equal(forged.status, 403);
  assert.deepEqual(await forged.json(), { error: 'csrf_rejected' });
  const foreign = await h.delegate(alice, { headers: { origin: 'https://evil.invalid' } });
  assert.equal(foreign.status, 403);
  h.advance(30 * MINUTE);
  const expired = await h.delegate(alice);
  assert.equal(expired.status, 401);
  assert.deepEqual(await expired.json(), { error: 'session_required' });
  assert.equal(h.store.snapshot().families.some((f) => f.accountId === ALICE), false);
  assert.equal(h.transport.assertions.length, 0);
  // A session bound to an id that is not an AppServer account id is never delegated.
  const legacy = await h.login(LEGACY_LOGIN);
  assert.deepEqual(await (await h.delegate(legacy)).json(), { error: 'delegation_unavailable' });
  assert.equal(h.transport.assertions.length, 0);
});

test('AppServer refusals, unconfirmed answers and transport failures are not delegations', async () => {
  const h = harness();
  const alice = await h.login();
  const cases: [(claims: DelegationClaims) => TransportResult, number, string][] = [
    [() => ({ kind: 'rejected', error: 'delegation_subject_mismatch' }), 502, 'delegation_rejected'],
    [(c) => ({ kind: 'verified', body: { verified: true, contract: DELEGATION_CONTRACT, version: 1, iss: c.iss, sub: BOB, scope: c.scope, exp: c.exp } }), 502, 'delegation_rejected'],
    [(c) => ({ kind: 'verified', body: { verified: true, contract: DELEGATION_CONTRACT, version: 1, iss: c.iss, sub: c.sub, scope: ['wallet:write'], exp: c.exp } }), 502, 'delegation_rejected'],
    [() => ({ kind: 'verified', body: { verified: true } }), 502, 'delegation_rejected'],
    [() => ({ kind: 'unavailable' }), 503, 'delegation_unavailable'],
    [() => { throw new Error('network'); }, 503, 'delegation_unavailable'],
  ];
  for (const [answer, status, error] of cases) {
    h.transport.answer = answer;
    const response = await h.delegate(alice);
    assert.equal(response.status, status, error);
    assert.deepEqual(await response.json(), { error });
  }
});

test('flags off, misconfigured or unwired: no route, or a fixed 503, and never an outbound call', async () => {
  const bodyOf = async (r: Response) => [r.status, await r.json()];
  const sessionsOnly = harness(SESSIONS_ENV);
  const alice = await sessionsOnly.login();
  assert.deepEqual(await bodyOf(await sessionsOnly.delegate(alice)), [404, { error: 'not_found' }]);
  const delegationOnly = harness(DELEGATION_ENV);
  assert.deepEqual(await bodyOf(await delegationOnly.request('/api/session/delegation')), [404, { error: 'not_found' }]);
  for (const env of [{ ...ENABLED_ENV, ATOMIC_APPSERVER_DELEGATION_AUDIENCE: '' }, { ...ENABLED_ENV, ATOMIC_GATEWAY_DELEGATION_ISSUER: 'Bad Issuer' },
    { ...ENABLED_ENV, ATOMIC_GATEWAY_DELEGATION_KEY_ID: '' }]) {
    const h = harness(env);
    assert.deepEqual(await bodyOf(await h.delegate(await h.login())), [503, { error: 'delegation_unavailable' }]);
    assert.equal(h.transport.assertions.length, 0);
  }
  for (const ports of [{ signer: false }, { transport: false }]) {
    const h = harness(ENABLED_ENV, ports);
    assert.deepEqual(await bodyOf(await h.delegate(await h.login())), [503, { error: 'delegation_unavailable' }]);
    assert.equal(h.transport.assertions.length, 0);
  }
  const misconfigured = harness({ ...DELEGATION_ENV, ATOMIC_BROWSER_SESSIONS_ENABLED: 'true' });
  assert.deepEqual(await bodyOf(await misconfigured.request('/api/session/delegation')), [503, { error: 'browser_sessions_unavailable' }]);
  for (const h of [sessionsOnly, delegationOnly, misconfigured]) assert.equal(h.transport.assertions.length, 0);
  // The deployed default reads process.env, where neither flag is set.
  assert.deepEqual(await bodyOf(await defaultApp.request('/api/session/delegation', { method: 'POST' })), [404, { error: 'not_found' }]);
  assert.deepEqual(readDelegationGate({}), { state: 'disabled' });
  assert.deepEqual(readDelegationGate({ ATOMIC_APPSERVER_DELEGATION_ENABLED: 'TRUE' }), { state: 'disabled' });
  // Only POST, behind the C37 guard.
  const h = harness();
  const get = await h.request('/api/session/delegation', { method: 'GET' });
  assert.equal(get.status, 405);
  assert.equal(h.transport.assertions.length, 0);
});

test('the HTTP transport sends only the assertion, with no credentials, cookies or redirects', async () => {
  const calls: { url: string; init: RequestInit }[] = [];
  let reply = new Response(JSON.stringify(fixture.verifyResponse.body), { status: 200 });
  const transport = httpDelegationTransport({ appServerOrigin: 'https://appserver.atomic.test', fetch: (async (url: URL, init: RequestInit) => {
    calls.push({ url: String(url), init });
    return reply;
  }) as unknown as typeof fetch });
  assert.deepEqual(await transport.verify('atomic-delegation-v1.x.y'), { kind: 'verified', body: fixture.verifyResponse.body });
  const call = calls[0] as { url: string; init: RequestInit };
  assert.equal(call.url, `https://appserver.atomic.test${VERIFY_PATH}`);
  assert.equal(call.init.method, fixture.verifyRequest.method);
  assert.deepEqual(call.init.headers, { 'content-type': fixture.verifyRequest.contentType });
  assert.equal(call.init.body, JSON.stringify({ assertion: 'atomic-delegation-v1.x.y' }));
  assert.equal(call.init.redirect, 'error');
  assert.equal(call.init.credentials, 'omit');
  reply = new Response(JSON.stringify({ error: 'delegation_expired' }), { status: 401 });
  assert.deepEqual(await transport.verify('a'), { kind: 'rejected', error: 'delegation_expired' });
  for (const [body, status] of [['{"error":"delegation_unavailable"}', 503], ['not json', 200], ['{}', 401]] as const) {
    reply = new Response(body, { status });
    assert.deepEqual(await transport.verify('a'), { kind: 'unavailable' });
  }
  assert.throws(() => httpDelegationTransport({ appServerOrigin: 'http://appserver.atomic.test' }));
});

test('delegation modules import nothing beyond the session types and node:crypto', () => {
  const allowed = ['node:crypto', './contract.js', './client.js', '../browser-sessions/store.js', '../browser-sessions/config.js'];
  for (const name of readdirSync(new URL('../src/delegation/', import.meta.url))) {
    const source = readFileSync(new URL(`../src/delegation/${name}`, import.meta.url), 'utf8');
    for (const [, spec] of source.matchAll(/from '([^']+)'/g)) assert.ok(allowed.includes(spec as string), `${name} imports ${spec}`);
  }
});
