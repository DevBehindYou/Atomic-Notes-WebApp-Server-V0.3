import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { MemorySessionStore } from '../src/browser-sessions/store.js';
import { ALICE_ASSERTION, BOB_ASSERTION, FixtureIdentityVerifier } from './support/identity-fixture.js';

const ORIGIN = 'https://app.atomic.test';
const SECOND_ORIGIN = 'https://beta.atomic.test';
const FOREIGN_ORIGIN = 'https://evil.invalid';
const ENABLED_ENV = {
  ATOMIC_BROWSER_SESSIONS_ENABLED: 'true',
  ATOMIC_BROWSER_ALLOWED_ORIGINS: `${ORIGIN}, ${SECOND_ORIGIN}`,
};
const MINUTE = 60 * 1000;
const CSRF_HEADER = 'x-atomic-csrf';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const COOKIE_PATTERN = /^__Host-atomic_session=([A-Za-z0-9_-]{43}); Path=\/; Max-Age=(\d+); HttpOnly; Secure; SameSite=Strict$/;
const CLEAR_COOKIE = '__Host-atomic_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict';
const UNSAFE_ROUTES = ['/api/session/start', '/api/session/login', '/api/session/logout'];
const SAFE_ROUTES = ['/api/session', '/api/session/accounts/acct-alice'];
const ALL_ROUTES = [...SAFE_ROUTES, ...UNSAFE_ROUTES];

interface SendOptions {
  method?: string;
  /** `null` omits the header. Defaults to the allowlisted origin for unsafe methods. */
  origin?: string | null;
  cookie?: string;
  csrf?: string;
  /** `null` omits the header. Defaults to JSON for POST. */
  contentType?: string | null;
  body?: string;
  headers?: Record<string, string>;
}

interface Exchange {
  method: string;
  path: string;
  status: number;
  json: unknown;
  setCookie: string | null;
  headers: Headers;
}

interface Session {
  id: string;
  csrf: string;
}

function harness() {
  let now = Date.UTC(2026, 10, 8, 9, 0, 0);
  const store = new MemorySessionStore();
  const verifier = new FixtureIdentityVerifier();
  const app = createApp({ env: ENABLED_ENV, browserSessions: { store, verifier, clock: () => now } });
  const transcript: Exchange[] = [];

  async function send(path: string, request: SendOptions = {}): Promise<Exchange> {
    const method = request.method ?? 'GET';
    const unsafe = !['GET', 'HEAD', 'OPTIONS'].includes(method);
    const headers: Record<string, string> = { ...request.headers };
    const origin = request.origin === undefined ? (unsafe ? ORIGIN : null) : request.origin;
    if (origin !== null) headers['origin'] = origin;
    const contentType = request.contentType === undefined ? (method === 'POST' ? 'application/json' : null) : request.contentType;
    if (contentType !== null) headers['content-type'] = contentType;
    if (request.cookie !== undefined) headers['cookie'] = `__Host-atomic_session=${request.cookie}`;
    if (request.csrf !== undefined) headers[CSRF_HEADER] = request.csrf;
    const body = request.body ?? (method === 'POST' ? '{}' : undefined);
    const response = await app.request(path, { method, headers, ...(body === undefined ? {} : { body }) });
    const text = await response.text();
    const exchange: Exchange = {
      method,
      path,
      status: response.status,
      json: text === '' ? undefined : JSON.parse(text),
      setCookie: response.headers.get('set-cookie'),
      headers: response.headers,
    };
    assertResponsePolicy(exchange);
    transcript.push(exchange);
    return exchange;
  }

  async function start(origin = ORIGIN): Promise<Session> {
    const response = await send('/api/session/start', { method: 'POST', origin });
    assert.equal(response.status, 200, JSON.stringify(response.json));
    return { id: issuedId(response), csrf: csrfOf(response) };
  }

  async function login(assertion = ALICE_ASSERTION, from?: Session): Promise<Session> {
    const response = await send('/api/session/login', {
      method: 'POST',
      body: JSON.stringify({ assertion }),
      ...(from === undefined ? {} : { cookie: from.id, csrf: from.csrf }),
    });
    assert.equal(response.status, 200, JSON.stringify(response.json));
    return { id: issuedId(response), csrf: csrfOf(response) };
  }

  async function isSignedIn(session: Session): Promise<boolean> {
    const response = await send('/api/session', { cookie: session.id });
    return (response.json as { signedIn: boolean }).signedIn;
  }

  return { app, store, verifier, transcript, send, start, login, isSignedIn, advance(ms: number) { now += ms; } };
}

/** Invariants every response must satisfy, whatever the route or outcome. */
function assertResponsePolicy(exchange: Exchange): void {
  const where = `${exchange.method} ${exchange.path} -> ${exchange.status}`;
  exchange.headers.forEach((_value, name) => {
    assert.equal(name.toLowerCase().startsWith('access-control-'), false, `${where} emitted ${name}`);
  });
  assert.equal(exchange.headers.get('cache-control'), 'no-store, no-cache, must-revalidate', where);
  if (exchange.path.startsWith('/api/session')) {
    const vary = (exchange.headers.get('vary') ?? '').split(',').map((entry) => entry.trim().toLowerCase());
    assert.ok(vary.includes('origin') && vary.includes('cookie'), `${where} Vary: ${exchange.headers.get('vary')}`);
  }
}

function issuedId(exchange: Exchange): string {
  const match = COOKIE_PATTERN.exec(exchange.setCookie ?? '');
  assert.ok(match, `expected a session cookie, got ${exchange.setCookie}`);
  return match[1] as string;
}

function csrfOf(exchange: Exchange): string {
  const token = (exchange.json as { csrf?: unknown } | undefined)?.csrf;
  assert.equal(typeof token, 'string', `expected a csrf token in ${JSON.stringify(exchange.json)}`);
  assert.match(token as string, TOKEN_PATTERN);
  return token as string;
}

function randomToken(): string {
  return randomBytes(32).toString('base64url');
}

test('legitimate same-origin flow: start, status, login, status, logout', async () => {
  const { send, start, login, store, verifier } = harness();
  const sameOrigin = { 'sec-fetch-site': 'same-origin' };

  const anonymous = await send('/api/session', { headers: sameOrigin });
  assert.deepEqual(anonymous.json, { signedIn: false });
  assert.equal(anonymous.setCookie, null, 'a GET never creates a session');
  assert.equal(store.snapshot().families.length, 0);

  const preAuth = await start();
  assert.notEqual(preAuth.csrf, preAuth.id);
  const pending = await send('/api/session', { cookie: preAuth.id, headers: sameOrigin });
  assert.deepEqual(pending.json, { signedIn: false, csrf: preAuth.csrf });

  const session = await login(ALICE_ASSERTION, preAuth);
  assert.notEqual(session.csrf, preAuth.csrf, 'the token rotates with the id at login');
  assert.equal(verifier.calls.length, 1);
  const status = await send('/api/session', { cookie: session.id, headers: sameOrigin });
  assert.equal(status.status, 200);
  assert.equal((status.json as { signedIn: boolean }).signedIn, true);
  assert.equal(csrfOf(status), session.csrf, 'status returns the current token to same-origin callers');
  assert.equal(csrfOf(await send('/api/session/accounts/acct-alice', { cookie: session.id })), session.csrf);

  const logout = await send('/api/session/logout', { method: 'POST', cookie: session.id, csrf: session.csrf, headers: sameOrigin });
  assert.equal(logout.status, 200);
  assert.deepEqual(logout.json, { signedIn: false });
  assert.equal(logout.setCookie, CLEAR_COOKIE);
  assert.deepEqual(store.snapshot(), { families: [], retiredIdHashes: [] });
});

test('unsafe requests need an exact allowlisted Origin: missing, null, forged and look-alike origins are rejected', async () => {
  const { send, login, store, verifier, isSignedIn } = harness();
  const session = await login();
  const before = JSON.stringify(store.snapshot());
  const callsBefore = verifier.calls.length;

  const rejected: (string | null)[] = [
    null,
    'null',
    '',
    FOREIGN_ORIGIN,
    'http://app.atomic.test',
    'https://app.atomic.test:8443',
    'https://app.atomic.test:443',
    'https://app.atomic.test.evil.invalid',
    'https://evilapp.atomic.test',
    'https://sub.app.atomic.test',
    'https://APP.atomic.test',
    `${ORIGIN}/`,
    `${ORIGIN}/api`,
    `${ORIGIN}, ${FOREIGN_ORIGIN}`,
    'wss://app.atomic.test',
  ];
  for (const origin of rejected) {
    for (const path of UNSAFE_ROUTES) {
      const response = await send(path, {
        method: 'POST',
        origin,
        cookie: session.id,
        csrf: session.csrf,
        body: JSON.stringify({ assertion: BOB_ASSERTION }),
      });
      assert.equal(response.status, 403, `${path} origin=${JSON.stringify(origin)}`);
      assert.deepEqual(response.json, { error: 'origin_rejected' });
      assert.equal(response.setCookie, null);
    }
  }
  assert.equal(verifier.calls.length, callsBefore, 'the verifier never saw a rejected request');
  assert.equal(JSON.stringify(store.snapshot()), before, 'nothing was created, revoked or touched');
  assert.equal(await isSignedIn(session), true);

  // A safe request may omit Origin, but any Origin it presents must be allowlisted.
  for (const origin of ['null', FOREIGN_ORIGIN, 'https://app.atomic.test.evil.invalid']) {
    assert.equal((await send('/api/session', { cookie: session.id, origin })).status, 403, origin);
  }
});

test('fetch metadata: cross-site, same-site and user-initiated requests are rejected', async () => {
  const { send, login, isSignedIn, store } = harness();
  const session = await login();
  const before = JSON.stringify(store.snapshot());

  for (const site of ['cross-site', 'same-site', 'none', 'bogus']) {
    for (const path of UNSAFE_ROUTES) {
      const response = await send(path, { method: 'POST', cookie: session.id, csrf: session.csrf, headers: { 'sec-fetch-site': site } });
      assert.equal(response.status, 403, `${path} ${site}`);
      assert.deepEqual(response.json, { error: 'origin_rejected' });
      assert.equal(response.setCookie, null);
    }
    for (const path of SAFE_ROUTES) {
      const response = await send(path, { cookie: session.id, headers: { 'sec-fetch-site': site } });
      assert.equal(response.status, 403, `${path} ${site}`);
      assert.equal(response.setCookie, null);
    }
  }
  assert.equal(JSON.stringify(store.snapshot()), before);
  assert.equal(await isSignedIn(session), true);
});

test('cross-site form posts are refused: only application/json is accepted on unsafe routes', async () => {
  const { send, login, isSignedIn, store, verifier } = harness();
  const session = await login();
  const before = JSON.stringify(store.snapshot());
  const callsBefore = verifier.calls.length;
  const assertion = JSON.stringify({ assertion: BOB_ASSERTION });

  for (const contentType of [
    'application/x-www-form-urlencoded',
    'multipart/form-data; boundary=----atomic',
    'text/plain',
    'text/plain;charset=UTF-8',
    'application/jsonp',
    'application/json-patch+json',
    'text/json',
    null,
  ]) {
    for (const path of UNSAFE_ROUTES) {
      const response = await send(path, { method: 'POST', contentType, cookie: session.id, csrf: session.csrf, body: assertion });
      assert.equal(response.status, 415, `${path} ${contentType}`);
      assert.deepEqual(response.json, { error: 'unsupported_media_type' });
      assert.equal(response.setCookie, null);
    }
  }
  assert.equal(verifier.calls.length, callsBefore);
  assert.equal(JSON.stringify(store.snapshot()), before);
  assert.equal(await isSignedIn(session), true);

  const charset = await send('/api/session/logout', {
    method: 'POST', contentType: 'Application/JSON; charset=utf-8', cookie: session.id, csrf: session.csrf });
  assert.equal(charset.status, 200, 'JSON media type parameters and case are accepted');
});

test('OPTIONS preflight is never approved: no CORS headers for any origin', async () => {
  const { send, store } = harness();
  for (const origin of [FOREIGN_ORIGIN, ORIGIN, 'null']) {
    for (const path of ALL_ROUTES) {
      const response = await send(path, {
        method: 'OPTIONS',
        origin,
        headers: {
          'access-control-request-method': 'POST',
          'access-control-request-headers': `content-type, ${CSRF_HEADER}`,
        },
      });
      assert.equal(response.status, 405, `${origin} ${path}`);
      assert.deepEqual(response.json, { error: 'method_not_allowed' });
      assert.equal(response.setCookie, null);
      assert.ok(response.headers.get('allow'), 'Allow names the one supported method');
    }
  }
  assert.equal(store.snapshot().families.length, 0);
});

test('safe and other methods never mutate: GET/HEAD on state-changing routes are 405 and create nothing', async () => {
  const { send, login, isSignedIn, store, advance } = harness();
  const session = await login();
  const before = JSON.stringify(store.snapshot());

  for (const method of ['GET', 'HEAD', 'PUT', 'PATCH', 'DELETE']) {
    for (const path of UNSAFE_ROUTES) {
      const response = await send(path, { method, origin: ORIGIN, cookie: session.id, csrf: session.csrf });
      assert.equal(response.status, 405, `${method} ${path}`);
      assert.equal(response.headers.get('allow'), 'POST');
      assert.equal(response.setCookie, null);
    }
  }
  for (const method of ['HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']) {
    for (const path of SAFE_ROUTES) {
      const response = await send(path, { method, origin: ORIGIN, cookie: session.id, csrf: session.csrf });
      assert.equal(response.status, 405, `${method} ${path}`);
      assert.equal(response.headers.get('allow'), 'GET');
      assert.equal(response.setCookie, null);
    }
  }
  assert.equal(JSON.stringify(store.snapshot()), before, 'no session was created, rotated, touched or revoked');
  assert.equal(await isSignedIn(session), true, 'GET /logout did not log out');

  // HEAD does not rotate even when rotation is due.
  advance(15 * MINUTE);
  const head = await send('/api/session', { method: 'HEAD', cookie: session.id });
  assert.equal(head.status, 405);
  assert.equal(head.setCookie, null);

  // GET without a session never issues one.
  const fresh = harness();
  for (const path of SAFE_ROUTES) {
    assert.equal((await fresh.send(path)).setCookie, null);
  }
  assert.equal(fresh.store.snapshot().families.length, 0);
});

test('CSRF token: missing, malformed, forged or another session\'s token is rejected and the session survives', async () => {
  const { send, login, isSignedIn, store } = harness();
  const alice = await login();
  const bob = (await harness().login(BOB_ASSERTION));
  const before = JSON.stringify(store.snapshot());

  const bad: (string | undefined)[] = [undefined, '', 'x', `${alice.csrf}x`, alice.csrf.slice(1), randomToken(), bob.csrf, alice.id,
    alice.csrf.toLowerCase() === alice.csrf ? alice.csrf.toUpperCase() : alice.csrf.toLowerCase()];
  for (const csrf of bad) {
    const response = await send('/api/session/logout', { method: 'POST', cookie: alice.id, ...(csrf === undefined ? {} : { csrf }) });
    assert.equal(response.status, 403, `csrf=${csrf}`);
    assert.deepEqual(response.json, { error: 'csrf_rejected' });
    assert.equal(response.setCookie, null);
  }
  assert.equal(JSON.stringify(store.snapshot()), before, 'a rejected request leaves the session untouched');
  assert.equal(await isSignedIn(alice), true);

  // The token is a header, never a cookie or a query parameter.
  const inQuery = await send(`/api/session/logout?csrf=${alice.csrf}`, { method: 'POST', cookie: alice.id });
  assert.equal(inQuery.status, 403);
  const inBody = await send('/api/session/logout', { method: 'POST', cookie: alice.id, body: JSON.stringify({ csrf: alice.csrf }) });
  assert.equal(inBody.status, 403);
  assert.equal(await isSignedIn(alice), true);

  const ok = await send('/api/session/logout', { method: 'POST', cookie: alice.id, csrf: alice.csrf });
  assert.equal(ok.status, 200);
  assert.equal(await isSignedIn(alice), false);
});

test('CSRF token: a token is stale once its session id rotates', async () => {
  const { send, login, isSignedIn, advance } = harness();
  const first = await login();
  advance(15 * MINUTE);
  const rotation = await send('/api/session', { cookie: first.id });
  const second: Session = { id: issuedId(rotation), csrf: csrfOf(rotation) };
  assert.notEqual(second.id, first.id);
  assert.notEqual(second.csrf, first.csrf);

  const stale = await send('/api/session/logout', { method: 'POST', cookie: second.id, csrf: first.csrf });
  assert.equal(stale.status, 403);
  assert.deepEqual(stale.json, { error: 'csrf_rejected' });
  assert.equal(stale.setCookie, null);
  assert.equal(await isSignedIn(second), true);

  // Rotation through the account route also hands back the new token.
  advance(15 * MINUTE);
  const viaAccount = await send('/api/session/accounts/acct-alice', { cookie: second.id });
  const third: Session = { id: issuedId(viaAccount), csrf: csrfOf(viaAccount) };
  assert.notEqual(third.csrf, second.csrf);
  assert.equal((await send('/api/session/logout', { method: 'POST', cookie: third.id, csrf: second.csrf })).status, 403);

  assert.equal((await send('/api/session/logout', { method: 'POST', cookie: third.id, csrf: third.csrf })).status, 200);
});

test('CSRF token: tokens are stale after logout, re-login and revocation', async () => {
  const { send, login, isSignedIn } = harness();
  const first = await login();
  const second = await login(ALICE_ASSERTION, first);
  assert.notEqual(second.csrf, first.csrf);
  assert.equal((await send('/api/session/logout', { method: 'POST', cookie: second.id, csrf: first.csrf })).status, 403);
  assert.equal(await isSignedIn(second), true);

  assert.equal((await send('/api/session/logout', { method: 'POST', cookie: second.id, csrf: second.csrf })).status, 200);
  const third = await login();
  for (const stale of [first.csrf, second.csrf]) {
    const response = await send('/api/session/logout', { method: 'POST', cookie: third.id, csrf: stale });
    assert.equal(response.status, 403);
    assert.equal(response.setCookie, null);
  }
  assert.equal(await isSignedIn(third), true);
});

test('login and start that act on a presented session require that session\'s token', async () => {
  const { send, start, login, isSignedIn, verifier, store } = harness();

  const preAuth = await start();
  const callsBefore = verifier.calls.length;
  for (const csrf of [undefined, randomToken()]) {
    const response = await send('/api/session/login', {
      method: 'POST', cookie: preAuth.id, body: JSON.stringify({ assertion: ALICE_ASSERTION }), ...(csrf === undefined ? {} : { csrf }) });
    assert.equal(response.status, 403);
    assert.deepEqual(response.json, { error: 'csrf_rejected' });
    assert.equal(response.setCookie, null);
  }
  assert.equal(verifier.calls.length, callsBefore, 'the single-use assertion was not consumed');
  assert.deepEqual((await send('/api/session', { cookie: preAuth.id })).json, { signedIn: false, csrf: preAuth.csrf });

  const alice = await login(ALICE_ASSERTION, preAuth);
  const before = JSON.stringify(store.snapshot());
  const restart = await send('/api/session/start', { method: 'POST', cookie: alice.id });
  assert.equal(restart.status, 403);
  assert.deepEqual(restart.json, { error: 'csrf_rejected' });
  assert.equal(restart.setCookie, null);
  assert.equal(JSON.stringify(store.snapshot()), before);
  assert.equal(await isSignedIn(alice), true);

  const bobOverAlice = await send('/api/session/login', {
    method: 'POST', cookie: alice.id, body: JSON.stringify({ assertion: BOB_ASSERTION }) });
  assert.equal(bobOverAlice.status, 403);
  assert.equal(await isSignedIn(alice), true);

  const accepted = await send('/api/session/start', { method: 'POST', cookie: alice.id, csrf: alice.csrf });
  assert.equal(accepted.status, 200);
  assert.equal(await isSignedIn(alice), false, 'start revoked the presented session');

  // A cookie the server does not recognise is not a session to protect: it is never adopted.
  const unknown = await send('/api/session/login', {
    method: 'POST', cookie: randomToken(), body: JSON.stringify({ assertion: ALICE_ASSERTION }) });
  assert.equal(unknown.status, 200);
});

test('a session bound to one origin is not reachable from another allowlisted origin, even with its token', async () => {
  const { send, login, isSignedIn } = harness();
  const alice = await login();
  for (const path of UNSAFE_ROUTES) {
    const response = await send(path, {
      method: 'POST', origin: SECOND_ORIGIN, cookie: alice.id, csrf: alice.csrf, body: JSON.stringify({ assertion: BOB_ASSERTION }) });
    assert.equal(response.status, 403, path);
    assert.deepEqual(response.json, { error: 'origin_rejected' });
    assert.equal(response.setCookie, null);
  }
  assert.equal(await isSignedIn(alice), true);
});

test('the token is never stored, never set as a cookie and no response grants cross-origin access', async () => {
  const { send, start, login, store, transcript, advance } = harness();
  const preAuth = await start();
  const alice = await login(ALICE_ASSERTION, preAuth);
  advance(15 * MINUTE);
  const rotated = await send('/api/session', { cookie: alice.id });
  const current: Session = { id: issuedId(rotated), csrf: csrfOf(rotated) };
  await send('/api/session', { cookie: current.id, origin: FOREIGN_ORIGIN });
  await send('/api/session/logout', { method: 'OPTIONS', origin: FOREIGN_ORIGIN });
  await send('/api/session/logout', { method: 'POST', cookie: current.id });
  const stored = JSON.stringify(store.snapshot());
  for (const token of [preAuth.csrf, alice.csrf, current.csrf]) {
    assert.equal(stored.includes(token), false, 'store holds no csrf token');
    for (const exchange of transcript) assert.equal((exchange.setCookie ?? '').includes(token), false);
  }
  await send('/api/session/logout', { method: 'POST', cookie: current.id, csrf: current.csrf });

  assert.equal(transcript.length, 7);
  for (const exchange of transcript) {
    assert.equal(exchange.headers.get('access-control-allow-origin'), null);
    assert.equal(exchange.headers.get('access-control-allow-credentials'), null);
  }
});
