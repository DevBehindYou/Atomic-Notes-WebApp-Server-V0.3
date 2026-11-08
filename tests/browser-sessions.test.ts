import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import { createApp } from '../src/app.js';
import { readBoundedUtf8 } from '../src/browser-sessions/routes.js';
import { hashSessionId } from '../src/browser-sessions/service.js';
import { MemorySessionStore } from '../src/browser-sessions/store.js';
import {
  ALICE_ASSERTION,
  BOB_ASSERTION,
  CANARIES,
  FixtureIdentityVerifier,
} from './support/identity-fixture.js';

const ORIGIN = 'https://app.atomic.test';
const SECOND_ORIGIN = 'https://beta.atomic.test';
const FOREIGN_ORIGIN = 'https://evil.invalid';
const ENABLED_ENV = {
  ATOMIC_BROWSER_SESSIONS_ENABLED: 'true',
  ATOMIC_BROWSER_ALLOWED_ORIGINS: `${ORIGIN}, ${SECOND_ORIGIN}`,
};
const MINUTE = 60 * 1000;
const COOKIE_PATTERN = /^__Host-atomic_session=([A-Za-z0-9_-]{43}); Path=\/; Max-Age=(\d+); HttpOnly; Secure; SameSite=Strict$/;
const CLEAR_COOKIE = '__Host-atomic_session=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict';
const SESSION_ROUTES = ['/api/session', '/api/session/start', '/api/session/login', '/api/session/logout', '/api/session/accounts/acct-alice'];
const READY_BODY = {
  status: 'not_ready',
  service: 'atomic-notes-webapp-server',
  browser_session: 'unimplemented',
  appserver_delegation: 'unimplemented',
};

interface SendOptions {
  method?: 'GET' | 'POST' | 'HEAD';
  origin?: string | null;
  cookie?: string | undefined;
  body?: unknown;
  rawBody?: string;
  headers?: Record<string, string>;
}

interface Exchange {
  status: number;
  text: string;
  json: unknown;
  setCookie: string | null;
  headers: Headers;
}

function harness(options: { verifier?: FixtureIdentityVerifier | null } = {}) {
  let now = Date.UTC(2026, 10, 8, 9, 0, 0);
  const store = new MemorySessionStore();
  const verifier = options.verifier === null ? undefined : (options.verifier ?? new FixtureIdentityVerifier());
  const app = createApp({
    env: ENABLED_ENV,
    browserSessions: { store, clock: () => now, ...(verifier === undefined ? {} : { verifier }) },
  });
  const transcript: Exchange[] = [];

  async function send(path: string, request: SendOptions = {}): Promise<Exchange> {
    const method = request.method ?? 'GET';
    const headers: Record<string, string> = { ...request.headers };
    const origin = request.origin === undefined ? (method === 'POST' ? ORIGIN : null) : request.origin;
    if (origin !== null) headers['origin'] = origin;
    if (request.cookie !== undefined) headers['cookie'] = `__Host-atomic_session=${request.cookie}`;
    let body: string | undefined = request.rawBody;
    if (request.body !== undefined) {
      body = JSON.stringify(request.body);
      headers['content-type'] ??= 'application/json';
    }
    const response = await app.request(path, { method, headers, ...(body === undefined ? {} : { body }) });
    const text = await response.text();
    const exchange: Exchange = {
      status: response.status,
      text,
      json: text === '' ? undefined : JSON.parse(text),
      setCookie: response.headers.get('set-cookie'),
      headers: response.headers,
    };
    assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
    assert.equal(response.headers.get('access-control-allow-origin'), null);
    transcript.push(exchange);
    return exchange;
  }

  async function login(assertion = ALICE_ASSERTION, cookie?: string, origin = ORIGIN): Promise<string> {
    const response = await send('/api/session/login', { method: 'POST', origin, cookie, body: { assertion } });
    assert.equal(response.status, 200, response.text);
    return issuedId(response);
  }

  return {
    store,
    verifier,
    transcript,
    send,
    login,
    advance(ms: number) { now += ms; },
    now: () => now,
  };
}

function issuedId(exchange: Exchange): string {
  const match = COOKIE_PATTERN.exec(exchange.setCookie ?? '');
  assert.ok(match, `expected a session cookie, got ${exchange.setCookie}`);
  return match[1] as string;
}

function maxAge(exchange: Exchange): number {
  return Number(COOKIE_PATTERN.exec(exchange.setCookie ?? '')?.[2]);
}

function forgedId(): string {
  return randomBytes(32).toString('base64url');
}

test('flag off: session routes keep the existing 404 boundary and readiness is unchanged', async () => {
  const variants = [
    createApp(),
    createApp({ env: {} }),
    createApp({ env: { ...ENABLED_ENV, ATOMIC_BROWSER_SESSIONS_ENABLED: '1' } }),
    createApp({ env: { ...ENABLED_ENV, ATOMIC_BROWSER_SESSIONS_ENABLED: 'TRUE' } }),
    createApp({ env: { ATOMIC_BROWSER_ALLOWED_ORIGINS: ORIGIN }, browserSessions: { verifier: new FixtureIdentityVerifier() } }),
  ];
  for (const app of variants) {
    for (const path of SESSION_ROUTES) {
      for (const method of ['GET', 'POST']) {
        const response = await app.request(path, {
          method,
          headers: { origin: ORIGIN, 'content-type': 'application/json', cookie: `__Host-atomic_session=${forgedId()}` },
          ...(method === 'POST' ? { body: JSON.stringify({ assertion: ALICE_ASSERTION }) } : {}),
        });
        assert.equal(response.status, 404, `${method} ${path}`);
        assert.deepEqual(await response.json(), { error: 'not_found' });
        assert.equal(response.headers.get('set-cookie'), null);
      }
    }
    const ready = await app.request('/api/ready');
    assert.equal(ready.status, 503);
    assert.deepEqual(await ready.json(), READY_BODY);
  }
});

test('flag on without a valid exact HTTPS origin allowlist fails closed with 503', async () => {
  for (const origins of [undefined, '', ' , ', 'http://app.atomic.test', 'https://app.atomic.test/', '*', `${ORIGIN},not a url`]) {
    const env: Record<string, string> = { ATOMIC_BROWSER_SESSIONS_ENABLED: 'true' };
    if (origins !== undefined) env['ATOMIC_BROWSER_ALLOWED_ORIGINS'] = origins;
    const app = createApp({ env, browserSessions: { verifier: new FixtureIdentityVerifier() } });
    for (const path of SESSION_ROUTES) {
      const response = await app.request(path, { method: 'POST', headers: { origin: ORIGIN } });
      assert.equal(response.status, 503, `${origins} ${path}`);
      assert.deepEqual(await response.json(), { error: 'browser_sessions_unavailable' });
      assert.equal(response.headers.get('set-cookie'), null);
    }
    const ready = await app.request('/api/ready');
    assert.equal(ready.status, 503);
    assert.deepEqual(await ready.json(), READY_BODY);
  }
});

test('flag on: readiness and health stay exactly as before; unrelated routes still 404', async () => {
  const { send } = harness();
  const ready = await send('/api/ready');
  assert.equal(ready.status, 503);
  assert.deepEqual(ready.json, READY_BODY);
  const health = await send('/api/health');
  assert.deepEqual(health.json, { status: 'ok', service: 'atomic-notes-webapp-server' });
  for (const path of ['/api/notes', '/api/session/extra', '/api/auth/callback']) {
    const response = await send(path, { method: 'POST' });
    assert.equal(response.status, 404, path);
  }
});

test('login issues a 256-bit __Host- cookie with exact attributes and non-secret status only', async () => {
  const { send, store, verifier } = harness();
  const response = await send('/api/session/login', { method: 'POST', body: { assertion: ALICE_ASSERTION } });
  assert.equal(response.status, 200);
  assert.match(response.setCookie ?? '', COOKIE_PATTERN);
  assert.equal(maxAge(response), 12 * 60 * 60);
  assert.doesNotMatch(response.setCookie ?? '', /Domain=/i);
  assert.equal(Buffer.from(issuedId(response), 'base64url').length, 32);
  assert.deepEqual(response.json, {
    signedIn: true,
    accountHint: 'a***@example.test',
    expiresAt: '2026-11-08T09:30:00.000Z',
  });
  assert.deepEqual(verifier?.calls, [{ assertion: ALICE_ASSERTION, origin: ORIGIN }]);

  const status = await send('/api/session', { cookie: issuedId(response) });
  assert.deepEqual(status.json, response.json);
  assert.equal(status.setCookie, null);

  const [family] = store.snapshot().families;
  assert.equal(family?.idHash, hashSessionId(issuedId(response)));
  assert.equal(family?.accountId, 'acct-alice');
});

test('login without a configured identity verifier answers 503 and issues nothing', async () => {
  const { send } = harness({ verifier: null });
  const response = await send('/api/session/login', { method: 'POST', body: { assertion: ALICE_ASSERTION } });
  assert.equal(response.status, 503);
  assert.deepEqual(response.json, { error: 'identity_unavailable' });
  assert.equal(response.setCookie, null);
});

test('fixation: server never adopts an id it did not issue', async () => {
  const { send, login, store } = harness();
  const attackerId = forgedId();

  const probe = await send('/api/session', { cookie: attackerId });
  assert.deepEqual(probe.json, { signedIn: false });
  assert.equal(probe.setCookie, CLEAR_COOKIE);

  const sessionId = await login(ALICE_ASSERTION, attackerId);
  assert.notEqual(sessionId, attackerId);
  assert.deepEqual((await send('/api/session', { cookie: attackerId })).json, { signedIn: false });
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: attackerId })).status, 401);
  assert.equal(((await send('/api/session', { cookie: sessionId })).json as { signedIn: boolean }).signedIn, true);
  assert.equal(store.snapshot().families.length, 1);

  for (const malformed of ['short', `${attackerId}x`, 'a'.repeat(42) + '=']) {
    const response = await send('/api/session', { cookie: malformed });
    assert.deepEqual(response.json, { signedIn: false });
    assert.equal(response.setCookie, CLEAR_COOKIE);
  }

  const duplicate = await send('/api/session', {
    headers: { cookie: `__Host-atomic_session=${sessionId}; __Host-atomic_session=${attackerId}` },
  });
  assert.deepEqual(duplicate.json, { signedIn: false });
  assert.equal(duplicate.setCookie, CLEAR_COOKIE);
});

test('fixation: a pre-login session id is replaced and invalidated at login', async () => {
  const { send, login, store, advance } = harness();
  const start = await send('/api/session/start', { method: 'POST' });
  assert.deepEqual(start.json, { signedIn: false });
  const preAuthId = issuedId(start);
  assert.equal(maxAge(start), 10 * 60);

  const pending = await send('/api/session', { cookie: preAuthId });
  assert.deepEqual(pending.json, { signedIn: false });
  assert.equal(pending.setCookie, null);
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: preAuthId })).status, 401);

  const sessionId = await login(ALICE_ASSERTION, preAuthId);
  assert.notEqual(sessionId, preAuthId);
  const replay = await send('/api/session', { cookie: preAuthId });
  assert.deepEqual(replay.json, { signedIn: false });
  assert.equal(replay.setCookie, CLEAR_COOKIE);
  assert.equal(store.snapshot().families.length, 1);
  assert.equal((await send('/api/session', { cookie: sessionId })).status, 200);

  const abandoned = issuedId(await send('/api/session/start', { method: 'POST' }));
  advance(10 * MINUTE);
  const expired = await send('/api/session', { cookie: abandoned });
  assert.deepEqual(expired.json, { signedIn: false });
  assert.equal(expired.setCookie, CLEAR_COOKIE);
});

test('idle expiry ends an inactive session and removes it server-side', async () => {
  const { send, login, store, advance } = harness();
  const sessionId = await login();
  advance(29 * MINUTE);
  const active = await send('/api/session', { cookie: sessionId });
  assert.equal((active.json as { signedIn: boolean }).signedIn, true);
  assert.equal((active.json as { expiresAt: string }).expiresAt, '2026-11-08T09:59:00.000Z');
  // 29 minutes also crosses the rotation interval; continue with the rotated id so the
  // assertions below exercise idle expiry, not retired-id replay.
  const currentId = issuedId(active);

  advance(30 * MINUTE);
  const expired = await send('/api/session', { cookie: currentId });
  assert.deepEqual(expired.json, { signedIn: false });
  assert.equal(expired.setCookie, CLEAR_COOKIE);
  assert.deepEqual(store.snapshot(), { families: [], retiredIdHashes: [] });

  const boundaryId = await login();
  advance(30 * MINUTE - 1);
  assert.equal(((await send('/api/session/accounts/acct-alice', { cookie: boundaryId })).status), 200);
});

test('absolute expiry ends a session even with continuous activity across rotations', async () => {
  const { send, login, store, advance } = harness();
  let sessionId = await login();
  const rotated = new Set<string>([sessionId]);
  for (let elapsed = 10 * MINUTE; elapsed < 12 * 60 * MINUTE; elapsed += 10 * MINUTE) {
    advance(10 * MINUTE);
    const response = await send('/api/session', { cookie: sessionId });
    assert.equal((response.json as { signedIn: boolean }).signedIn, true, `elapsed ${elapsed}`);
    if (response.setCookie !== null) {
      sessionId = issuedId(response);
      assert.equal(maxAge(response), (12 * 60 * MINUTE - elapsed) / 1000);
      rotated.add(sessionId);
    }
  }
  assert.ok(rotated.size > 20, 'session id rotated periodically');
  advance(10 * MINUTE);
  const expired = await send('/api/session', { cookie: sessionId });
  assert.deepEqual(expired.json, { signedIn: false });
  assert.equal(expired.setCookie, CLEAR_COOKIE);
  assert.equal(store.snapshot().families.length, 0);
});

test('rotation: periodic id rotation invalidates the old id; replaying it revokes the family', async () => {
  const { send, login, store, advance } = harness();
  const firstId = await login();
  advance(14 * MINUTE);
  assert.equal((await send('/api/session', { cookie: firstId })).setCookie, null);

  advance(1 * MINUTE);
  const rotation = await send('/api/session', { cookie: firstId });
  const secondId = issuedId(rotation);
  assert.notEqual(secondId, firstId);
  assert.equal(maxAge(rotation), 12 * 60 * 60 - 15 * 60);
  assert.equal((rotation.json as { signedIn: boolean }).signedIn, true);
  assert.equal(store.snapshot().families[0]?.idHash, hashSessionId(secondId));
  assert.deepEqual(store.snapshot().retiredIdHashes, [hashSessionId(firstId)]);
  assert.equal((await send('/api/session', { cookie: secondId })).status, 200);

  const replay = await send('/api/session', { cookie: firstId });
  assert.deepEqual(replay.json, { signedIn: false });
  assert.equal(replay.setCookie, CLEAR_COOKIE);
  assert.deepEqual(store.snapshot(), { families: [], retiredIdHashes: [] });

  const victim = await send('/api/session', { cookie: secondId });
  assert.deepEqual(victim.json, { signedIn: false });
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: secondId })).status, 401);
});

test('rotation: re-login rotates even for the same account and invalidates the previous id', async () => {
  const { send, login } = harness();
  const firstId = await login();
  const secondId = await login(ALICE_ASSERTION, firstId);
  assert.notEqual(secondId, firstId);
  assert.deepEqual((await send('/api/session', { cookie: firstId })).json, { signedIn: false });
  assert.equal((await send('/api/session', { cookie: secondId })).status, 200);
});

test('logout deletes the session server-side and clears the cookie', async () => {
  const { send, login, store } = harness();
  const sessionId = await login();

  const missingOrigin = await send('/api/session/logout', { method: 'POST', origin: null, cookie: sessionId });
  assert.equal(missingOrigin.status, 403);
  assert.equal(missingOrigin.setCookie, null);

  const logout = await send('/api/session/logout', { method: 'POST', cookie: sessionId });
  assert.equal(logout.status, 200);
  assert.deepEqual(logout.json, { signedIn: false });
  assert.equal(logout.setCookie, CLEAR_COOKIE);
  assert.deepEqual(store.snapshot(), { families: [], retiredIdHashes: [] });

  const replay = await send('/api/session', { cookie: sessionId });
  assert.deepEqual(replay.json, { signedIn: false });
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: sessionId })).status, 401);

  const again = await send('/api/session/logout', { method: 'POST' });
  assert.equal(again.status, 200);
  assert.equal(again.setCookie, CLEAR_COOKIE);
});

test('logout with a rotated (retired) id revokes the whole family', async () => {
  const { send, login, store, advance } = harness();
  const firstId = await login();
  advance(15 * MINUTE);
  const secondId = issuedId(await send('/api/session', { cookie: firstId }));
  await send('/api/session/logout', { method: 'POST', cookie: firstId });
  assert.deepEqual(store.snapshot(), { families: [], retiredIdHashes: [] });
  assert.deepEqual((await send('/api/session', { cookie: secondId })).json, { signedIn: false });
});

test('wrong origin: foreign, missing and cross-site requests are rejected; sessions are origin bound', async () => {
  const { send, login, verifier, store } = harness();

  for (const request of [
    { origin: FOREIGN_ORIGIN },
    { origin: null },
    { origin: 'null' },
    { origin: `${ORIGIN}/` },
    { origin: ORIGIN, headers: { 'sec-fetch-site': 'cross-site' } },
  ] as const) {
    for (const path of ['/api/session/login', '/api/session/start']) {
      const response = await send(path, { method: 'POST', body: { assertion: ALICE_ASSERTION }, ...request });
      assert.equal(response.status, 403, `${path} ${JSON.stringify(request)}`);
      assert.deepEqual(response.json, { error: 'origin_rejected' });
      assert.equal(response.setCookie, null);
    }
  }
  assert.equal(verifier?.calls.length, 0);
  assert.equal(store.snapshot().families.length, 0);

  const sessionId = await login();
  const foreign = await send('/api/session', { cookie: sessionId, origin: FOREIGN_ORIGIN });
  assert.equal(foreign.status, 403);
  const crossSite = await send('/api/session/accounts/acct-alice', { cookie: sessionId, headers: { 'sec-fetch-site': 'cross-site' } });
  assert.equal(crossSite.status, 403);

  const otherAllowed = await send('/api/session/accounts/acct-alice', { cookie: sessionId, origin: SECOND_ORIGIN });
  assert.equal(otherAllowed.status, 403);
  assert.deepEqual(otherAllowed.json, { error: 'origin_rejected' });
  const otherLogout = await send('/api/session/logout', { method: 'POST', cookie: sessionId, origin: SECOND_ORIGIN });
  assert.equal(otherLogout.status, 403);
  assert.equal(otherLogout.setCookie, null);

  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: sessionId, origin: ORIGIN })).status, 200);
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: sessionId, headers: { 'sec-fetch-site': 'same-origin' } })).status, 200);
});

test('wrong account: a session for account A cannot act as account B', async () => {
  const { send, login } = harness();
  assert.deepEqual((await send('/api/session/accounts/acct-alice')).json, { error: 'session_required' });

  const aliceId = await login(ALICE_ASSERTION);
  const own = await send('/api/session/accounts/acct-alice', { cookie: aliceId });
  assert.equal(own.status, 200);
  assert.equal((own.json as { signedIn: boolean }).signedIn, true);
  const other = await send('/api/session/accounts/acct-bob', { cookie: aliceId });
  assert.equal(other.status, 403);
  assert.deepEqual(other.json, { error: 'account_mismatch' });

  const bobId = await login(BOB_ASSERTION, aliceId);
  assert.notEqual(bobId, aliceId);
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: aliceId })).status, 401);
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: bobId })).status, 403);
  const bob = await send('/api/session/accounts/acct-bob', { cookie: bobId });
  assert.equal(bob.status, 200);
  assert.deepEqual(Object.keys(bob.json as object).sort(), ['expiresAt', 'signedIn']);
});

test('rejected or malformed logins issue nothing and keep the existing session', async () => {
  const { send, login } = harness();
  const sessionId = await login();
  const cases: SendOptions[] = [
    { body: { assertion: 'fixture-assertion-unknown' } },
    { body: { assertion: '' } },
    { body: { assertion: 42 } },
    { body: {} },
    { body: { assertion: 'x'.repeat(4097) } },
    { rawBody: 'not json', headers: { 'content-type': 'application/json' } },
    { rawBody: JSON.stringify({ assertion: ALICE_ASSERTION }), headers: { 'content-type': 'text/plain' } },
    { rawBody: JSON.stringify({ assertion: ALICE_ASSERTION }) },
  ];
  for (const request of cases) {
    const response = await send('/api/session/login', { method: 'POST', cookie: sessionId, ...request });
    assert.ok([400, 401].includes(response.status), response.text);
    assert.equal(response.setCookie, null);
  }
  assert.equal((await send('/api/session/accounts/acct-alice', { cookie: sessionId })).status, 200);
});

test('no provider or AppServer tokens reach browser responses or the session store', async () => {
  const { send, login, store, transcript, advance } = harness();
  const preAuthId = issuedId(await send('/api/session/start', { method: 'POST' }));
  const aliceId = await login(ALICE_ASSERTION, preAuthId);
  await send('/api/session', { cookie: aliceId });
  advance(15 * MINUTE);
  const rotatedId = issuedId(await send('/api/session/accounts/acct-alice', { cookie: aliceId }));
  await send('/api/session/accounts/acct-bob', { cookie: rotatedId });
  const bobId = await login(BOB_ASSERTION, rotatedId);
  await send('/api/session', { cookie: bobId, origin: FOREIGN_ORIGIN });
  await send('/api/session/login', { method: 'POST', body: { assertion: 'fixture-assertion-unknown' } });
  await send('/api/session/logout', { method: 'POST', cookie: bobId });
  const finalId = await login(ALICE_ASSERTION);

  const surfaced = transcript.map((exchange) => {
    const parts = [exchange.text];
    exchange.headers.forEach((value, name) => parts.push(name, value));
    return parts.join('\n');
  }).join('\n');
  for (const canary of CANARIES) assert.equal(surfaced.includes(canary), false, canary);
  assert.doesNotMatch(surfaced, /token|bearer|credential/i);

  const stored = JSON.stringify(store.snapshot());
  for (const canary of CANARIES) assert.equal(stored.includes(canary), false, canary);
  for (const rawId of [preAuthId, aliceId, rotatedId, bobId, finalId]) assert.equal(stored.includes(rawId), false);
  assert.equal(stored.includes(hashSessionId(finalId)), true);
  assert.doesNotMatch(stored, /credential|token/i);
});

/** A request body delivered as a stream with no Content-Length, in [chunks]. */
function streamed(chunks: Uint8Array[], pulled: { count: number }, headers: Record<string, string> = {}): Request {
  let index = 0;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      pulled.count++;
      if (index < chunks.length) controller.enqueue(chunks[index++] as Uint8Array);
      else controller.close();
    },
  });
  return new Request('http://gateway.test/api/session/login', {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-type': 'application/json', ...headers },
    body,
    duplex: 'half',
  } as RequestInit);
}

test('login bodies are capped by bytes actually read, never by a declared or UTF-16 length', async () => {
  const verifier = new FixtureIdentityVerifier();
  const { send, store } = harness({ verifier });
  const app = createApp({ env: ENABLED_ENV, browserSessions: { store, verifier } });
  const before = JSON.stringify(store.snapshot());
  const callsBefore = verifier.calls.length;

  // A valid assertion padded with 5,000 three-byte characters: under the
  // 8,192 UTF-16 code units the old check counted, but over 8 KiB of UTF-8.
  const multibyte = JSON.stringify({ assertion: ALICE_ASSERTION, pad: '€'.repeat(5000) });
  assert.ok(multibyte.length < 8192 && Buffer.byteLength(multibyte) > 8192);
  const response = await send('/api/session/login', {
    method: 'POST', rawBody: multibyte, headers: { 'content-type': 'application/json' } });
  assert.equal(response.status, 400, response.text);

  // No Content-Length (chunked) and a false small Content-Length: reading stops
  // just past the cap and the stream is cancelled.
  const big = new Uint8Array(1024).fill(0x20);
  for (const headers of [{}, { 'content-length': '10' }]) {
    const pulled = { count: 0 };
    const chunks = Array.from({ length: 64 }, () => big);
    const result = await app.request(streamed(chunks, pulled, headers));
    assert.equal(result.status, 400);
    assert.equal(result.headers.get('set-cookie'), null);
    assert.ok(pulled.count <= 10, `read ${pulled.count} chunks of 64`);
  }

  // Invalid UTF-8 is refused, not replaced.
  const invalid = await app.request(streamed([new Uint8Array([0x7b, 0xff, 0xfe, 0x7d])], { count: 0 }));
  assert.equal(invalid.status, 400);

  assert.equal(verifier.calls.length, callsBefore, 'the verifier never saw any of these bodies');
  assert.equal(JSON.stringify(store.snapshot()), before, 'nothing was stored');
});

test('readBoundedUtf8 returns the body within the cap and undefined past it', async () => {
  const ok = await readBoundedUtf8(new Request('http://x.test', { method: 'POST', body: '{"a":"€"}' }), 64);
  assert.equal(ok, '{"a":"€"}');
  assert.equal(await readBoundedUtf8(new Request('http://x.test', { method: 'POST', body: 'x'.repeat(65) }), 64), undefined);
  assert.equal(await readBoundedUtf8(new Request('http://x.test', { method: 'POST', body: 'x'.repeat(64) }), 64), 'x'.repeat(64));
  assert.equal(await readBoundedUtf8(new Request('http://x.test'), 64), '');
});
