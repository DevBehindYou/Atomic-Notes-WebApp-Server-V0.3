import assert from 'node:assert/strict';
import test from 'node:test';
import { HTTPException } from 'hono/http-exception';
import app, { createApp } from '../src/app.js';

function assertResponseBoundary(response: Response): void {
  assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.match(response.headers.get('content-type') ?? '', /^application\/json/);
  assert.equal(response.headers.get('set-cookie'), null);
  assert.equal(response.headers.get('access-control-allow-origin'), null);
  assert.equal(response.headers.get('access-control-allow-credentials'), null);
}

test('health confirms only the fixed WebAppServer process identity', async () => {
  const response = await app.request('/api/health?service=untrusted&token=sensitive');
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok', service: 'atomic-notes-webapp-server' });
  assertResponseBoundary(response);
});

test('readiness remains unavailable until browser sessions and delegation are implemented', async () => {
  const response = await app.request('/api/ready');
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), {
    status: 'not_ready',
    service: 'atomic-notes-webapp-server',
    browser_session: 'unimplemented',
    appserver_delegation: 'unimplemented',
  });
  assertResponseBoundary(response);
});

test('unknown and planned routes return a fixed response without reflecting request data', async () => {
  for (const path of ['/', '/api/notes', '/api/auth/callback?code=sensitive', '/missing-sensitive-path']) {
    const response = await app.request(path, { headers: { origin: 'https://untrusted.invalid' } });
    assert.equal(response.status, 404, path);
    assert.deepEqual(await response.json(), { error: 'not_found' });
    assertResponseBoundary(response);
  }
});

test('unsafe methods and preflight requests cannot activate status or future mutation routes', async () => {
  for (const path of ['/api/health', '/api/ready', '/api/notes']) {
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      const response = await app.request(path, {
        method,
        headers: { origin: 'https://untrusted.invalid', 'access-control-request-method': 'POST' },
      });
      assert.equal(response.status, 404, `${method} ${path}`);
      assert.deepEqual(await response.json(), { error: 'not_found' });
      assertResponseBoundary(response);
    }
  }
});

test('HEAD probes preserve status and response headers without a body', async () => {
  for (const [path, status] of [['/api/health', 200], ['/api/ready', 503]] as const) {
    const response = await app.request(path, { method: 'HEAD' });
    assert.equal(response.status, status);
    assert.equal(await response.text(), '');
    assertResponseBoundary(response);
  }
});

test('unexpected failures hide errors, stack traces and attached exception responses', async () => {
  const failingApp = createApp();
  failingApp.get('/failure', () => { throw new Error('sensitive stack/configuration value'); });
  failingApp.get('/http-failure', () => {
    throw new HTTPException(401, {
      res: new Response('sensitive exception response', { headers: { 'set-cookie': 'secret=value' } }),
    });
  });

  for (const path of ['/failure', '/http-failure']) {
    const response = await failingApp.request(path);
    assert.equal(response.status, 500);
    assert.deepEqual(await response.json(), { error: 'internal_server_error' });
    assertResponseBoundary(response);
  }
});
