import assert from 'node:assert/strict';
import test from 'node:test';
import app from '../dist/app.js';

test('compiled default export serves Vercel-compatible fetch requests without starting a listener', async () => {
  assert.equal(typeof app.fetch, 'function');
  const response = await app.fetch(new Request('https://staging.invalid/api/health'));
  assert.equal(response.status, 200);
  assert.deepEqual(await response.json(), { status: 'ok', service: 'atomic-notes-webapp-server' });
  assert.equal(response.headers.get('cache-control'), 'no-store, no-cache, must-revalidate');
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
});
