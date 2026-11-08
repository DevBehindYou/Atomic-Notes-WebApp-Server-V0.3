import assert from 'node:assert/strict';
import test from 'node:test';
import { characterize, percentile, summarize } from './bench/session-characterization.js';

test('percentiles use the nearest-rank method', () => {
  const sorted = Array.from({ length: 100 }, (_, i) => i + 1);
  assert.deepEqual([percentile(sorted, 50), percentile(sorted, 90), percentile(sorted, 99), percentile(sorted, 100)],
    [50, 90, 99, 100]);
  assert.equal(percentile([], 50), 0);
  assert.deepEqual(summarize([3, 1, 2]), { n: 3, p50Ms: 2, p90Ms: 3, p99Ms: 3, maxMs: 3 });
});

test('a small characterization run completes every lifecycle and leaves no live session', async () => {
  const report = await characterize(50);
  assert.equal(report.scope.includes('not production capacity'), true);
  for (const point of report.points) {
    assert.deepEqual(point.errors, {}, `concurrency ${point.concurrency}`);
    assert.equal(point.liveFamiliesAfterLogout, 0);
    for (const step of ['start', 'login', 'status', 'logout']) {
      assert.equal(point.steps[step]?.n, 50);
    }
  }
  // Numbers and fixed codes only: nothing session-, account- or token-shaped.
  const text = JSON.stringify(report);
  assert.doesNotMatch(text, /acct-|fixture-assertion|CANARY|__Host-|[A-Za-z0-9_-]{43}/);
});
