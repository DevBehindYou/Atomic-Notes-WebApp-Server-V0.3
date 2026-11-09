import assert from 'node:assert/strict';
import test from 'node:test';
import { characterize, percentile, summarize } from './bench/session-characterization.js';
import { benchmarkVerifier } from './bench/delegation-characterization.js';
import { ALICE_ASSERTION } from './support/identity-fixture.js';

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
  assert.equal(report.memorySampling, 'before_after_and_batch_boundaries');
  for (const point of report.points) {
    assert.ok(point.memoryKiB.rssSampledMax >= point.memoryKiB.rssBefore);
    assert.ok(point.memoryKiB.heapUsedSampledMax >= point.memoryKiB.heapUsedBefore);
  }
  assert.equal(report.delegation.scope, 'in_process_payloads_no_sockets');
  assert.deepEqual(report.delegation.phases.map(p => p.mode), ['baseline', 'slow_provider', 'provider_unavailable', 'recovery']);
  for (const phase of report.delegation.phases) {
    assert.equal(phase.requests, 50);
    assert.equal(phase.logicalCalls, 50);
    assert.ok(phase.payloadBytes.gatewayRequest > 0);
    assert.ok(phase.payloadBytes.gatewayResponse > 0);
    assert.ok(phase.payloadBytes.delegationRequest > 0);
    assert.ok(phase.payloadBytes.delegationResponse > 0);
    assert.equal(phase.failed, phase.mode === 'provider_unavailable' ? 50 : 0);
  }
  assert.equal(report.delegation.liveFamiliesAfterLogout, 0);
  assert.equal(report.delegation.sufficientSamples, false);
});

test('the benchmark verifier discards assertions and rejects unknown identities', async () => {
  const verifier = benchmarkVerifier();
  for (let i = 0; i < 200; i++) assert.ok(await verifier.verify({ assertion: ALICE_ASSERTION, origin: 'https://notes.atomic.test' }));
  assert.equal(await verifier.verify({ assertion: 'unknown', origin: 'https://notes.atomic.test' }), null);
  assert.equal('calls' in verifier, false);
});
