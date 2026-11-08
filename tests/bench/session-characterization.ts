// C48: in-process characterization of the browser session routes.
//
//   node --import tsx tests/bench/session-characterization.ts [samplesPerPoint]
//
// Drives the real app through `app.request` with the in-memory store and the
// controlled identity fixture: no network, no OAuth, no AppServer, no
// deployment. Writes ci-gateway-session-characterization.json with numbers
// only. These are local, single-process observations, not production capacity.
import { writeFileSync } from 'node:fs';
import { createApp } from '../../src/app.js';
import { MemorySessionStore } from '../../src/browser-sessions/store.js';
import { ALICE_ASSERTION, FixtureIdentityVerifier } from '../support/identity-fixture.js';

const ORIGIN = 'https://notes.atomic.test';
const ENV = { ATOMIC_BROWSER_SESSIONS_ENABLED: 'true', ATOMIC_BROWSER_ALLOWED_ORIGINS: ORIGIN };
const COOKIE = /__Host-atomic_session=([A-Za-z0-9_-]{43})/;

export function percentile(sorted: readonly number[], p: number): number {
  if (sorted.length === 0) return 0;
  const index = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[index] as number;
}

export function summarize(samples: readonly number[]) {
  const sorted = [...samples].sort((a, b) => a - b);
  const round = (n: number) => Math.round(n * 1000) / 1000;
  return {
    n: sorted.length,
    p50Ms: round(percentile(sorted, 50)),
    p90Ms: round(percentile(sorted, 90)),
    p99Ms: round(percentile(sorted, 99)),
    maxMs: round(sorted[sorted.length - 1] ?? 0),
  };
}

type Step = 'start' | 'login' | 'status' | 'logout';

async function lifecycle(app: ReturnType<typeof createApp>, timings: Record<Step, number[]>, errors: Map<string, number>) {
  const time = async (step: Step, run: () => Response | Promise<Response>) => {
    const started = performance.now();
    const response = await run();
    timings[step].push(performance.now() - started);
    if (response.status >= 400) errors.set(`${step}_${response.status}`, (errors.get(`${step}_${response.status}`) ?? 0) + 1);
    return response;
  };
  const json = { origin: ORIGIN, 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' };
  const started = await time('start', () => app.request('/api/session/start', { method: 'POST', headers: json, body: '{}' }));
  const preId = COOKIE.exec(started.headers.get('set-cookie') ?? '')?.[1];
  const preCsrf = ((await started.json()) as { csrf?: string }).csrf;
  const loggedIn = await time('login', () => app.request('/api/session/login', {
    method: 'POST',
    headers: { ...json, cookie: `__Host-atomic_session=${preId}`, 'x-atomic-csrf': preCsrf ?? '' },
    body: JSON.stringify({ assertion: ALICE_ASSERTION }),
  }));
  const id = COOKIE.exec(loggedIn.headers.get('set-cookie') ?? '')?.[1];
  const csrf = ((await loggedIn.json()) as { csrf?: string }).csrf;
  await time('status', () => app.request('/api/session', { headers: { origin: ORIGIN, 'sec-fetch-site': 'same-origin', cookie: `__Host-atomic_session=${id}` } }));
  await time('logout', () => app.request('/api/session/logout', {
    method: 'POST', headers: { ...json, cookie: `__Host-atomic_session=${id}`, 'x-atomic-csrf': csrf ?? '' }, body: '{}',
  }));
}

export async function characterize(samplesPerPoint: number) {
  const points = [];
  for (const concurrency of [1, 8, 32, 128]) {
    const store = new MemorySessionStore();
    const app = createApp({ env: ENV, browserSessions: { store, verifier: new FixtureIdentityVerifier() } });
    const timings: Record<Step, number[]> = { start: [], login: [], status: [], logout: [] };
    const errors = new Map<string, number>();
    globalThis.gc?.();
    const before = process.memoryUsage();
    let peakRss = before.rss;
    const begun = performance.now();
    for (let done = 0; done < samplesPerPoint; done += concurrency) {
      const batch = Math.min(concurrency, samplesPerPoint - done);
      await Promise.all(Array.from({ length: batch }, () => lifecycle(app, timings, errors)));
      peakRss = Math.max(peakRss, process.memoryUsage().rss);
    }
    const elapsedMs = performance.now() - begun;
    const after = process.memoryUsage();
    points.push({
      concurrency,
      lifecycles: samplesPerPoint,
      lifecyclesPerSecond: Math.round((samplesPerPoint / elapsedMs) * 1000),
      steps: Object.fromEntries(Object.entries(timings).map(([step, samples]) => [step, summarize(samples)])),
      errors: Object.fromEntries([...errors.entries()].sort()),
      liveFamiliesAfterLogout: store.snapshot().families.length,
      memoryKiB: {
        rssBefore: Math.round(before.rss / 1024),
        rssAfter: Math.round(after.rss / 1024),
        rssPeak: Math.round(peakRss / 1024),
        heapUsedBefore: Math.round(before.heapUsed / 1024),
        heapUsedAfter: Math.round(after.heapUsed / 1024),
      },
    });
  }
  return {
    version: 1,
    scope: 'in-process gateway session routes, in-memory store, fixture identity; not production capacity',
    node: process.version,
    samplesPerPoint,
    points,
  };
}

if (import.meta.url === `file://${process.argv[1]?.replace(/\\/g, '/').replace(/^(?=[A-Za-z]:)/, '/')}`
    || process.argv[1]?.endsWith('session-characterization.ts')) {
  const samples = Math.max(50, Math.min(5000, Number(process.argv[2] ?? 400) || 400));
  const report = await characterize(samples);
  writeFileSync('ci-gateway-session-characterization.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report.points.map(p => ({ c: p.concurrency, perSecond: p.lifecyclesPerSecond,
    loginP99: p.steps['login']?.p99Ms, errors: p.errors, liveFamilies: p.liveFamiliesAfterLogout }))));
}
