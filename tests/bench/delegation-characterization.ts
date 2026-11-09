// Controlled, in-process C48 workload. No sockets, OAuth or external AppServer.
import { generateKeyPairSync, sign, verify } from 'node:crypto';
import { createApp } from '../../src/app.js';
import type { IdentityVerifier } from '../../src/browser-sessions/identity.js';
import { MemorySessionStore } from '../../src/browser-sessions/store.js';
import { httpDelegationTransport } from '../../src/delegation/client.js';
import { DELEGATION_CONTRACT, type DelegationClaims } from '../../src/delegation/contract.js';
import { ALICE_ASSERTION } from '../support/identity-fixture.js';

const ACCOUNT = '5e6f7081-1234-4abc-8def-123456789012';
const ORIGIN = 'https://notes.atomic.test';
const COOKIE = /__Host-atomic_session=([A-Za-z0-9_-]{43})/;
const HEADERS = { origin: ORIGIN, 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' };

/** Unlike the assertion-recording test fixture, retains no input history. */
export function benchmarkVerifier(): IdentityVerifier {
  return { verify: async input => input.assertion === ALICE_ASSERTION ? { accountId: ACCOUNT } : null };
}

const MODES = ['baseline', 'slow_provider', 'provider_unavailable', 'recovery'] as const;
type Mode = typeof MODES[number];
type Bytes = { gatewayRequest: number; gatewayResponse: number; delegationRequest: number; delegationResponse: number };

export async function characterizeDelegation(samples: number, summarize: (values: readonly number[]) => unknown) {
  const store = new MemorySessionStore();
  const keys = generateKeyPairSync('ed25519'); // ephemeral fixture only; never serialized
  let mode: Mode = 'baseline';
  let logicalCalls = 0;
  let bytes: Bytes = { gatewayRequest: 0, gatewayResponse: 0, delegationRequest: 0, delegationResponse: 0 };
  const transport = httpDelegationTransport({ appServerOrigin: 'https://appserver.atomic.test',
    fetch: async (_url, init) => {
      logicalCalls++;
      const body = String(init?.body ?? '');
      bytes.delegationRequest += Buffer.byteLength(body);
      const { assertion } = JSON.parse(body) as { assertion: string };
      const [header, payload, signature] = assertion.split('.') as [string, string, string];
      if (!verify(null, Buffer.from(`${header}.${payload}`, 'ascii'), keys.publicKey, Buffer.from(signature, 'base64url'))) {
        throw new Error('benchmark_invalid_signature');
      }
      const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as DelegationClaims;
      if (mode === 'slow_provider') await new Promise(resolve => setTimeout(resolve, 5));
      const responseBody = mode === 'provider_unavailable' ? { error: 'fixture_unavailable' }
        : { verified: true, contract: DELEGATION_CONTRACT, version: 1,
          iss: claims.iss, sub: claims.sub, exp: claims.exp, scope: claims.scope };
      const text = JSON.stringify(responseBody);
      bytes.delegationResponse += Buffer.byteLength(text);
      return new Response(text, { status: mode === 'provider_unavailable' ? 503 : 200 });
    },
  });
  const app = createApp({
    env: { ATOMIC_BROWSER_SESSIONS_ENABLED: 'true', ATOMIC_BROWSER_ALLOWED_ORIGINS: ORIGIN,
      ATOMIC_APPSERVER_DELEGATION_ENABLED: 'true', ATOMIC_APPSERVER_DELEGATION_AUDIENCE: 'atomic-appserver-fixture',
      ATOMIC_GATEWAY_DELEGATION_ISSUER: 'atomic-gateway-fixture', ATOMIC_GATEWAY_DELEGATION_KEY_ID: 'fixture-key' },
    browserSessions: { store, verifier: benchmarkVerifier() },
    delegation: { signer: { sign: async input => sign(null, input, keys.privateKey) }, transport },
  });
  const started = await app.request('/api/session/start', { method: 'POST', headers: HEADERS, body: '{}' });
  const preId = COOKIE.exec(started.headers.get('set-cookie') ?? '')?.[1];
  const pre = await started.json() as { csrf: string };
  const loggedIn = await app.request('/api/session/login', { method: 'POST',
    headers: { ...HEADERS, cookie: `__Host-atomic_session=${preId}`, 'x-atomic-csrf': pre.csrf },
    body: JSON.stringify({ assertion: ALICE_ASSERTION }) });
  const id = COOKIE.exec(loggedIn.headers.get('set-cookie') ?? '')?.[1];
  const login = await loggedIn.json() as { csrf: string };
  if (loggedIn.status !== 200 || !id || !login.csrf) throw new Error('benchmark_session_setup_failed');
  const headers = { ...HEADERS, cookie: `__Host-atomic_session=${id}`, 'x-atomic-csrf': login.csrf };

  const phases = [];
  // Fixed phases and counts are chosen before observing failures: a final successful
  // request cannot erase intermittent failures in the recovery phase.
  for (const phase of MODES) {
    mode = phase;
    logicalCalls = 0;
    bytes = { gatewayRequest: 0, gatewayResponse: 0, delegationRequest: 0, delegationResponse: 0 };
    const timings: number[] = [];
    let failed = 0, unexpectedResponses = 0;
    const begun = performance.now();
    for (let done = 0; done < samples; done += 8) {
      await Promise.all(Array.from({ length: Math.min(8, samples - done) }, async () => {
        const start = performance.now();
        bytes.gatewayRequest += 2; // UTF-8 body '{}'; excludes headers and HTTP framing
        const response = await app.request('/api/session/delegation', { method: 'POST', headers, body: '{}' });
        const body = await response.text();
        bytes.gatewayResponse += Buffer.byteLength(body);
        timings.push(performance.now() - start);
        if (response.status !== 200) failed++;
        if (response.status !== (phase === 'provider_unavailable' ? 503 : 200)) unexpectedResponses++;
      }));
    }
    phases.push({ mode: phase, requests: timings.length, logicalCalls, failed, unexpectedResponses,
      elapsedMs: Math.round(performance.now() - begun), latency: summarize(timings), payloadBytes: { ...bytes } });
  }
  const logout = await app.request('/api/session/logout', { method: 'POST', headers, body: '{}' });
  const liveFamiliesAfterLogout = store.snapshot().families.length;
  const recovery = phases[phases.length - 1]!;
  return { scope: 'in_process_payloads_no_sockets', concurrency: 8,
    sufficientSamples: samples >= 200, phases, liveFamiliesAfterLogout,
    workloadPassed: phases.every(p => p.unexpectedResponses === 0 && p.logicalCalls === samples)
      && logout.status === 200 && liveFamiliesAfterLogout === 0,
    recoveryQualified: samples >= 200 && recovery.requests >= 200 && recovery.failed === 0 };
}
