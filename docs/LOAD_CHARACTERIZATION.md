# Gateway load and resource characterization (C48)

`npm run bench:sessions -- [samplesPerPoint]` runs
`tests/bench/session-characterization.ts`. It drives the real app through
`app.request`, using the in-memory session store and the controlled identity
fixture. It makes no network calls: no OAuth, no App Server, no deployment.

It writes `ci-gateway-session-characterization.json`, which contains numbers
and fixed codes only. A test checks that no account, assertion, token, cookie
or session-id-shaped value reaches it.

## What one sample is

One sample is a full lifecycle:

1. `POST /api/session/start`
2. `POST /api/session/login`, with the pre-login CSRF token
3. `GET /api/session`
4. `POST /api/session/logout`, with the CSRF token

Runs use concurrency 1, 8, 32 and 128.

For each step, the report gives the sample count n and the p50, p90, p99 and
max latency. It also gives:

- lifecycles per second;
- errors by step and status;
- session families still live after logout;
- RSS and heap before and after, plus their maximum samples at batch boundaries.
  These are sampled maxima, not continuous process peaks. The report includes
  `memorySampling: before_after_and_batch_boundaries`. Measurement arrays and other
  harness allocations are part of this process; no per-feature heap attribution is claimed.

The benchmark identity verifier does not retain assertion history. The separate
assertion-recording unit-test fixture is deliberately not used for memory sampling.

## Delegation delay, failure and recovery

The same command also runs four phases of `samplesPerPoint` delegation requests
each at concurrency 8: baseline, a 5 ms injected provider delay, provider 503,
and recovery. Phases and sample counts are chosen in advance. All requests in
the recovery phase count; a final success cannot erase previous failures.
At least 200 requests per phase are required for `recoveryQualified`; the smaller
unit-test smoke run remains explicitly insufficient.

The workload uses ephemeral Ed25519 keys and a controlled `fetch` response,
exercising the real signing, delegation route and capped response reader.
No key, assertion, session id or account enters the report. Logical transport
calls and UTF-8 body bytes at the gateway/delegation boundaries are separate
fields. Headers, HTTP framing, sockets and TLS are **not measured** by this
in-process workload. Expected 503 failures are recorded, and unexpected statuses
or leaked session families cause the CLI to fail.

## First local observation (not production capacity)

The table below is the historical v1 run. It predates the non-recording verifier
and delegation workload; do not reuse it as v2 memory or delegation evidence.

This was one run on a Windows development host, Node 22, with 200 lifecycles
per point.

| Concurrency | Lifecycles/s | Login p99 | Errors | Live families after logout |
| ---: | ---: | ---: | --- | ---: |
| 1 | 717 | 2.4 ms | none | 0 |
| 8 | 1,640 | 3.0 ms | none | 0 |
| 32 | 1,986 | 9.6 ms | none | 0 |
| 128 | 1,977 | 22.8 ms | none | 0 |

In this single process, throughput levels off at about 2,000 lifecycles per
second from concurrency 32 upward, while login p99 latency keeps rising. That
points to CPU-bound saturation, consistent with SHA-256 and HMAC work on every
request.

None of this measures a real store, network, TLS, Vercel cold starts or the
identity provider. It is not a capacity claim. A durable shared store, which
is required before activation, will change these numbers.

## Bounded resources (Codex follow-up)

`httpDelegationTransport` used to buffer the App Server's verify answer
without a limit. It now reads at most 4 KiB, whatever `Content-Length` says,
through the shared `readBoundedStreamUtf8` in `src/http/bounded-body.ts`. That
is the same reader the login body uses.

An answer that is larger, or that is not valid UTF-8, counts as unavailable.
A regression test confirms that reading stops after at most 8 one-KiB
chunks of an endless stream.
