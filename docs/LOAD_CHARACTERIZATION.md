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
- RSS and heap before, after and at peak.

## First local observation (not production capacity)

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
