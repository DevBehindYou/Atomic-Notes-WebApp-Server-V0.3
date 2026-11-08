import { Hono } from 'hono';
import { readBrowserSessionGate, type EnvironmentSource } from './browser-sessions/config.js';
import { registerBrowserSessionRoutes } from './browser-sessions/routes.js';
import type { BrowserSessionDependencies } from './browser-sessions/service.js';
import { MemorySessionStore } from './browser-sessions/store.js';
import type { DelegationSigner, DelegationTransport } from './delegation/client.js';
import { readDelegationGate } from './delegation/config.js';

export interface AppOptions {
  /** Configuration source. Defaults to an empty environment, so `createApp()` keeps every capability off. */
  readonly env?: EnvironmentSource;
  /** Browser session ports (C36). Without a verifier, login answers 503. */
  readonly browserSessions?: Partial<BrowserSessionDependencies>;
  /**
   * AppServer delegation ports (C38). Never read from the environment: without both,
   * the gated route answers 503 and no outbound call is possible.
   */
  readonly delegation?: { readonly signer?: DelegationSigner; readonly transport?: DelegationTransport };
}

export function createApp(options: AppOptions = {}): Hono {
  const app = new Hono();

  app.use('*', async (context, next) => {
    context.header('Cache-Control', 'no-store, no-cache, must-revalidate');
    context.header('X-Content-Type-Options', 'nosniff');
    await next();
  });

  app.get('/api/health', (context) => context.json({
    status: 'ok',
    service: 'atomic-notes-webapp-server',
  }));

  app.get('/api/ready', (context) => context.json({
    status: 'not_ready',
    service: 'atomic-notes-webapp-server',
    browser_session: 'unimplemented',
    appserver_delegation: 'unimplemented',
  }, 503));

  const env = options.env ?? {};
  registerBrowserSessionRoutes(app, readBrowserSessionGate(env), {
    store: options.browserSessions?.store ?? new MemorySessionStore(),
    ...(options.browserSessions?.verifier === undefined ? {} : { verifier: options.browserSessions.verifier }),
    ...(options.browserSessions?.clock === undefined ? {} : { clock: options.browserSessions.clock }),
    ...(options.browserSessions?.policy === undefined ? {} : { policy: options.browserSessions.policy }),
  }, {
    gate: readDelegationGate(env),
    ...(options.delegation?.signer === undefined ? {} : { signer: options.delegation.signer }),
    ...(options.delegation?.transport === undefined ? {} : { transport: options.delegation.transport }),
  });

  app.notFound((context) => context.json({ error: 'not_found' }, 404));
  app.onError((_error, context) => context.json({ error: 'internal_server_error' }, 500));

  return app;
}

export default createApp({ env: process.env });
