import { Hono } from 'hono';

export function createApp(): Hono {
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

  app.notFound((context) => context.json({ error: 'not_found' }, 404));
  app.onError((_error, context) => context.json({ error: 'internal_server_error' }, 500));

  return app;
}

export default createApp();
