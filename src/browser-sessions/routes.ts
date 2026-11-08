import type { Context, Hono } from 'hono';
import type { BrowserSessionGate } from './config.js';
import {
  BrowserSessionService,
  CLEAR_SESSION_COOKIE,
  readSessionCookie,
  sessionCookie,
  type BrowserSessionDependencies,
  type Resolution,
} from './service.js';

const MAX_LOGIN_BODY_BYTES = 8192;
const MAX_ASSERTION_LENGTH = 4096;
const SESSION_PATHS = ['/api/session', '/api/session/start', '/api/session/login', '/api/session/logout', '/api/session/accounts/:accountId'];

type OriginCheck = { ok: true; origin: string | undefined } | { ok: false };

/**
 * Registers browser session routes. Disabled: nothing is registered, so every path
 * keeps today's 404. Misconfigured: fixed 503. Enabled: the session lifecycle.
 */
export function registerBrowserSessionRoutes(
  app: Hono,
  gate: BrowserSessionGate,
  dependencies: BrowserSessionDependencies,
): void {
  if (gate.state === 'disabled') return;
  if (gate.state === 'misconfigured') {
    for (const path of SESSION_PATHS) {
      app.on(['GET', 'POST'], path, (context) => context.json({ error: 'browser_sessions_unavailable' }, 503));
    }
    return;
  }

  const service = new BrowserSessionService(dependencies);
  const allowedOrigins = gate.allowedOrigins;

  /**
   * Minimal origin policy needed by C36. Full CSRF middleware is C37.
   * Unsafe methods require an allowlisted Origin; any presented Origin must be
   * allowlisted; cross-site fetch metadata is rejected.
   */
  const checkOrigin = (context: Context, requireOrigin: boolean): OriginCheck => {
    if (context.req.header('sec-fetch-site') === 'cross-site') return { ok: false };
    const origin = context.req.header('origin');
    if (origin === undefined) return requireOrigin ? { ok: false } : { ok: true, origin: undefined };
    return allowedOrigins.has(origin) ? { ok: true, origin } : { ok: false };
  };

  const presented = (context: Context) => readSessionCookie(context.req.header('cookie'));

  const finish = (context: Context, resolution: Resolution, invalidCookie: boolean): void => {
    if (resolution.kind === 'active' && resolution.issuedId !== undefined) {
      context.header('Set-Cookie', sessionCookie(resolution.issuedId, maxAgeSeconds(resolution.session.absoluteExpiresAt, service.now())));
    } else if ((resolution.kind === 'none' && resolution.clearCookie) || invalidCookie) {
      context.header('Set-Cookie', CLEAR_SESSION_COOKIE);
    }
  };

  const rejectOrigin = (context: Context) => context.json({ error: 'origin_rejected' }, 403);

  app.get('/api/session', async (context) => {
    const origin = checkOrigin(context, false);
    if (!origin.ok) return rejectOrigin(context);
    const cookie = presented(context);
    const resolution = await service.resolve(cookie.value, origin.origin, { rotate: true });
    if (resolution.kind === 'origin_mismatch') return rejectOrigin(context);
    finish(context, resolution, cookie.invalid);
    return context.json(resolution.kind === 'active' ? service.status(resolution.session) : { signedIn: false });
  });

  app.get('/api/session/accounts/:accountId', async (context) => {
    const origin = checkOrigin(context, false);
    if (!origin.ok) return rejectOrigin(context);
    const cookie = presented(context);
    const resolution = await service.resolve(cookie.value, origin.origin, { rotate: true });
    if (resolution.kind === 'origin_mismatch') return rejectOrigin(context);
    finish(context, resolution, cookie.invalid);
    if (resolution.kind !== 'active' || resolution.session.accountId === null) {
      return context.json({ error: 'session_required' }, 401);
    }
    if (resolution.session.accountId !== context.req.param('accountId')) {
      return context.json({ error: 'account_mismatch' }, 403);
    }
    return context.json(service.status(resolution.session));
  });

  app.post('/api/session/start', async (context) => {
    const origin = checkOrigin(context, true);
    if (!origin.ok || origin.origin === undefined) return rejectOrigin(context);
    await service.revokePresented(presented(context).value);
    const issued = await service.issue(origin.origin, null);
    context.header('Set-Cookie', sessionCookie(issued.id, maxAgeSeconds(issued.session.absoluteExpiresAt, service.now())));
    return context.json({ signedIn: false });
  });

  app.post('/api/session/login', async (context) => {
    const origin = checkOrigin(context, true);
    if (!origin.ok || origin.origin === undefined) return rejectOrigin(context);
    if (!service.identityAvailable) return context.json({ error: 'identity_unavailable' }, 503);

    const assertion = await readAssertion(context);
    if (assertion === undefined) return context.json({ error: 'invalid_request' }, 400);
    const account = await service.verifyIdentity(assertion, origin.origin);
    if (account === null) return context.json({ error: 'identity_rejected' }, 401);

    // Fixation defence: whatever id was presented (pre-auth, another account, unknown)
    // is revoked and never upgraded; the authenticated session always gets a fresh id.
    await service.revokePresented(presented(context).value);
    const issued = await service.issue(origin.origin, account);
    context.header('Set-Cookie', sessionCookie(issued.id, maxAgeSeconds(issued.session.absoluteExpiresAt, service.now())));
    return context.json(service.status(issued.session));
  });

  app.post('/api/session/logout', async (context) => {
    const origin = checkOrigin(context, true);
    if (!origin.ok || origin.origin === undefined) return rejectOrigin(context);
    const cookie = presented(context);
    const resolution = await service.resolve(cookie.value, origin.origin, { rotate: false });
    if (resolution.kind === 'origin_mismatch') return rejectOrigin(context);
    if (resolution.kind === 'active') await service.revokeFamily(resolution.session.familyId);
    context.header('Set-Cookie', CLEAR_SESSION_COOKIE);
    return context.json({ signedIn: false });
  });
}

function maxAgeSeconds(expiresAt: number, now: number): number {
  return Math.floor((expiresAt - now) / 1000);
}

async function readAssertion(context: Context): Promise<string | undefined> {
  const contentType = context.req.header('content-type') ?? '';
  if (!/^application\/json(\s*;|$)/i.test(contentType)) return undefined;
  const declaredLength = Number(context.req.header('content-length') ?? '0');
  if (Number.isFinite(declaredLength) && declaredLength > MAX_LOGIN_BODY_BYTES) return undefined;
  // The declared length may be missing or false, so the cap is enforced on the
  // bytes actually read, and the body is never buffered past it.
  const text = await readBoundedUtf8(context.req.raw, MAX_LOGIN_BODY_BYTES);
  if (text === undefined) return undefined;
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return undefined;
  }
  if (typeof body !== 'object' || body === null) return undefined;
  const assertion = (body as Record<string, unknown>)['assertion'];
  if (typeof assertion !== 'string' || assertion.length === 0 || assertion.length > MAX_ASSERTION_LENGTH) return undefined;
  return assertion;
}

/**
 * Reads at most [maxBytes] of [request]'s body as strict UTF-8. Returns
 * undefined, after cancelling the stream, when the body is larger or is not
 * valid UTF-8. Nothing beyond the cap is read or held.
 */
export async function readBoundedUtf8(request: Request, maxBytes: number): Promise<string | undefined> {
  const stream = request.body;
  if (stream === null) return '';
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        return undefined;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return undefined;
  }
}
