import type { Context, Hono } from 'hono';
import type { BrowserSessionGate } from './config.js';
import { CSRF_HEADER, csrfTokenFor, csrfTokenMatches, sessionRequestGuard, type SessionRouteMethod } from './csrf.js';
import {
  BrowserSessionService,
  CLEAR_SESSION_COOKIE,
  readSessionCookie,
  sessionCookie,
  type BrowserSessionDependencies,
  type Resolution,
} from './service.js';
import type { SessionRecord } from './store.js';

const MAX_LOGIN_BODY_BYTES = 8192;
const MAX_ASSERTION_LENGTH = 4096;
const SESSION_ROUTES: Readonly<Record<string, SessionRouteMethod>> = {
  '/api/session': 'GET',
  '/api/session/accounts/:accountId': 'GET',
  '/api/session/start': 'POST',
  '/api/session/login': 'POST',
  '/api/session/logout': 'POST',
};

type PresentedSession =
  | { readonly rejection: Response }
  | { readonly rejection?: undefined; readonly resolution: Exclude<Resolution, { kind: 'origin_mismatch' }> };

/**
 * Registers browser session routes. Disabled: nothing is registered, so every path
 * keeps today's 404. Misconfigured: fixed 503. Enabled: the session lifecycle behind
 * the C37 request guard (`csrf.ts`).
 */
export function registerBrowserSessionRoutes(
  app: Hono,
  gate: BrowserSessionGate,
  dependencies: BrowserSessionDependencies,
): void {
  if (gate.state === 'disabled') return;
  if (gate.state === 'misconfigured') {
    for (const path of Object.keys(SESSION_ROUTES)) {
      app.on(['GET', 'POST'], path, (context) => context.json({ error: 'browser_sessions_unavailable' }, 503));
    }
    return;
  }

  const service = new BrowserSessionService(dependencies);
  // Method, fetch metadata, Origin and media type are enforced before any handler runs.
  for (const [path, method] of Object.entries(SESSION_ROUTES)) {
    app.use(path, sessionRequestGuard(gate.allowedOrigins, method));
  }

  /** The guard has already rejected any Origin outside the allowlist. */
  const requestOrigin = (context: Context): string | undefined => context.req.header('origin');
  const presented = (context: Context) => readSessionCookie(context.req.header('cookie'));

  const finish = (context: Context, resolution: Resolution, invalidCookie: boolean): void => {
    if (resolution.kind === 'active' && resolution.issuedId !== undefined) {
      issueCookie(context, resolution.issuedId, resolution.session);
    } else if ((resolution.kind === 'none' && resolution.clearCookie) || invalidCookie) {
      context.header('Set-Cookie', CLEAR_SESSION_COOKIE);
    }
  };

  const issueCookie = (context: Context, id: string, session: SessionRecord): void => {
    context.header('Set-Cookie', sessionCookie(id, maxAgeSeconds(session.absoluteExpiresAt, service.now())));
  };

  const rejectOrigin = (context: Context) => context.json({ error: 'origin_rejected' }, 403);

  /** Status plus the current anti-CSRF token. Only same-origin callers can read it. */
  const statusBody = (session: SessionRecord, sessionId: string) => ({ ...service.status(session), csrf: csrfTokenFor(sessionId) });

  /**
   * Unsafe routes: resolves the presented session without touching it. When it is a
   * live session the request acts on it, so it must carry that session's token. A
   * rejected request leaves the session exactly as it was. An id the server does not
   * recognise is not a session and is never adopted, so it needs no token.
   */
  const presentedForUnsafe = async (context: Context, origin: string): Promise<PresentedSession> => {
    const cookie = presented(context);
    const resolution = await service.resolve(cookie.value, origin, { rotate: false, touch: false });
    if (resolution.kind === 'origin_mismatch') return { rejection: rejectOrigin(context) };
    if (resolution.kind === 'active' && !csrfTokenMatches(cookie.value as string, context.req.header(CSRF_HEADER))) {
      return { rejection: context.json({ error: 'csrf_rejected' }, 403) };
    }
    return { resolution };
  };

  app.get('/api/session', async (context) => {
    const cookie = presented(context);
    const resolution = await service.resolve(cookie.value, requestOrigin(context), { rotate: true });
    if (resolution.kind === 'origin_mismatch') return rejectOrigin(context);
    finish(context, resolution, cookie.invalid);
    if (resolution.kind !== 'active') return context.json({ signedIn: false });
    return context.json(statusBody(resolution.session, resolution.issuedId ?? (cookie.value as string)));
  });

  app.get('/api/session/accounts/:accountId', async (context) => {
    const cookie = presented(context);
    const resolution = await service.resolve(cookie.value, requestOrigin(context), { rotate: true });
    if (resolution.kind === 'origin_mismatch') return rejectOrigin(context);
    finish(context, resolution, cookie.invalid);
    if (resolution.kind !== 'active' || resolution.session.accountId === null) {
      return context.json({ error: 'session_required' }, 401);
    }
    if (resolution.session.accountId !== context.req.param('accountId')) {
      return context.json({ error: 'account_mismatch' }, 403);
    }
    return context.json(statusBody(resolution.session, resolution.issuedId ?? (cookie.value as string)));
  });

  app.post('/api/session/start', async (context) => {
    const origin = requestOrigin(context) as string;
    const current = await presentedForUnsafe(context, origin);
    if (current.rejection !== undefined) return current.rejection;
    if (current.resolution.kind === 'active') await service.revokeFamily(current.resolution.session.familyId);
    const issued = await service.issue(origin, null);
    issueCookie(context, issued.id, issued.session);
    return context.json({ signedIn: false, csrf: csrfTokenFor(issued.id) });
  });

  app.post('/api/session/login', async (context) => {
    const origin = requestOrigin(context) as string;
    if (!service.identityAvailable) return context.json({ error: 'identity_unavailable' }, 503);
    // The token is checked before the body is read, so a forged request never
    // reaches the verifier or consumes a single-use assertion.
    const current = await presentedForUnsafe(context, origin);
    if (current.rejection !== undefined) return current.rejection;

    const assertion = await readAssertion(context);
    if (assertion === undefined) return context.json({ error: 'invalid_request' }, 400);
    const account = await service.verifyIdentity(assertion, origin);
    if (account === null) return context.json({ error: 'identity_rejected' }, 401);

    // Fixation defence: whatever session was presented (pre-auth, another account or the
    // same account) is revoked and never upgraded. The new session always gets a fresh
    // id, and with it a fresh token.
    if (current.resolution.kind === 'active') await service.revokeFamily(current.resolution.session.familyId);
    const issued = await service.issue(origin, account);
    issueCookie(context, issued.id, issued.session);
    return context.json(statusBody(issued.session, issued.id));
  });

  app.post('/api/session/logout', async (context) => {
    const current = await presentedForUnsafe(context, requestOrigin(context) as string);
    if (current.rejection !== undefined) return current.rejection;
    if (current.resolution.kind === 'active') await service.revokeFamily(current.resolution.session.familyId);
    context.header('Set-Cookie', CLEAR_SESSION_COOKIE);
    return context.json({ signedIn: false });
  });
}

function maxAgeSeconds(expiresAt: number, now: number): number {
  return Math.floor((expiresAt - now) / 1000);
}

async function readAssertion(context: Context): Promise<string | undefined> {
  // Defence in depth: the request guard has already required this media type.
  if (!/^application\/json\s*(;|$)/i.test(context.req.header('content-type') ?? '')) return undefined;
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
