import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import type { MiddlewareHandler } from 'hono';

/**
 * Origin, fetch-metadata, method, media-type and anti-CSRF policy for browser
 * session routes (C37).
 *
 * Topology: the browser app and this gateway are same-origin, so the policy never
 * emits `Access-Control-Allow-*` headers. A cross-origin caller cannot get a
 * preflight approved, cannot read a response and cannot send a JSON body or the
 * custom token header without one.
 */

/** Request header that carries the anti-CSRF token. Never a cookie, query or body field. */
export const CSRF_HEADER = 'X-Atomic-CSRF';
/** Session responses depend on these request headers; shared caches must not merge them. */
export const SESSION_VARY = 'Origin, Cookie';

const CSRF_DERIVATION_CONTEXT = 'atomic-notes/browser-session/csrf/v1';
const CSRF_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const JSON_MEDIA_TYPE = /^application\/json\s*(;|$)/i;

export type SessionRouteMethod = 'GET' | 'POST';

/**
 * Anti-CSRF token for the session whose raw id is [sessionId]: HMAC-SHA-256 keyed by
 * the 256-bit id. It is unpredictable without the HttpOnly cookie, changes whenever
 * the id rotates and dies with the session. Nothing about it is stored, so a store
 * leak reveals neither the token nor the id.
 */
export function csrfTokenFor(sessionId: string): string {
  return createHmac('sha256', sessionId).update(CSRF_DERIVATION_CONTEXT).digest('base64url');
}

/** Constant-time check of a presented token against [sessionId]'s current token. */
export function csrfTokenMatches(sessionId: string, presented: string | undefined): boolean {
  if (presented === undefined || !CSRF_TOKEN_PATTERN.test(presented)) return false;
  // Comparing fixed-length digests keeps the comparison constant time for any input.
  const expected = createHash('sha256').update(csrfTokenFor(sessionId), 'utf8').digest();
  const actual = createHash('sha256').update(presented, 'utf8').digest();
  return timingSafeEqual(expected, actual);
}

/**
 * Request guard for one session route that accepts exactly [method].
 *
 * - Any other method, including HEAD and OPTIONS preflight, is `405` with `Allow`
 *   and no CORS approval, before any session is read.
 * - `Sec-Fetch-Site`, when present, must be `same-origin`.
 * - `Origin` must be an exact allowlisted origin. It is required for POST and, when
 *   present, checked for GET. `null` and look-alikes never match.
 * - POST requires `Content-Type: application/json`, which an HTML form cannot send.
 *
 * The per-session anti-CSRF token is checked by the route, once the session is known.
 */
export function sessionRequestGuard(allowedOrigins: ReadonlySet<string>, method: SessionRouteMethod): MiddlewareHandler {
  return async (context, next) => {
    context.header('Vary', SESSION_VARY);

    // The raw method: Hono routes HEAD through GET handlers, but HEAD is not allowed here.
    if (context.req.method !== method) {
      context.header('Allow', method);
      return context.json({ error: 'method_not_allowed' }, 405);
    }

    const site = context.req.header('sec-fetch-site');
    if (site !== undefined && site !== 'same-origin') return context.json({ error: 'origin_rejected' }, 403);

    const origin = context.req.header('origin');
    if (origin === undefined ? method === 'POST' : !allowedOrigins.has(origin)) {
      return context.json({ error: 'origin_rejected' }, 403);
    }

    if (method === 'POST' && !JSON_MEDIA_TYPE.test(context.req.header('content-type') ?? '')) {
      return context.json({ error: 'unsupported_media_type' }, 415);
    }

    await next();
  };
}
