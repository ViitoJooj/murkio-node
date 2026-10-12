import { readRequest, type RequestLike } from './request';
import { MurkioServer, type AuthenticateOptions, type AuthResult, type MurkioServerOptions } from './server';
import { BROWSER_SDK, canvasTag, fieldTag, handshakePage, HANDSHAKE_GUARD, safeJson, scriptTag, type CanvasOptions, type FieldOptions, type HeadOptions } from './html';

export interface ProtectOptions extends AuthenticateOptions {
  /** Answer 401 (or redirect to signInUrl) when nobody is signed in. */
  required?: boolean;
  /** Only users with one of these roles pass; others get 403. */
  roles?: string[];
  /** Where browsers go when sign-in is required (the current path goes in ?redirect=). */
  signInUrl?: string;
  /** Refresh an expired session cookie with a tiny page before answering (default true). */
  handshake?: boolean;
}

export interface Protected {
  result: AuthResult;
  /** A response to send instead of running the route (401, 403, redirect or handshake), or null to go on. */
  response: Response | null;
}

type NextFunction = (error?: unknown) => void;
interface ExpressRequest {
  murkio?: AuthResult;
  [key: string]: unknown;
}
interface ExpressResponse {
  status(code: number): ExpressResponse;
  setHeader(name: string, value: string | string[]): unknown;
  end(body?: string): unknown;
  locals?: Record<string, unknown>;
}

function json(status: number, error: string): Response {
  return new Response(JSON.stringify({ error }), { status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' } });
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return btoa(String.fromCharCode(...bytes));
}

/**
 * Murkio for a backend. Create one per process:
 *
 *   const murkio = createMurkio(); // reads MURKIO_PUBLISHABLE_KEY
 *   app.use(murkio.express());     // req.murkio.session, .user
 *
 * and write the components into the pages you render with `head()`,
 * `canvas()`, `emailInput()`...
 */
export class Murkio extends MurkioServer {
  /** The <script> that loads the browser SDK, pinned with SRI. Put it in <head>. */
  head(options: HeadOptions = {}): string {
    return scriptTag(this.publishableKey, this.apiUrl, { scriptUrl: this.script.url, integrity: this.script.integrity, ...options });
  }

  /** The bootstrap inlined in the page, so the browser draws the canvas without fetching it. */
  async bootstrapScript(options: { nonce?: string } = {}): Promise<string> {
    const bootstrap = await this.bootstrap();
    const nonce = options.nonce ? ` nonce="${options.nonce.replace(/[^A-Za-z0-9+/=]/g, '')}"` : '';
    return `<script type="application/json" id="murkio-bootstrap" data-generated-at="${Date.now()}"${nonce}>${safeJson(bootstrap)}</script>`;
  }

  canvas(options: CanvasOptions = {}): string {
    return canvasTag(options);
  }

  emailInput(options: FieldOptions = {}): string {
    return fieldTag('murkio-identity-email-input', options);
  }

  passwordInput(options: FieldOptions = {}): string {
    return fieldTag('murkio-identity-password-input', options);
  }

  keepLogged(options: FieldOptions = {}): string {
    return fieldTag('murkio-identity-keep-logged', options);
  }

  loginButton(text: string, options: FieldOptions = {}): string {
    return fieldTag('murkio-identity-login-button', options, text);
  }

  registerButton(text: string, options: FieldOptions = {}): string {
    return fieldTag('murkio-identity-register-button', options, text);
  }

  errorMessage(options: FieldOptions = {}): string {
    return fieldTag('murkio-identity-error', options);
  }

  /**
   * Authenticates a request and decides what to answer for Fetch-style
   * frameworks (Hono, Next middleware, SvelteKit hooks, Bun): `response` is
   * the 401/403/redirect/handshake to send, or null to run the route.
   */
  async protect(request: RequestLike, options: ProtectOptions = {}): Promise<Protected> {
    const result = await this.authenticate(request, options);
    const info = readRequest(request);

    if (result.session) {
      if (options.roles && !options.roles.some((role) => result.session?.roles.includes(role))) return { result, response: json(403, 'forbidden') };
      return { result, response: null };
    }

    const navigation = info.method === 'GET' && (info.header('sec-fetch-mode') === 'navigate' || (info.header('accept') ?? '').includes('text/html'));
    if (options.handshake !== false && navigation && result.signedInHint && (result.reason === 'missing' || result.reason === 'expired') && info.cookie(HANDSHAKE_GUARD) === null) {
      const nonce = randomNonce();
      const secure = info.url.protocol === 'https:' ? '; Secure' : '';
      const scriptOrigin = new URL(this.script.url ?? BROWSER_SDK.url, info.url).origin;
      return {
        result,
        response: new Response(handshakePage(this.publishableKey, this.apiUrl, nonce, { scriptUrl: this.script.url, integrity: this.script.integrity }), {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}' ${scriptOrigin}; connect-src ${new URL(this.apiUrl).origin}; base-uri 'none'; frame-ancestors 'none'`,
            'Set-Cookie': `${HANDSHAKE_GUARD}=1; Path=/; Max-Age=30; HttpOnly; SameSite=Lax${secure}`,
          },
        }),
      };
    }

    if (!options.required) return { result, response: null };
    if (navigation && options.signInUrl) {
      const target = new URL(options.signInUrl, info.url);
      target.searchParams.set('redirect', info.url.pathname + info.url.search);
      return { result, response: new Response(null, { status: 302, headers: { Location: target.toString(), 'Cache-Control': 'no-store' } }) };
    }
    return { result, response: json(401, 'unauthorized') };
  }

  /** Express/Connect middleware: sets `req.murkio` (and `res.locals.murkio`) and answers 401/403/redirect/handshake per the options. */
  express(options: ProtectOptions = {}) {
    return (req: ExpressRequest, res: ExpressResponse, next: NextFunction) => {
      this.protect(req as never, options).then(async ({ result, response }) => {
        req.murkio = result;
        if (res.locals) res.locals.murkio = result;
        if (!response) return next();
        res.status(response.status);
        response.headers.forEach((value, name) => {
          res.setHeader(name, value);
        });
        res.end(await response.text());
      }, next);
    };
  }
}

export function createMurkio(options: MurkioServerOptions = {}): Murkio {
  return new Murkio(options);
}

export { MurkioServer, DEFAULT_API_URL } from './server';
export type { AuthenticateOptions, AuthResult, MurkioServerOptions, Reason, Session } from './server';
export { BROWSER_SDK, escapeAttribute, safeJson } from './html';
export type { CanvasOptions, FieldOptions, HeadOptions } from './html';
export { acceptedCookieNames, fnv1a32 } from './keys';
export type { RequestLike } from './request';
export type { ClientBootstrap, Me, PublicConfig } from './types';
