import type { ClientBootstrap, Me } from '@murkio/html';
import type { JWTPayload } from 'jose';
import { JWTExpired } from 'jose/errors';
import { createRemoteJWKSet, customFetch } from 'jose/jwks/remote';
import { jwtVerify } from 'jose/jwt/verify';
import { acceptedCookieNames, fnv1a32 } from './keys';
import { readRequest, type RequestInfo, type RequestLike } from './request';

export const DEFAULT_API_URL = 'https://api.mukio.com';

export interface MurkioServerOptions {
  /** The application's publishable key. Defaults to MURKIO_PUBLISHABLE_KEY. */
  publishableKey?: string;
  /** Base URL of the identity API. Defaults to MURKIO_API_URL, then the hosted API. */
  apiUrl?: string;
  /** The cookie domain set in the browser SDK, when the session cookie is shared with subdomains. */
  cookieDomain?: string;
  /** Self-hosted browser SDK (`murkio.js` of the same version) for head() and the handshake page. Defaults to MURKIO_SCRIPT_URL, then the CDN. */
  scriptUrl?: string;
  /** SRI hash of `scriptUrl`. Defaults to MURKIO_SCRIPT_INTEGRITY. */
  integrity?: string;
  fetch?: typeof fetch;
}

export interface Session {
  userId: string;
  sessionId: string;
  applicationId: string;
  roles: string[];
  /** The verified access token claims. */
  claims: JWTPayload & { sid: string; aid: string; roles: string[] };
  token: string;
}

export type Reason = 'missing' | 'invalid' | 'expired' | 'revoked' | 'csrf';

export interface AuthResult {
  session: Session | null;
  user: Me | null;
  /** Why there is no session (null when there is one). */
  reason: Reason | null;
  /** The browser holds a session (its signed-in cookie is set), even if this request's token is missing or expired. */
  signedInHint: boolean;
}

export interface AuthenticateOptions {
  /** Also load the profile (POST /v1/me, cached a minute per session). */
  loadUser?: boolean;
  /** Ask the API whether the session was revoked (cached 30 s). Local verification alone accepts a revoked token until it expires (15 min). */
  checkRevocation?: boolean;
}

const BOOTSTRAP_TTL_MS = 60_000;
const USER_TTL_MS = 60_000;
const REVOCATION_TTL_MS = 30_000;
const CACHE_LIMIT = 10_000;
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function env(name: string): string | undefined {
  return typeof process !== 'undefined' ? process.env?.[name] : undefined;
}

class TtlCache<T> {
  private readonly entries = new Map<string, { at: number; value: Promise<T> }>();
  constructor(private readonly ttl: number) {}

  get(key: string, load: () => Promise<T>): Promise<T> {
    const hit = this.entries.get(key);
    if (hit && Date.now() - hit.at < this.ttl) return hit.value;
    if (this.entries.size >= CACHE_LIMIT) this.entries.delete(this.entries.keys().next().value as string);
    const value = load();
    this.entries.set(key, { at: Date.now(), value });
    value.catch(() => this.entries.delete(key));
    return value;
  }
}

/**
 * MurkioServer checks who is behind a request, for the backend of an
 * application. It only needs the publishable key: GET /v1/client gives the
 * application id, the issuer and the JWKS, and the access tokens are verified
 * locally (EdDSA, issuer, audience, expiry), so a page render costs no call to
 * the API. It never signs anyone in: the browser does that against the API,
 * because the API rate-limits by the user's IP, and a backend calling for all
 * of its users would look like one very busy IP.
 */
export class MurkioServer {
  readonly publishableKey: string;
  readonly apiUrl: string;
  readonly keyHash: string;
  private readonly cookieDomain: string | undefined;
  protected readonly script: { url?: string; integrity?: string };
  private readonly fetcher: typeof fetch;
  private bootstrapping: { at: number; value: Promise<ClientBootstrap> } | null = null;
  private jwks: { url: string; set: ReturnType<typeof createRemoteJWKSet> } | null = null;
  private readonly users = new TtlCache<Me>(USER_TTL_MS);
  private readonly revocations = new TtlCache<boolean>(REVOCATION_TTL_MS);

  constructor(options: MurkioServerOptions = {}) {
    const key = options.publishableKey ?? env('MURKIO_PUBLISHABLE_KEY');
    if (!key?.startsWith('pk_')) {
      throw new Error('[murkio] set publishableKey (or MURKIO_PUBLISHABLE_KEY) to the application publishable key (pk_...).');
    }
    this.publishableKey = key;
    this.apiUrl = (options.apiUrl ?? env('MURKIO_API_URL') ?? DEFAULT_API_URL).replace(/\/+$/, '');
    this.keyHash = fnv1a32(key);
    this.cookieDomain = options.cookieDomain;
    this.script = { url: options.scriptUrl ?? env('MURKIO_SCRIPT_URL'), integrity: options.integrity ?? env('MURKIO_SCRIPT_INTEGRITY') };
    this.fetcher = options.fetch ?? ((input, init) => fetch(input, init));
  }

  private async call<T>(method: string, path: string, body?: unknown): Promise<T> {
    const response = await this.fetcher(this.apiUrl + path, {
      method,
      headers: { Authorization: `Bearer ${this.publishableKey}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const json = (await response.json().catch(() => null)) as { data?: T; details?: { code: string }[] } | null;
    if (!response.ok || json?.data === undefined) {
      const code = json?.details?.[0]?.code ?? `http-${response.status}`;
      throw Object.assign(new Error(`[murkio] ${method} ${path} failed: ${code}`), { code, status: response.status });
    }
    return json.data;
  }

  /** The application, its public config and published canvas (cached a minute). */
  bootstrap(): Promise<ClientBootstrap> {
    if (!this.bootstrapping || Date.now() - this.bootstrapping.at > BOOTSTRAP_TTL_MS) {
      const value = this.call<ClientBootstrap>('GET', '/v1/client');
      this.bootstrapping = { at: Date.now(), value };
      value.catch(() => {
        this.bootstrapping = null;
      });
    }
    return this.bootstrapping.value;
  }

  private async keySet(bootstrap: ClientBootstrap) {
    const url = new URL(bootstrap.jwks_url, `${this.apiUrl}/`).toString();
    if (this.jwks?.url !== url) {
      this.jwks = { url, set: createRemoteJWKSet(new URL(url), { [customFetch]: this.fetcher, cacheMaxAge: 10 * 60_000 }) };
    }
    return this.jwks.set;
  }

  /** Verifies an access token locally. Throws jose errors (JWTExpired, signature...) on a bad token. */
  async verifyToken(token: string): Promise<Session> {
    const bootstrap = await this.bootstrap();
    const { payload } = await jwtVerify(token, await this.keySet(bootstrap), {
      algorithms: ['EdDSA'],
      issuer: bootstrap.issuer,
      audience: bootstrap.application_id,
      requiredClaims: ['sub', 'sid', 'exp'],
    });
    const claims = payload as Session['claims'];
    return {
      userId: String(claims.sub),
      sessionId: String(claims.sid),
      applicationId: String(claims.aid ?? bootstrap.application_id),
      roles: Array.isArray(claims.roles) ? claims.roles.map(String) : [],
      claims,
      token,
    };
  }

  /** The profile of the session's user (POST /v1/me), cached a minute per session. */
  getUser(session: Session): Promise<Me> {
    return this.users.get(session.sessionId, () => this.call<Me>('POST', '/v1/me', { access_token: session.token }));
  }

  /** False when the API says the session was revoked (logout, ban, password change). Cached 30 s. */
  isActive(session: Session): Promise<boolean> {
    return this.revocations.get(String(session.claims.jti ?? session.token), async () => {
      const result = await this.call<{ active: boolean }>('POST', '/v1/sessions/verify', { access_token: session.token });
      return result.active;
    });
  }

  /**
   * Finds and verifies the session of a request: the `Authorization: Bearer`
   * access token (APIs called with `murkio.fetch`/`getToken`), or the session
   * cookie the browser SDK writes (page navigations).
   *
   * The cookie goes with every request to the site, including ones another
   * site makes the browser send. So it only counts for safe methods (GET,
   * HEAD, OPTIONS) or when the browser says the request comes from this same
   * origin; anything that changes state must send the token in the header.
   */
  async authenticate(request: RequestLike, options: AuthenticateOptions = {}): Promise<AuthResult> {
    const info = readRequest(request);
    const names = acceptedCookieNames(this.keyHash, info.url.host, this.cookieDomain);
    const signedInHint = names.some((name) => info.cookie(name.uat) === '1');
    const none = (reason: Reason): AuthResult => ({ session: null, user: null, reason, signedInHint });

    let token: string | null = null;
    const authorization = info.header('authorization');
    if (authorization?.startsWith('Bearer ')) {
      const value = authorization.slice(7).trim();
      if (!value.startsWith('pk_') && !value.startsWith('sk_')) token = value;
    }
    if (!token) {
      const cookie = names.map((name) => info.cookie(name.session)).find((value) => value);
      if (!cookie) return none('missing');
      if (!SAFE_METHODS.has(info.method) && !sameOrigin(info)) return none('csrf');
      token = cookie;
    }

    let session: Session;
    try {
      session = await this.verifyToken(token);
    } catch (error) {
      return none(error instanceof JWTExpired ? 'expired' : 'invalid');
    }

    if (options.checkRevocation && !(await this.isActive(session))) return none('revoked');
    const user = options.loadUser ? await this.getUser(session) : null;
    return { session, user, reason: null, signedInHint };
  }
}

function sameOrigin(info: RequestInfo): boolean {
  const site = info.header('sec-fetch-site');
  if (site) return site === 'same-origin';
  const origin = info.header('origin');
  return origin !== null && origin === info.url.origin;
}
