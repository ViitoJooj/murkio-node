import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { acceptedCookieNames, BROWSER_SDK, createMurkio, fnv1a32, safeJson } from '../src';

const PK = 'pk_node_test';
const HASH = fnv1a32(PK);
let privateKey: CryptoKey;
let jwk: Record<string, unknown>;
let calls: string[] = [];

const bootstrap = {
  application_id: 'app-1',
  issuer: 'enterprise-auth',
  jwks_url: '/v1/applications/app-1/jwks.json',
  config: { methods: { password: true }, mfa: { mode: 'off' }, oauth_providers: [], signup: { login_on_verify: true } },
  canvas: { version: 0, document: { schema: 1, title: '</script><script>alert(1)</script>' } },
};

const fakeFetch = (async (input: RequestInfo | URL, init: RequestInit = {}) => {
  const url = new URL(String(input));
  const route = `${init.method ?? 'GET'} ${url.pathname}`;
  calls.push(route);
  const reply = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
  switch (route) {
    case 'GET /v1/client':
      return reply({ data: bootstrap });
    case 'GET /v1/applications/app-1/jwks.json':
      return reply({ keys: [jwk] });
    case 'POST /v1/me':
      return reply({ data: { id: 'user-1', email: 'ana@example.com', email_verified: true, roles: ['user'], mfa_enabled: false } });
    case 'POST /v1/sessions/verify': {
      const token = JSON.parse(String(init.body)).access_token as string;
      const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString()) as { jti?: string };
      return reply({ data: { active: payload.jti !== 'revoked' } });
    }
  }
  return reply({ error: 'not found' }, 404);
}) as typeof fetch;

async function token(claims: Record<string, unknown> = {}, options: { expiresIn?: string | number; audience?: string } = {}) {
  const { jti, ...rest } = claims;
  return new SignJWT({ sid: 'session-1', aid: 'app-1', roles: ['user'], ...rest })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'key-1' })
    .setSubject('user-1')
    .setIssuer('enterprise-auth')
    .setAudience(options.audience ?? 'app-1')
    .setIssuedAt()
    .setJti(typeof jti === 'string' ? jti : String(Math.random()))
    .setExpirationTime(options.expiresIn ?? '15m')
    .sign(privateKey);
}

const murkio = () => createMurkio({ publishableKey: PK, apiUrl: 'https://api.example.com', fetch: fakeFetch });

function request(url: string, headers: Record<string, string> = {}, method = 'GET') {
  return new Request(url, { method, headers });
}

beforeAll(async () => {
  const pair = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
  privateKey = pair.privateKey as CryptoKey;
  jwk = { ...(await exportJWK(pair.publicKey)), kid: 'key-1', alg: 'EdDSA', use: 'sig' };
});

describe('keys', () => {
  it('hashes like the browser SDK', () => {
    expect(fnv1a32('')).toBe('811c9dc5');
    expect(fnv1a32('foobar')).toBe('bf9cf968');
  });

  it('accepts the unprefixed cookie only on localhost and __Secure- only with a cookie domain', () => {
    expect(acceptedCookieNames('h', 'app.example.com').map((n) => n.session)).toEqual(['__Host-murkio_session_h']);
    expect(acceptedCookieNames('h', 'app.example.com', '.example.com').map((n) => n.session)).toEqual(['__Host-murkio_session_h', '__Secure-murkio_session_h']);
    expect(acceptedCookieNames('h', 'localhost:3000').map((n) => n.session)).toContain('murkio_session_h');
  });
});

describe('authenticate', () => {
  it('verifies the bearer token of an API call', async () => {
    const result = await murkio().authenticate(request('https://app.example.com/api', { Authorization: `Bearer ${await token({ roles: ['admin'] })}` }));
    expect(result.reason).toBeNull();
    expect(result.session).toMatchObject({ userId: 'user-1', sessionId: 'session-1', applicationId: 'app-1', roles: ['admin'] });
  });

  it('refuses tokens of another application, expired tokens and API keys', async () => {
    const m = murkio();
    const other = await m.authenticate(request('https://app.example.com/', { Authorization: `Bearer ${await token({}, { audience: 'app-2' })}` }));
    const expired = await m.authenticate(request('https://app.example.com/', { Authorization: `Bearer ${await token({}, { expiresIn: Math.floor(Date.now() / 1000) - 10 })}` }));
    const key = await m.authenticate(request('https://app.example.com/', { Authorization: `Bearer ${PK}` }));
    expect([other.reason, expired.reason, key.reason]).toEqual(['invalid', 'expired', 'missing']);
  });

  it('reads the session cookie on navigations and refuses it on cross-site writes', async () => {
    const m = murkio();
    const cookie = `__Host-murkio_session_${HASH}=${await token()}; __Host-murkio_uat_${HASH}=1`;
    expect((await m.authenticate(request('https://app.example.com/dashboard', { cookie }))).session?.userId).toBe('user-1');
    expect((await m.authenticate(request('https://app.example.com/api', { cookie, 'sec-fetch-site': 'cross-site' }, 'POST'))).reason).toBe('csrf');
    expect((await m.authenticate(request('https://app.example.com/api', { cookie, 'sec-fetch-site': 'same-origin' }, 'POST'))).session).not.toBeNull();
    expect((await m.authenticate(request('https://app.example.com/api', { cookie, origin: 'https://app.example.com' }, 'POST'))).session).not.toBeNull();
  });

  it('ignores the unprefixed cookie on a real host', async () => {
    const cookie = `murkio_session_${HASH}=${await token()}`;
    expect((await murkio().authenticate(request('https://app.example.com/', { cookie }))).reason).toBe('missing');
    expect((await murkio().authenticate(request('http://localhost:3000/', { cookie }))).session).not.toBeNull();
  });

  it('loads the user and checks revocation with short caches', async () => {
    const m = murkio();
    calls = [];
    const header = { Authorization: `Bearer ${await token()}` };
    await m.authenticate(request('https://app.example.com/', header), { loadUser: true, checkRevocation: true });
    const result = await m.authenticate(request('https://app.example.com/', header), { loadUser: true, checkRevocation: true });
    expect(result.user?.email).toBe('ana@example.com');
    expect(calls.filter((c) => c === 'POST /v1/me')).toHaveLength(1);
    expect(calls.filter((c) => c === 'POST /v1/sessions/verify')).toHaveLength(1);

    const revoked = await m.authenticate(request('https://app.example.com/', { Authorization: `Bearer ${await token({ jti: 'revoked' })}` }), { checkRevocation: true });
    expect(revoked.reason).toBe('revoked');
    expect(revoked.session).toBeNull();
  });
});

describe('protect', () => {
  const navigation = { accept: 'text/html', 'sec-fetch-mode': 'navigate' };

  it('answers 401 for APIs and redirects browsers to the sign-in page', async () => {
    const api = await murkio().protect(request('https://app.example.com/api/orders'), { required: true });
    expect(api.response?.status).toBe(401);

    const page = await murkio().protect(request('https://app.example.com/dashboard?tab=1', navigation), { required: true, signInUrl: '/login' });
    expect(page.response?.status).toBe(302);
    expect(page.response?.headers.get('Location')).toBe('https://app.example.com/login?redirect=%2Fdashboard%3Ftab%3D1');
  });

  it('serves the handshake page when the browser holds a session but the cookie expired', async () => {
    const cookie = `__Host-murkio_uat_${HASH}=1`;
    const { response } = await murkio().protect(request('https://app.example.com/dashboard', { ...navigation, cookie }), { required: true });
    expect(response?.status).toBe(200);
    const csp = response?.headers.get('Content-Security-Policy') ?? '';
    const nonce = csp.match(/'nonce-([^']+)'/)?.[1];
    const html = await response!.text();
    expect(nonce).toBeTruthy();
    expect(html).toContain(`nonce="${nonce}"`);
    expect(html).toContain(`data-murkio-key="${PK}"`);
    expect(response?.headers.get('Set-Cookie')).toContain('murkio_handshake=1');

    const looped = await murkio().protect(request('https://app.example.com/dashboard', { ...navigation, cookie: `${cookie}; murkio_handshake=1` }), { required: true });
    expect(looped.response?.status).toBe(401);
  });

  it('checks roles', async () => {
    const header = { Authorization: `Bearer ${await token()}` };
    expect((await murkio().protect(request('https://app.example.com/admin', header), { roles: ['admin'] })).response?.status).toBe(403);
    expect((await murkio().protect(request('https://app.example.com/admin', header), { roles: ['user'] })).response).toBeNull();
  });

  it('works as express middleware', async () => {
    const m = murkio();
    const middleware = m.express({ required: true });
    const req = { method: 'GET', url: '/api', headers: { host: 'app.example.com', authorization: `Bearer ${await token()}` } } as Record<string, unknown>;
    await new Promise<void>((resolve, reject) => middleware(req as never, { status: () => reject(new Error('unexpected')), setHeader: () => undefined, end: () => undefined, locals: {} } as never, () => resolve()));
    expect((req.murkio as { session: { userId: string } }).session.userId).toBe('user-1');

    const denied: { status?: number; body?: string } = {};
    const res = { status(code: number) { denied.status = code; return res; }, setHeader: () => undefined, end(body: string) { denied.body = body; }, locals: {} };
    await new Promise<void>((resolve) => {
      res.end = (body: string) => { denied.body = body; resolve(); };
      middleware({ method: 'GET', url: '/api', headers: { host: 'app.example.com' } } as never, res as never, () => resolve());
    });
    expect(denied.status).toBe(401);
  });
});

describe('html helpers', () => {
  it('pins the browser SDK and escapes attributes and inline JSON', async () => {
    const m = murkio();
    expect(m.head({ afterLogin: '/home' })).toBe(
      `<script src="${BROWSER_SDK.url}" integrity="${BROWSER_SDK.integrity}" crossorigin="anonymous" data-murkio-key="${PK}" data-murkio-api="https://api.example.com" data-murkio-after-login="/home"></script>`,
    );
    expect(BROWSER_SDK.integrity).toMatch(/^sha384-/);
    expect(m.canvas({ className: '" onload="x', screen: 'sign_up' })).toBe('<murkio-identity-canvas screen="sign_up" class="&quot; onload=&quot;x"></murkio-identity-canvas>');
    expect(m.emailInput({ className: 'input', placeholder: 'you@example.com' })).toBe('<murkio-identity-email-input class="input" placeholder="you@example.com"></murkio-identity-email-input>');
    expect(m.loginButton('Entrar', { className: 'btn' })).toBe('<murkio-identity-login-button class="btn" label="Entrar"></murkio-identity-login-button>');

    const inline = await m.bootstrapScript();
    expect(inline).toContain("data-generated-at=");
    expect(inline).not.toContain('</script><script>');
    expect(JSON.parse(inline.replace(/^<script[^>]*>|<\/script>$/g, '')).canvas.document.title).toBe('</script><script>alert(1)</script>');
    expect(safeJson(' ')).toBe('"\\u2028"');
  });
});
