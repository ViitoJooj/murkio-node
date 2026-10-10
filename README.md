# @murkio/node

Murkio identity for backends on Node 20+ and edge runtimes (Express, Hono, Next,
SvelteKit, Bun, Deno). It tells who is behind each request and writes the login
components into the pages you render. The only setting is your publishable key.

```sh
MURKIO_PUBLISHABLE_KEY=pk_...    # MURKIO_API_URL is optional
```

## Express

```js
import express from 'express';
import { createMurkio } from '@murkio/node';

const murkio = createMurkio();
const app = express();

app.use(murkio.express());                                     // req.murkio.session (or null)
app.get('/dashboard', murkio.express({ required: true, signInUrl: '/login' }), (req, res) => {
  res.send(`Hello ${req.murkio.session.userId}`);
});
app.get('/admin', murkio.express({ required: true, roles: ['admin'], loadUser: true }), (req, res) => {
  res.json(req.murkio.user);                                   // email, roles, 2FA from POST /v1/me
});

app.get('/login', async (req, res) => {
  res.send(`<!doctype html><html><head>${murkio.head({ afterLogin: '/dashboard' })}${await murkio.bootstrapScript()}</head>
    <body>${murkio.canvas()}</body></html>`);
});
```

## Fetch-style frameworks (Hono, SvelteKit hooks, Bun, Next middleware)

```ts
const { result, response } = await murkio.protect(request, { required: true });
if (response) return response;     // 401, 403, redirect or the session-refresh page
result.session?.userId;
```

## How it works

- `GET /v1/client` (with the publishable key) gives the application id, the token
  issuer and the JWKS. Access tokens are verified **locally** (EdDSA, `iss`, `aud`,
  `exp`): a request costs no call to the API. `checkRevocation: true` also asks the
  API (cached 30 s) so a logout or ban takes effect before the token expires (15 min).
- The token comes from `Authorization: Bearer` (your API called with `murkio.fetch`
  or `getToken()` in the browser) or from the session cookie `@murkio/html` writes
  (`__Host-murkio_session_<hash>`) on page navigations.
- **CSRF:** the cookie only counts for GET/HEAD/OPTIONS or same-origin requests
  (`Sec-Fetch-Site`, else `Origin`). Anything that changes state must send the token
  in the header. Only the `__Host-` cookie is accepted on a real host (the plain name
  only on localhost; `__Secure-` only with `cookieDomain`).
- **Expired cookie:** the access token cookie lasts 15 minutes. When a page request
  has none but the browser's "signed in" cookie is set, `protect`/`express` answer a
  tiny page (strict CSP, no-store) that loads the SDK, refreshes the tokens and
  reloads the same URL. A 30-second guard cookie stops it from looping.
- The backend never signs anyone in or refreshes tokens: the browser does, because
  the API rate-limits per user IP.

## Page helpers

`head()` writes the `<script>` of the browser SDK of the same release, pinned with
its SRI hash (`scriptUrl`/`integrity` to self-host). `bootstrapScript()` inlines the
application and canvas (escaped for `<script>`), so the canvas draws at once.
`canvas()`, `emailInput()`, `passwordInput()`, `keepLogged()`, `loginButton(text)`,
`registerButton(text)` and `errorMessage()` return the components' HTML with escaped
attributes.
