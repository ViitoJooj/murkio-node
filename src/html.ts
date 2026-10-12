import { BROWSER_SDK } from './cdn';

export { BROWSER_SDK };

export function escapeAttribute(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/'/g, '&#39;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * JSON inside a <script> tag: JSON.stringify leaves "</script>" and the
 * U+2028/U+2029 separators as they are, and either would end or break the
 * script. Every <, >, & and separator becomes a \u escape.
 */
export function safeJson(value: unknown): string {
  return JSON.stringify(value)
    .replace(/</g, '\\u003c')
    .replace(/>/g, '\\u003e')
    .replace(/&/g, '\\u0026')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

export function attributes(values: Record<string, string | boolean | undefined | null>): string {
  let output = '';
  for (const [name, value] of Object.entries(values)) {
    if (value === undefined || value === null || value === false) continue;
    output += value === true ? ` ${name}` : ` ${name}="${escapeAttribute(value)}"`;
  }
  return output;
}

export interface HeadOptions {
  /** Where to go after signing in. */
  afterLogin?: string;
  locale?: string;
  /** Social sign-in return URL (must be in the application's redirect URLs). */
  oauthRedirectUrl?: string;
  /** Nonce for a Content Security Policy that lists script nonces. */
  nonce?: string;
  /** Self-hosted copy of the browser SDK. Keep the integrity of the same version. */
  scriptUrl?: string;
  integrity?: string;
}

export function scriptTag(publishableKey: string, apiUrl: string, options: HeadOptions = {}): string {
  const url = options.scriptUrl ?? BROWSER_SDK.url;
  const integrity = options.integrity ?? (options.scriptUrl ? undefined : BROWSER_SDK.integrity);
  return `<script${attributes({
    src: url,
    integrity,
    crossorigin: integrity ? 'anonymous' : undefined,
    nonce: options.nonce,
    'data-murkio-key': publishableKey,
    'data-murkio-api': apiUrl,
    'data-murkio-locale': options.locale,
    'data-murkio-after-login': options.afterLogin,
    'data-murkio-oauth-redirect': options.oauthRedirectUrl,
  })}></script>`;
}

export interface CanvasOptions {
  screen?: 'sign_in' | 'sign_up';
  className?: string;
  locale?: string;
  lightDom?: boolean;
}

export function canvasTag(options: CanvasOptions = {}): string {
  return `<murkio-identity-canvas${attributes({
    screen: options.screen,
    class: options.className,
    locale: options.locale,
    'light-dom': options.lightDom,
  })}></murkio-identity-canvas>`;
}

export interface FieldOptions {
  className?: string;
  form?: string;
  placeholder?: string;
  label?: string;
}

export function fieldTag(name: string, options: FieldOptions = {}, text?: string): string {
  return `<${name}${attributes({ class: options.className, form: options.form, placeholder: options.placeholder, label: options.label ?? text })}></${name}>`;
}

/**
 * The page a browser gets when its session cookie expired (or is missing) but
 * its "signed in" cookie says there is a session: it loads the SDK, which
 * refreshes the tokens and rewrites the cookie, and reloads the same URL. A
 * short-lived guard cookie keeps it from looping when the refresh fails.
 */
export function handshakePage(publishableKey: string, apiUrl: string, nonce: string, script: HeadOptions = {}): string {
  return `<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title></title>
${scriptTag(publishableKey, apiUrl, { ...script, nonce })}
<script nonce="${escapeAttribute(nonce)}">(async function(){try{var m=window.Murkio&&window.Murkio.getMurkio();if(m)await m.getToken();}catch(e){}location.replace(location.href);})();</script>
</head><body></body></html>`;
}

export const HANDSHAKE_GUARD = 'murkio_handshake';
