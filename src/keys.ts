/**
 * The same FNV-1a hash the browser SDK uses to name its cookies
 * (@murkio/html src/hash.ts): the session cookie of a publishable key is
 * `__Host-murkio_session_<hash>`. Both must stay in sync; a test checks the
 * reference vectors.
 */
export function fnv1a32(value: string): string {
  let hash = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(value)) {
    hash ^= byte;
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

export interface CookieNames {
  session: string;
  uat: string;
}

/**
 * The session cookie names a backend accepts, strongest first. `__Host-` is
 * what the browser writes on https. `__Secure-` only when the developer set a
 * cookie domain (shared with subdomains). The unprefixed name only for
 * localhost: on a real host any sibling subdomain could set it.
 */
export function acceptedCookieNames(keyHash: string, host: string, cookieDomain?: string): CookieNames[] {
  const names: CookieNames[] = [{ session: `__Host-murkio_session_${keyHash}`, uat: `__Host-murkio_uat_${keyHash}` }];
  if (cookieDomain) names.push({ session: `__Secure-murkio_session_${keyHash}`, uat: `__Secure-murkio_uat_${keyHash}` });
  const hostname = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
    names.push({ session: `murkio_session_${keyHash}`, uat: `murkio_uat_${keyHash}` });
  }
  return names;
}
