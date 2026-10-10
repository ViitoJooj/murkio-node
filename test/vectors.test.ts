import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { createMurkio, fnv1a32 } from '../src';

const vectors = JSON.parse(readFileSync(join(__dirname, '../../../spec/server/vectors.json'), 'utf8')) as {
  application_id: string;
  issuer: string;
  jwks: unknown;
  cases: { name: string; token: string; expect: 'valid' | 'expired' | 'rejected'; session?: { user_id: string; session_id: string; roles: string[] } }[];
  cookie_hash: Record<string, string>;
};

const fetch = (async (input: RequestInfo | URL) => {
  const path = new URL(String(input)).pathname;
  const body =
    path === '/v1/client'
      ? { data: { application_id: vectors.application_id, issuer: vectors.issuer, jwks_url: '/jwks.json', config: {}, canvas: {} } }
      : vectors.jwks;
  return new Response(JSON.stringify(body), { status: 200 });
}) as typeof globalThis.fetch;

/** The same tokens must get the same verdict in every server SDK (libs/spec/server). */
describe('shared vectors', () => {
  it('hashes publishable keys like the other SDKs', () => {
    for (const [value, hash] of Object.entries(vectors.cookie_hash)) expect(fnv1a32(value)).toBe(hash);
  });

  for (const tc of vectors.cases) {
    it(tc.name, async () => {
      const murkio = createMurkio({ publishableKey: 'pk_vectors', apiUrl: 'https://api.example.com', fetch });
      const result = await murkio.authenticate(new Request('https://app.example.com/', { headers: { Authorization: `Bearer ${tc.token || 'x'}` } }));
      if (tc.expect === 'valid') {
        expect(result.session).toMatchObject({ userId: tc.session?.user_id, sessionId: tc.session?.session_id, roles: tc.session?.roles });
      } else {
        expect(result.session).toBeNull();
        expect(result.reason).toBe(tc.expect === 'expired' ? 'expired' : 'invalid');
      }
    });
  }
});
