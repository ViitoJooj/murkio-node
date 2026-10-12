/** The public configuration of an application (`GET /v1/client`). */
export interface PublicConfig {
  methods: { password: boolean };
  mfa: { mode: 'off' | 'optional' | 'required' };
  oauth_providers: string[];
  signup: { login_on_verify: boolean };
}

/** `GET /v1/client`: the application, its config and the published canvas. The server passes the canvas on, it never reads it. */
export interface ClientBootstrap {
  application_id: string;
  issuer: string;
  jwks_url: string;
  config: PublicConfig;
  canvas: { version: number; document: unknown };
}

/** The profile of `POST /v1/me`. */
export interface Me {
  id: string;
  session_id: string;
  email: string | null;
  email_verified: boolean;
  roles: string[];
  mfa_enabled: boolean;
  created_at: string;
}
