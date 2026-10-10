/** What the SDK reads from a request, from a Fetch `Request` or a Node `IncomingMessage`. */
export interface RequestInfo {
  method: string;
  url: URL;
  header(name: string): string | null;
  cookie(name: string): string | null;
}

interface NodeLike {
  method?: string;
  url?: string;
  originalUrl?: string;
  headers: Record<string, string | string[] | undefined>;
  protocol?: string;
  secure?: boolean;
  socket?: { encrypted?: boolean };
}

export type RequestLike = Request | NodeLike;

function parseCookies(raw: string | null): Map<string, string> {
  const cookies = new Map<string, string>();
  if (!raw) return cookies;
  for (const part of raw.split(';')) {
    const index = part.indexOf('=');
    if (index < 1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (!cookies.has(name) && value !== '') {
      try {
        cookies.set(name, decodeURIComponent(value));
      } catch {
        cookies.set(name, value);
      }
    }
  }
  return cookies;
}

export function readRequest(request: RequestLike): RequestInfo {
  if (typeof Request !== 'undefined' && request instanceof Request) {
    const cookies = parseCookies(request.headers.get('cookie'));
    return {
      method: request.method.toUpperCase(),
      url: new URL(request.url),
      header: (name) => request.headers.get(name),
      cookie: (name) => cookies.get(name) ?? null,
    };
  }

  const node = request as NodeLike;
  const header = (name: string) => {
    const value = node.headers[name.toLowerCase()];
    return Array.isArray(value) ? (value[0] ?? null) : (value ?? null);
  };
  const protocol = node.protocol ?? (node.secure || node.socket?.encrypted ? 'https' : 'http');
  const cookies = parseCookies(header('cookie'));
  return {
    method: (node.method ?? 'GET').toUpperCase(),
    url: new URL(node.originalUrl ?? node.url ?? '/', `${protocol}://${header('host') ?? 'localhost'}`),
    header,
    cookie: (name) => cookies.get(name) ?? null,
  };
}
