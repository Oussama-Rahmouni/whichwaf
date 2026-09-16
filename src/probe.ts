/**
 * PROBE — fetch a URL once, capture everything the classifier needs.
 *
 * Plain undici (Node global fetch), no stealth: the point of the probe is to see the
 * WAF's *default* reaction to a non-browser client. Redirects are followed but the
 * chain is recorded — a 301 into a challenge page is itself a tell.
 */

export interface ProbeResult {
  url: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
  redirectChain: string[];
  elapsedMs: number;
}

const PROBE_UA =
  'whichwaf/0.1 (+https://github.com/Oussama-Rahmouni/whichwaf)';

export async function probe(url: string, opts: { timeoutMs?: number; maxBodyBytes?: number } = {}): Promise<ProbeResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBodyBytes = opts.maxBodyBytes ?? 512_000;
  const started = Date.now();

  const res = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: {
      // Deliberately honest UA. This is a diagnostic tool, not a bypass tool.
      'user-agent': PROBE_UA,
      accept: 'text/html,application/xhtml+xml,application/json,*/*',
    },
  });

  const headers: Record<string, string | string[]> = {};
  res.headers.forEach((value, key) => {
    headers[key] = value;
  });
  // undici exposes combined set-cookie via getSetCookie() — keep the array form,
  // cookie names are first-class evidence.
  const setCookies = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
  if (setCookies.length > 0) headers['set-cookie'] = setCookies;

  const text = await res.text();

  return {
    url,
    finalUrl: res.url,
    status: res.status,
    headers,
    body: text.slice(0, maxBodyBytes),
    redirectChain: res.url !== url ? [url, res.url] : [url],
    elapsedMs: Date.now() - started,
  };
}
