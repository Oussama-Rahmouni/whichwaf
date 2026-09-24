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
  profile: ProbeProfile;
}

const PROBE_UA =
  'whichwaf/0.2 (+https://github.com/Oussama-Rahmouni/whichwaf)';

export type ProbeProfile = 'honest' | 'browser';

/**
 * The two probe profiles. `honest` is the tool's own UA — it measures the WAF's
 * default reaction to a non-browser client. `browser` mimics a current Chrome on
 * Windows — same request, different identity. Diffing the two verdicts tells you
 * WHERE the stack discriminates (identity/transport vs everyone-equally).
 */
const BROWSER_HEADERS: Record<string, string> = {
  'user-agent':
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
  accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
  'accept-language': 'en-US,en;q=0.9',
  'upgrade-insecure-requests': '1',
  'sec-fetch-dest': 'document',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-site': 'none',
  'sec-fetch-user': '?1',
  'sec-ch-ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
  'sec-ch-ua-mobile': '?0',
  'sec-ch-ua-platform': '"Windows"',
};

export async function probe(
  url: string,
  opts: { timeoutMs?: number; maxBodyBytes?: number; profile?: ProbeProfile } = {},
): Promise<ProbeResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBodyBytes = opts.maxBodyBytes ?? 512_000;
  const started = Date.now();

  const reqHeaders =
    opts.profile === 'browser'
      ? BROWSER_HEADERS
      : {
          // Deliberately honest UA. This is a diagnostic tool, not a bypass tool.
          'user-agent': PROBE_UA,
          accept: 'text/html,application/xhtml+xml,application/json,*/*',
        };

  const res = await fetch(url, {
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs),
    headers: reqHeaders,
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
    profile: opts.profile ?? 'honest',
  };
}
