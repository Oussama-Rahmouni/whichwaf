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
  'whichwaf/0.4 (+https://github.com/Oussama-Rahmouni/whichwaf)';

export type ProbeProfile = 'honest' | 'browser' | 'impersonated';

const DEFAULT_CHROME_VERSION = '150';

function chromeHeaders(version: string): Record<string, string> {
  return {
    'user-agent':
      `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${version}.0.0.0 Safari/537.36`,
    accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
    'accept-language': 'en-US,en;q=0.9',
    'upgrade-insecure-requests': '1',
    'sec-fetch-dest': 'document',
    'sec-fetch-mode': 'navigate',
    'sec-fetch-site': 'none',
    'sec-fetch-user': '?1',
    'sec-ch-ua': `"Chromium";v="${version}", "Not=A?Brand";v="24", "Google Chrome";v="${version}"`,
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
  };
}

const BROWSER_HEADERS = chromeHeaders(DEFAULT_CHROME_VERSION);

/** Keep the browser-header and curl-impersonate profiles on the same Chrome identity. */
export function browserHeadersForImpersonate(binary: string | null): Record<string, string> {
  const version = /curl_chrome(\d+)/i.exec(binary ?? '')?.[1] ?? DEFAULT_CHROME_VERSION;
  return chromeHeaders(version);
}

export async function probe(
  url: string,
  opts: { timeoutMs?: number; maxBodyBytes?: number; profile?: ProbeProfile; extraHeaders?: Record<string, string> } = {},
): Promise<ProbeResult> {
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBodyBytes = opts.maxBodyBytes ?? 512_000;
  const started = Date.now();

  const reqHeaders = {
    ...(opts.profile === 'browser'
      ? BROWSER_HEADERS
      : {
          // Deliberately honest UA. This is a diagnostic tool, not a bypass tool.
          'user-agent': PROBE_UA,
          accept: 'text/html,application/xhtml+xml,application/json,*/*',
        }),
    ...opts.extraHeaders,
  };

  // Follow redirects manually. fetch(redirect:'follow') hides the chain, and
  // the chain itself is evidence: a 302 into /challenge or queue-it.net is a
  // tell even when the final page looks clean.
  const redirectChain: string[] = [];
  const setCookies: string[] = [];
  let current = url;
  let res: Response | null = null;
  for (let hop = 0; hop <= 10; hop++) {
    res = await fetch(current, {
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
      headers: reqHeaders,
    });
    redirectChain.push(current);
    const sc = (res.headers as unknown as { getSetCookie?: () => string[] }).getSetCookie?.() ?? [];
    setCookies.push(...sc);
    const loc = res.headers.get('location');
    if (loc && res.status >= 300 && res.status < 400) {
      current = new URL(loc, current).toString();
      continue;
    }
    break;
  }
  if (!res) throw new Error('no response');

  const headers: Record<string, string | string[]> = {};
  res.headers.forEach((value, key) => {
    headers[key] = value;
  });
  // undici exposes combined set-cookie via getSetCookie() — keep the array form,
  // cookie names are first-class evidence. Cookies from every hop are kept:
  // a clearance cookie set by the intermediate hop matters.
  if (setCookies.length > 0) headers['set-cookie'] = setCookies;

  const text = await res.text();

  return {
    url,
    finalUrl: current,
    status: res.status,
    headers,
    body: text.slice(0, maxBodyBytes),
    redirectChain,
    elapsedMs: Date.now() - started,
    profile: opts.profile ?? 'honest',
  };
}

// ── session + repeat probes ─────────────────────────────────────────────────
// Single-request probes are blind in two dimensions: STATE (does honoring the
// set-cookie lift the gate?) and TIME (does request N get blocked when request
// 1 was clean?). These two probes extend the classifier along both.

/** Build a Cookie header value from a set-cookie array (name=value pairs only). */
export function cookieHeaderFrom(setCookies: string[]): string {
  return setCookies
    .map((c) => c.split(';')[0].trim())
    .filter((c) => c.includes('='))
    .join('; ');
}

export interface SessionProbe {
  first: ProbeResult;
  /** second request carrying the first response's cookies; null if no cookies were set */
  second: ProbeResult | null;
  /** the redirect chain visited the same URL twice while setting cookies */
  cookieLoop: boolean;
}

/**
 * Probe once, then — if the response set cookies — probe again carrying them.
 * The Imperva/Akamai/old-DataDome pattern is "block → set cookie → pass on
 * retry"; distinguishing it from a hard block changes the entire playbook.
 */
export async function probeWithSession(
  url: string,
  opts: { timeoutMs?: number; profile?: ProbeProfile } = {},
): Promise<SessionProbe> {
  const first = await probe(url, opts);

  const rawCookies = first.headers['set-cookie'];
  const setCookies = Array.isArray(rawCookies) ? rawCookies : rawCookies ? [rawCookies] : [];
  const cookieLoop =
    first.redirectChain.length > 1 &&
    new Set(first.redirectChain).size < first.redirectChain.length &&
    setCookies.length > 0;

  let second: ProbeResult | null = null;
  if (setCookies.length > 0) {
    second = await probe(first.finalUrl, {
      ...opts,
      extraHeaders: { cookie: cookieHeaderFrom(setCookies) },
    });
  }
  return { first, second, cookieLoop };
}

/**
 * Probe the same URL N times at a fixed cadence with the same profile.
 * Volume/behavior gates degrade mid-sequence; identity/transport gates fire
 * from request 1.
 */
export async function probeRepeat(
  url: string,
  opts: { count?: number; delayMs?: number; timeoutMs?: number; profile?: ProbeProfile } = {},
): Promise<ProbeResult[]> {
  const count = opts.count ?? 10;
  const delayMs = opts.delayMs ?? 300;
  const results: ProbeResult[] = [];
  for (let i = 0; i < count; i++) {
    results.push(await probe(url, opts));
    if (i < count - 1 && delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
  }
  return results;
}

// ── curl-impersonate transport profile ──────────────────────────────────────
// The `browser` profile spoofs HEADERS only — it still rides Node's TLS stack,
// so it carries the same JA3/JA4 + HTTP/2 SETTINGS fingerprint as `honest`.
// Stacks that gate on transport fingerprints (the jofogas-style fake-429) treat
// both identically, and a two-way diff wrongly concludes "blocks everyone".
//
// The `impersonated` profile shells out to curl-impersonate (if installed),
// which replays a real Chrome TLS ClientHello + HTTP/2 settings. Comparing its
// verdict against the other two isolates the transport layer definitively.

/**
 * Pick the best impersonate binary from names found on PATH.
 * Prefers the highest explicit Chrome version (curl_chrome150 > curl_chrome131),
 * then the unversioned wrapper scripts. Pure — exported for tests.
 */
export function pickImpersonateBinary(candidates: string[]): string | null {
  let best: { name: string; version: number } | null = null;
  for (const name of candidates) {
    const m = /^curl_chrome(\d+)$/i.exec(name);
    if (m) {
      const version = parseInt(m[1], 10);
      if (!best || version > best.version) best = { name, version };
    }
  }
  if (best) return best.name;
  for (const wrapper of ['curl-impersonate-chrome', 'curl-impersonate']) {
    if (candidates.includes(wrapper)) return wrapper;
  }
  return null;
}

export async function findImpersonateBinary(): Promise<string | null> {
  if (process.env.WHICHWAF_CURL_IMPERSONATE) return process.env.WHICHWAF_CURL_IMPERSONATE;

  // Discover what's actually installed: scan every PATH dir for curl_chromeNNN
  // versioned binaries and the unversioned wrappers, then pick the newest
  // Chrome impersonation available.
  const { readdir } = await import('node:fs/promises');
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const run = promisify(execFile);

  const names = new Set<string>();
  const pathSep = process.platform === 'win32' ? ';' : ':';
  for (const dir of (process.env.PATH ?? '').split(pathSep)) {
    if (!dir) continue;
    try {
      for (const f of await readdir(dir)) {
        if (/^curl_chrome\d+$/i.test(f) || /^curl-impersonate(-chrome)?$/.test(f)) names.add(f);
      }
    } catch {
      /* unreadable PATH entry */
    }
  }

  const pick = pickImpersonateBinary([...names]);
  if (!pick) return null;
  try {
    await run(pick, ['--version'], { timeout: 3000 });
    return pick;
  } catch {
    return null;
  }
}

/**
 * Probe with a real browser TLS/HTTP2 fingerprint via curl-impersonate.
 * Headers are dumped to a temp file; `-w` write-out supplies status/final URL.
 */
export async function probeImpersonate(
  url: string,
  binary: string,
  opts: { timeoutMs?: number; maxBodyBytes?: number; extraHeaders?: Record<string, string> } = {},
): Promise<ProbeResult> {
  const { execFile } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const { readFile, mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const run = promisify(execFile);

  const started = Date.now();
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const maxBodyBytes = opts.maxBodyBytes ?? 512_000;
  const dir = await mkdtemp(join(tmpdir(), 'whichwaf-'));
  const headerFile = join(dir, 'headers.txt');
  const headerArgs = Object.entries(opts.extraHeaders ?? {})
    .flatMap(([name, value]) => ['-H', `${name}: ${value}`]);

  try {
    const { stdout } = await run(
      binary,
      [
        '-sS',
        '-L',
        '--max-redirs',
        '10',
        '-D',
        headerFile,
        '--max-time',
        String(Math.ceil(timeoutMs / 1000)),
        ...headerArgs,
        '-w',
        '\n%{json}',
        url,
      ],
      { timeout: timeoutMs + 5000, maxBuffer: maxBodyBytes * 2 },
    );

    const nl = stdout.lastIndexOf('\n{');
    const body = nl >= 0 ? stdout.slice(0, nl) : stdout;
    const meta = nl >= 0 ? (JSON.parse(stdout.slice(nl + 1)) as Record<string, unknown>) : {};

    // The header dump holds one block per redirect hop; the LAST block is the
    // final response. Set-cookie lines from every hop are collected.
    const headerDump = await readFile(headerFile, 'utf8').catch(() => '');
    const blocks = headerDump.split(/\r?\n\r?\n/).filter((b) => b.trim().length > 0);
    const headers: Record<string, string | string[]> = {};
    const setCookies: string[] = [];
    for (const block of blocks) {
      for (const line of block.split(/\r?\n/).slice(1)) {
        const i = line.indexOf(':');
        if (i <= 0) continue;
        const name = line.slice(0, i).trim().toLowerCase();
        const value = line.slice(i + 1).trim();
        if (name === 'set-cookie') setCookies.push(value);
      }
    }
    const last = blocks[blocks.length - 1] ?? '';
    for (const line of last.split(/\r?\n/).slice(1)) {
      const i = line.indexOf(':');
      if (i <= 0) continue;
      headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
    }
    if (setCookies.length > 0) headers['set-cookie'] = setCookies;

    const finalUrl = typeof meta.url_effective === 'string' ? meta.url_effective : url;
    return {
      url,
      finalUrl,
      status: typeof meta.http_code === 'number' ? meta.http_code : 0,
      headers,
      body: body.slice(0, maxBodyBytes),
      redirectChain: finalUrl !== url ? [url, finalUrl] : [url],
      elapsedMs: Date.now() - started,
      profile: 'impersonated',
    };
  } finally {
    await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
