/**
 * PASSIVE VENDOR FINGERPRINTS — who is in front of this site, block or no block.
 *
 * `detectChallenge` answers "what is blocking me right now". This answers the wider
 * question: "whose stack is this response passing through" — including on clean 200s,
 * where no challenge fires but the vendor still rides the response (cf-ray on every
 * Cloudflare page, _abck on every Akamai Bot Manager page, etc).
 *
 * Signatures are data, not code: each entry lists header names, header value patterns,
 * cookie names, and body markers. A vendor is reported with every piece of evidence found.
 */

import { headerVal, type DetectInput } from './detect.js';

export type VendorKind = 'waf' | 'cdn' | 'captcha' | 'bot-manager';

export interface VendorSignature {
  name: string;
  kind: VendorKind;
  /** exact header names whose presence is evidence */
  headers?: string[];
  /** [headerName, valuePattern] pairs */
  headerValues?: [string, RegExp][];
  /** cookie names (matched inside set-cookie) */
  cookies?: string[];
  /** body markers */
  bodyPatterns?: RegExp[];
  /** one-line "what this means for a scraper" */
  note: string;
}

export interface VendorHit {
  name: string;
  kind: VendorKind;
  evidence: string[];
  note: string;
}

export const SIGNATURES: VendorSignature[] = [
  {
    name: 'cloudflare',
    kind: 'waf',
    headers: ['cf-ray', 'cf-mitigated', 'cf-cache-status', 'cf-request-id'],
    headerValues: [['server', /^cloudflare$/i]],
    cookies: ['__cf_bm', 'cf_clearance'],
    bodyPatterns: [/challenge-platform/i, /__cf_chl_/i, /challenges\.cloudflare\.com/i],
    note: 'JS challenge + managed challenge + Turnstile. Transport (TLS/JA3) and session layers both scored.',
  },
  {
    name: 'datadome',
    kind: 'bot-manager',
    headers: ['x-datadome', 'x-dd-debug'],
    cookies: ['datadome'],
    bodyPatterns: [/api-js\.datadome\.co/i, /geo\.captcha-delivery\.com/i, /dd_cookie_test_/i],
    note: 'Behavioral scoring + device fingerprint. Session continuity matters more than raw volume.',
  },
  {
    name: 'perimeterx',
    kind: 'bot-manager',
    headers: ['x-px-original-token'],
    cookies: ['_pxhd', '_pxff_ts'],
    bodyPatterns: [/perimeterx/i, /px-captcha/i, /_px[A-Z0-9]/i, /px-client/i],
    note: 'Now HUMAN. Sensor JS + behavioral model. Mobile SDK common on app APIs.',
  },
  {
    name: 'akamai',
    kind: 'bot-manager',
    headerValues: [['server', /AkamaiGHost|Akamai/i]],
    headers: ['x-akamai-transformed'],
    cookies: ['_abck', 'ak_bmsc', 'bm_sv', 'akaalb'],
    bodyPatterns: [/Reference\s*#\s*[0-9a-f.]+/i, /akam\.net/i],
    note: 'Bot Manager sensor (_abck) + edge deny. TLS fingerprint scored at the edge.',
  },
  {
    name: 'kasada',
    kind: 'bot-manager',
    headers: ['x-kpsdk-ct', 'x-kpsdk-v', 'x-kpsdk-h'],
    bodyPatterns: [/kpsdk/i, /\/ips\.js/i],
    note: 'Proof-of-work style client puzzle (ips.js). Hardest of the majors to fake passively.',
  },
  {
    name: 'imperva',
    kind: 'waf',
    headers: ['x-iinfo', 'x-cdn-forward'],
    cookies: ['incap_ses_', 'visid_incap_', 'nlbi_'],
    bodyPatterns: [/incapsula incident id/i, /_incapsula_ resource/i],
    note: 'Incapsula. Cookie-based session gating with occasional JS challenges.',
  },
  {
    name: 'awswaf',
    kind: 'waf',
    headers: ['x-amzn-waf-action', 'x-amzn-waf-rulegroup'],
    cookies: ['aws-waf-token'],
    note: 'AWS WAF challenge/CAPTCHA action. Token cookie carries the clearance.',
  },
  {
    name: 'fastly',
    kind: 'cdn',
    headers: ['x-served-by', 'x-cache-hits', 'fastly-restarts'],
    headerValues: [['server', /^Varnish$/i]],
    note: 'CDN layer. WAF (Signal Sciences/Next-Gen) may or may not be enabled behind it.',
  },
  {
    name: 'cloudfront',
    kind: 'cdn',
    headers: ['x-amz-cf-id', 'x-amz-cf-pop'],
    headerValues: [['via', /CloudFront/i]],
    note: 'AWS CDN. Often paired with AWS WAF or a custom Lambda@Edge gate.',
  },
  {
    name: 'vercel',
    kind: 'cdn',
    headers: ['x-vercel-id', 'x-vercel-cache'],
    headerValues: [['server', /^Vercel$/i]],
    note: 'Vercel edge. Built-in bot protection is opt-in; check for challenge behavior.',
  },
  {
    name: 'recaptcha',
    kind: 'captcha',
    bodyPatterns: [/g-recaptcha/i, /recaptcha\/api\.js/i, /grecaptcha\.execute/i],
    note: 'Google reCAPTCHA v2/v3 or Enterprise. v3 scores silently; v2 challenges visibly.',
  },
  {
    name: 'hcaptcha',
    kind: 'captcha',
    bodyPatterns: [/h-captcha/i, /hcaptcha\.com/i],
    note: 'hCaptcha widget or Enterprise risk score.',
  },
  {
    name: 'turnstile',
    kind: 'captcha',
    bodyPatterns: [/challenges\.cloudflare\.com\/turnstile/i, /cf-turnstile/i],
    note: 'Cloudflare Turnstile — managed, mostly non-interactive, still a scored signal.',
  },
  {
    name: 'funcaptcha',
    kind: 'captcha',
    bodyPatterns: [/funcaptcha/i, /arkoselabs/i],
    note: 'Arkose Labs. Interactive challenges, expensive to solve at scale.',
  },
];

function cookieBlob(headers: DetectInput['headers']): string {
  const raw = headerVal(headers, 'set-cookie') ?? '';
  return raw.toLowerCase();
}

export function fingerprintVendors(input: Pick<DetectInput, 'headers' | 'body'>): VendorHit[] {
  const { headers, body } = input;
  const cookies = cookieBlob(headers);
  const hits: VendorHit[] = [];

  for (const sig of SIGNATURES) {
    const evidence: string[] = [];

    for (const h of sig.headers ?? []) {
      if (headerVal(headers, h) !== null) evidence.push(`header: ${h}`);
    }
    for (const [h, re] of sig.headerValues ?? []) {
      const v = headerVal(headers, h);
      if (v !== null && re.test(v)) evidence.push(`header: ${h}: ${v}`);
    }
    for (const c of sig.cookies ?? []) {
      if (cookies.includes(c.toLowerCase())) evidence.push(`cookie: ${c}`);
    }
    for (const re of sig.bodyPatterns ?? []) {
      const m = body.match(re);
      if (m) evidence.push(`body: "${m[0]}"`);
    }

    if (evidence.length > 0) {
      hits.push({ name: sig.name, kind: sig.kind, evidence, note: sig.note });
    }
  }
  return hits;
}
