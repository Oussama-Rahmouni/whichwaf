/**
 * CHALLENGE DETECTOR — pure classifier.
 *
 * Input: response status + headers + body (+ cookies). Output: which WAF/challenge,
 * if any, is sitting in front of the target.
 *
 * The critical property: PRESENCE of a WAF (embedded JS, benign headers on a 200) is
 * NOT a BLOCK. Misclassifying presence as a block sends clean traffic to solvers and
 * burns money; missing a real block loops forever.
 *
 * Each signal is small and additive (header tells > body tells). Returns the FIRST
 * positive match by priority — WAF blocks first, then CAPTCHA widgets, then "none".
 */

export type ChallengeKind =
  | 'cloudflare'
  | 'vercel'
  | 'datadome'
  | 'perimeterx'
  | 'akamai'
  | 'kasada'
  | 'imperva'
  | 'awswaf'
  | 'distil'
  | 'queueit'
  | 'sucuri'
  | 'wordfence'
  | 'f5bigip'
  | 'ddosguard'
  | 'modsecurity'
  | 'radware'
  | 'reblaze'
  | 'turnstile'
  | 'recaptcha'
  | 'hcaptcha'
  | 'funcaptcha'
  | 'geetest'
  | 'captcha-generic'
  | 'ratelimit'
  | 'unknown-gate'
  | 'none';

export type Confidence = 'high' | 'medium' | 'low';
export type SignalSource = 'status' | 'header' | 'cookie' | 'body' | 'multi';

export interface ChallengeSignal {
  kind: ChallengeKind;
  confidence: Confidence;
  source: SignalSource;
  evidence: string; // the actual matched substring/header name, for logs
}

export interface DetectInput {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  url?: string;
  /** every hop the probe followed, oldest first (includes the final URL) */
  redirectChain?: string[];
  /** response time — corroborating evidence: edge rejections are near-instant */
  elapsedMs?: number;
}

export function headerVal(headers: DetectInput['headers'], name: string): string | null {
  const lower = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) return Array.isArray(v) ? v.join(',') : (v ?? null);
  }
  return null;
}

export function hasHeader(headers: DetectInput['headers'], name: string): boolean {
  return headerVal(headers, name) !== null;
}

/** All response headers as one lowercase string — catches cookie names riding in set-cookie. */
function headerBlob(headers: DetectInput['headers']): string {
  return Object.entries(headers)
    .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(',') : v ?? ''}`)
    .join('\n')
    .toLowerCase();
}

export function detectChallenge(input: DetectInput): ChallengeSignal {
  const { status, headers, body } = input;
  const blob = headerBlob(headers);

  // ── Cloudflare ────────────────────────────────────────────────────────────
  if (hasHeader(headers, 'cf-ray') || hasHeader(headers, 'cf-mitigated')) {
    const challengeBody = /challenge-platform|__cf_chl_|cf-browser-verification|Just a moment/i.test(body);
    const blocked = status === 403 || status === 503 || hasHeader(headers, 'cf-mitigated') || challengeBody;
    if (blocked) {
      const trigger = hasHeader(headers, 'cf-mitigated')
        ? 'cf-mitigated header'
        : challengeBody
          ? `challenge page (status ${status})`
          : `status ${status}`;
      return { kind: 'cloudflare', confidence: 'high', source: 'multi', evidence: `cf-ray + ${trigger}` };
    }
  }
  if (/challenge-platform|__cf_chl_|cf-browser-verification/i.test(body)) {
    return { kind: 'cloudflare', confidence: 'medium', source: 'body', evidence: 'cf challenge marker in body' };
  }

  // ── Vercel ──────────────────────────────────────────────────────────────
  // x-vercel-mitigated: challenge is Vercel's Security Checkpoint — a JS
  // proof-of-work, NOT a rate limit. A real browser can execute the PoW. Detection
  // alone does not prove that changing TLS is enough; use the differential probe.
  const vercelMitigated = headerVal(headers, 'x-vercel-mitigated');
  if (vercelMitigated !== null && /challenge|captcha|deny/i.test(vercelMitigated)) {
    return {
      kind: 'vercel',
      confidence: 'high',
      source: 'multi',
      evidence: `x-vercel-mitigated: ${vercelMitigated} + status ${status} — Vercel Security Checkpoint (JS proof-of-work), not a rate limit`,
    };
  }
  if (/<title[^>]*>\s*vercel security checkpoint\s*<\/title>/i.test(body)) {
    return { kind: 'vercel', confidence: 'high', source: 'body', evidence: '"Vercel Security Checkpoint" page title' };
  }

  // ── DataDome ──────────────────────────────────────────────────────────────
  // DataDome's JS is embedded on every page it protects, good responses included.
  // Only the captcha-delivery interstitial (or a 4xx carrying the dd header) is a block.
  const ddInterstitial = /geo\.captcha-delivery\.com|dd_cookie_test_/i.test(body);
  if (ddInterstitial && (status === 403 || status === 401 || /captcha/i.test(body))) {
    return { kind: 'datadome', confidence: 'high', source: 'multi', evidence: `datadome interstitial + status ${status}` };
  }
  if ((hasHeader(headers, 'x-dd-debug') || hasHeader(headers, 'x-datadome')) && status >= 400) {
    return { kind: 'datadome', confidence: 'high', source: 'multi', evidence: `x-datadome header + status ${status}` };
  }
  if (hasHeader(headers, 'x-datadome') || /api-js\.datadome\.co|datadome\.co|"dd":\s*{/i.test(body)) {
    return { kind: 'datadome', confidence: 'low', source: hasHeader(headers, 'x-datadome') ? 'header' : 'body', evidence: 'datadome present (not blocking)' };
  }

  // ── PerimeterX / HUMAN ────────────────────────────────────────────────────
  // The word "perimeterx" appears in prose (articles about anti-bot) — never a
  // block signal by itself. A block is a challenge artifact (px-captcha element,
  // _px* script vars, px-cdn.net) on a block status, or the challenge header.
  const pxArtifact = /px-captcha|_px[A-Z0-9]|px-cdn\.net/i.test(body);
  if (hasHeader(headers, 'x-px-original-token') || (pxArtifact && status >= 400)) {
    return { kind: 'perimeterx', confidence: 'high', source: 'multi', evidence: `px challenge marker + status ${status}` };
  }
  if (pxArtifact) {
    return { kind: 'perimeterx', confidence: 'low', source: 'body', evidence: 'perimeterx present (not blocking)' };
  }

  // ── Akamai (Bot Manager) ──────────────────────────────────────────────────
  const server = headerVal(headers, 'server') ?? '';
  if (/AkamaiGHost|Akamai/i.test(server) || hasHeader(headers, 'x-akamai-transformed')) {
    if (status === 403 || /Reference\s*#\s*[0-9a-f.]+|akam\.net/i.test(body)) {
      return { kind: 'akamai', confidence: 'high', source: 'multi', evidence: `Server: ${server} + ${status}` };
    }
  }
  // _abck cookie is Akamai Bot Manager's sensor cookie — on a 403 it means the
  // bot manager fired even without an Akamai-branded server header.
  if (status === 403 && /set-cookie:[^\n]*_abck=/i.test(blob)) {
    return { kind: 'akamai', confidence: 'medium', source: 'cookie', evidence: '_abck sensor cookie + 403' };
  }

  // ── Kasada ────────────────────────────────────────────────────────────────
  if (hasHeader(headers, 'x-kpsdk-ct') || hasHeader(headers, 'x-kpsdk-v')) {
    if (status === 429 || status === 403) {
      return { kind: 'kasada', confidence: 'high', source: 'multi', evidence: `x-kpsdk header + status ${status}` };
    }
  }
  if ((status === 429 || status === 403) && /kpsdk|\/ips\.js/i.test(body)) {
    return { kind: 'kasada', confidence: 'medium', source: 'body', evidence: 'kpsdk/ips.js marker + block status' };
  }

  // ── Imperva / Incapsula ───────────────────────────────────────────────────
  if (/incapsula incident id|_incapsula_ resource/i.test(body)) {
    return { kind: 'imperva', confidence: 'high', source: 'body', evidence: 'Incapsula incident page' };
  }
  if (status === 403 && (hasHeader(headers, 'x-iinfo') || /set-cookie:[^\n]*(incap_ses_|visid_incap_)/i.test(blob))) {
    return { kind: 'imperva', confidence: 'high', source: 'multi', evidence: `imperva header/cookie + 403` };
  }

  // ── AWS WAF ───────────────────────────────────────────────────────────────
  const wafAction = headerVal(headers, 'x-amzn-waf-action');
  if (wafAction && /challenge|captcha|block/i.test(wafAction)) {
    return { kind: 'awswaf', confidence: 'high', source: 'header', evidence: `x-amzn-waf-action: ${wafAction}` };
  }
  if (status === 403 && /set-cookie:[^\n]*aws-waf-token=/i.test(blob)) {
    return { kind: 'awswaf', confidence: 'medium', source: 'cookie', evidence: 'aws-waf-token cookie + 403' };
  }

  // ── Distil / Imperva ABP ──────────────────────────────────────────────────
  if (/distil_r_captcha|Pardon Our Interruption/i.test(body)) {
    return { kind: 'distil', confidence: 'high', source: 'body', evidence: 'distil interstitial' };
  }

  // ── Queue-it ──────────────────────────────────────────────────────────────
  // The waiting room is a redirect into queue-it.net — check the final URL too.
  if (/queue-it\.net/i.test(input.url ?? '') || (/queue-it\.net/i.test(body) && /queue|waiting/i.test(body))) {
    return { kind: 'queueit', confidence: 'high', source: 'body', evidence: 'queue-it waiting room' };
  }

  // ── Sucuri ────────────────────────────────────────────────────────────────
  if (/Sucuri Website Firewall/i.test(body)) {
    return { kind: 'sucuri', confidence: 'high', source: 'body', evidence: 'sucuri block page' };
  }
  if (status === 403 && hasHeader(headers, 'x-sucuri-id')) {
    return { kind: 'sucuri', confidence: 'high', source: 'multi', evidence: 'x-sucuri-id + 403' };
  }

  // ── Wordfence ─────────────────────────────────────────────────────────────
  // 503 "temporarily unavailable" is the classic Wordfence rate-limit response.
  if (/generated by wordfence/i.test(body)) {
    return { kind: 'wordfence', confidence: 'high', source: 'body', evidence: 'wordfence block page' };
  }
  if ((status === 403 || status === 503) && /wordfence/i.test(body)) {
    return { kind: 'wordfence', confidence: 'medium', source: 'body', evidence: `wordfence marker + status ${status}` };
  }

  // ── F5 BIG-IP ASM ─────────────────────────────────────────────────────────
  if (/The requested URL was rejected\. Please consult with your administrator/i.test(body)) {
    return { kind: 'f5bigip', confidence: 'high', source: 'body', evidence: 'F5 ASM rejection page' };
  }

  // ── DDoS-Guard ────────────────────────────────────────────────────────────
  if (/ddos-guard/i.test(server) && (status === 403 || status === 503)) {
    return { kind: 'ddosguard', confidence: 'high', source: 'multi', evidence: `ddos-guard server + status ${status}` };
  }
  if (status >= 400 && /DDoS-Guard/i.test(body)) {
    return { kind: 'ddosguard', confidence: 'medium', source: 'body', evidence: 'ddos-guard marker + error status' };
  }

  // ── ModSecurity / OWASP CRS ───────────────────────────────────────────────
  if ((status === 406 || status === 403) && /mod_security|modsecurity/i.test(body)) {
    return { kind: 'modsecurity', confidence: 'high', source: 'multi', evidence: `mod_security marker + status ${status}` };
  }

  // ── Radware Bot Manager ───────────────────────────────────────────────────
  if (status === 403 && /set-cookie:[^\n]*reese84=/i.test(blob)) {
    return { kind: 'radware', confidence: 'medium', source: 'cookie', evidence: 'reese84 sensor cookie + 403' };
  }

  // ── Reblaze ───────────────────────────────────────────────────────────────
  if (status === 403 && /set-cookie:[^\n]*rbzid=/i.test(blob)) {
    return { kind: 'reblaze', confidence: 'medium', source: 'cookie', evidence: 'rbzid cookie + 403' };
  }

  // ── CAPTCHA widgets / challenge platforms ─────────────────────────────────
  // UberEats-style botdefense JSON envelope: the API never serves a widget,
  // so match the envelope directly.
  if (/"botdefense"\s*:/i.test(body) && /"provider"\s*:\s*"RECAPTCHA"/i.test(body)) {
    return { kind: 'recaptcha', confidence: 'high', source: 'body', evidence: 'botdefense reCAPTCHA envelope' };
  }
  if (/challenges\.cloudflare\.com\/turnstile|cf-turnstile/i.test(body)) {
    return { kind: 'turnstile', confidence: 'high', source: 'body', evidence: 'turnstile widget' };
  }
  if (/funcaptcha|arkoselabs|client-api\.arkoselabs/i.test(body)) {
    return { kind: 'funcaptcha', confidence: 'high', source: 'body', evidence: 'arkose/funcaptcha marker' };
  }
  if (/g-recaptcha|recaptcha\/api\.js|grecaptcha\.execute/i.test(body)) {
    return { kind: 'recaptcha', confidence: 'high', source: 'body', evidence: 'g-recaptcha widget' };
  }
  if (/h-captcha|hcaptcha\.com\/captcha/i.test(body)) {
    return { kind: 'hcaptcha', confidence: 'high', source: 'body', evidence: 'hcaptcha widget' };
  }
  if (/api\.geetest\.com|initGeetest|geetest/i.test(body)) {
    return { kind: 'geetest', confidence: 'high', source: 'body', evidence: 'geetest widget' };
  }
  if (status === 403 && /captcha/i.test(body)) {
    return { kind: 'captcha-generic', confidence: 'low', source: 'body', evidence: '403 + "captcha" in body' };
  }

  // ── CloudFront edge error page ────────────────────────────────────────────
  // CloudFront serves this page itself ("Generated by cloudfront") when the
  // request never reaches the origin: AWS WAF block, geo restriction, or a
  // Lambda@Edge/CloudFront Function gate. The status is whatever the gate
  // configured — 403 is common, 429 is used to *look like* rate limiting.
  // Real signature: x-cache: Error from cloudfront + the branded error body.
  const cfErrorPage =
    /The request could not be satisfied/i.test(body) &&
    (/Generated by cloudfront/i.test(body) || /^Error from cloudfront$/im.test(headerVal(headers, 'x-cache') ?? ''));
  if (cfErrorPage && status >= 400) {
    return {
      kind: 'unknown-gate',
      confidence: 'high',
      source: 'multi',
      evidence: `CloudFront edge error page (status ${status}) — request rejected at the edge, never reached origin`,
    };
  }

  // ── Akamai silent challenge (_sec) ────────────────────────────────────────
  if (/_sec\/cpt_challenge|_sec\/verify|\/_sec\/cpo/i.test(body) || /_sec\/cpt_challenge/i.test(input.url ?? '')) {
    return { kind: 'akamai', confidence: 'medium', source: 'body', evidence: 'akamai _sec challenge path' };
  }

  // ── Redirect into a challenge path ────────────────────────────────────────
  // The final URL may look clean while the chain passed through a challenge
  // gate (common with "verify then redirect back" flows).
  const chain = [...(input.redirectChain ?? []), input.url ?? ''].filter(Boolean);
  const challengeHop = chain.find((u) => /\/(cdn-cgi\/challenge|_sec\/|browser-check|__verify|challenge-platform)/i.test(u));
  if (challengeHop) {
    return {
      kind: 'unknown-gate',
      confidence: 'medium',
      source: 'multi',
      evidence: `redirect chain passes through challenge path: ${challengeHop}`,
    };
  }

  // ── Generic interstitial text ─────────────────────────────────────────────
  // Browser-check pages that carry no vendor marker. Keep the phrases tight —
  // loose words like "challenge" or "verify" appear in normal prose.
  const interstitial =
    /checking your (browser|connection)|verify you are (a )?human|needs to review the security of your connection|enable javascript and cookies to continue|attention required!/i.test(
      body,
    );
  if (interstitial && (status >= 400 || body.length < 20_000)) {
    return {
      kind: 'unknown-gate',
      confidence: status >= 400 ? 'medium' : 'low',
      source: 'body',
      evidence: `browser-check interstitial text (status ${status})`,
    };
  }

  // ── 429: real rate limit vs. soft-block disguise ──────────────────────────
  // A genuine rate limiter identifies itself: Retry-After, X-RateLimit-*
  // headers, or a body that says "rate limit". A BARE 429 — none of those,
  // on a single first request — is the classic disguise for an edge gate
  // (TLS/JA3/JA4 + HTTP/2 fingerprint rejection, or IP reputation). jofogas-style
  // stacks serve exactly this behind CloudFront.
  //
  // Second-generation disguise: gates that DO add plausible-looking headers.
  // `Retry-After: 0` or an absurd backoff (>24h) is a real limiter shape with
  // an impossible value — a real limiter never says "retry immediately".
  const edgeFast =
    input.elapsedMs !== undefined && input.elapsedMs < 150
      ? ` Served in ${input.elapsedMs}ms — near-instant, so generated at the edge without touching an origin.`
      : '';
  if (status === 429) {
    const retryAfter = headerVal(headers, 'retry-after');
    const rateHeaders = Object.keys(headers).filter((k) => /^x-(rate|ratelimit)/i.test(k));
    const bodySays = /rate.?limit|too many requests|throttl/i.test(body);
    if (retryAfter !== null) {
      const secs = /^\d+$/.test(retryAfter.trim()) ? parseInt(retryAfter.trim(), 10) : null;
      if (secs === 0 || (secs !== null && secs > 86_400)) {
        return {
          kind: 'unknown-gate',
          confidence: 'medium',
          source: 'multi',
          evidence: `429 with implausible Retry-After: ${retryAfter} — real limiters never say "retry immediately" or "retry tomorrow"; header is camouflage`,
        };
      }
      return { kind: 'ratelimit', confidence: 'high', source: 'multi', evidence: `429 with retry-after: ${retryAfter}` };
    }
    if (rateHeaders.length > 0 || bodySays) {
      const why = rateHeaders.length > 0 ? rateHeaders.join(', ') : 'body says rate limit';
      return { kind: 'ratelimit', confidence: 'high', source: 'multi', evidence: `429 with genuine rate-limit markers (${why})` };
    }
    return {
      kind: 'unknown-gate',
      confidence: 'medium',
      source: 'status',
      evidence:
        'bare 429 — no Retry-After, no X-RateLimit-*, body does not mention rate limiting. First-request 429 is a classic soft-block disguise (TLS/HTTP fingerprint or IP reputation rejection), not real rate limiting' +
        edgeFast,
    };
  }

  // ── Bare edge denial ──────────────────────────────────────────────────────
  // 403/503 with a tiny body behind a known CDN, carrying no WAF markers and
  // no explanatory text: the edge generated the response (WAF custom response,
  // geo block, or fingerprint gate). A real application 403 almost always
  // comes from the app with its own error body.
  if ((status === 403 || status === 503) && body.trim().length < 512) {
    const edge = hasHeader(headers, 'x-amz-cf-id') || hasHeader(headers, 'x-amz-cf-pop')
      ? 'cloudfront'
      : /AkamaiGHost/i.test(server) || hasHeader(headers, 'x-akamai-transformed')
        ? 'akamai'
        : hasHeader(headers, 'x-served-by') || hasHeader(headers, 'x-cache-hits')
          ? 'fastly'
          : hasHeader(headers, 'x-vercel-id')
            ? 'vercel'
            : null;
    if (edge && !/error|denied|forbidden|blocked|unavailable/i.test(body)) {
      return {
        kind: 'unknown-gate',
        confidence: 'medium',
        source: 'multi',
        evidence: `bare ${status} with tiny unexplained body behind ${edge} — edge-generated denial (WAF custom response, geo block, or fingerprint gate)` + edgeFast,
      };
    }
  }

  return { kind: 'none', confidence: 'high', source: 'status', evidence: `status ${status}, no WAF markers` };
}
