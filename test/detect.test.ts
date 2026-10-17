/**
 * Classifier tests. The critical property being pinned:
 * PRESENCE of a WAF (embedded JS, benign headers on a 200) must NOT be
 * classified as a BLOCK. Presence ≠ block.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectChallenge, type DetectInput } from '../src/detect.js';
import { fingerprintVendors } from '../src/vendors.js';
import { analyze } from '../src/analyze.js';

const mk = (over: Partial<DetectInput>): DetectInput => ({
  status: 200,
  headers: {},
  body: '<html>normal page</html>',
  ...over,
});

// ── baseline ────────────────────────────────────────────────────────────────

test('clean 200 with no markers → none', () => {
  assert.equal(detectChallenge(mk({})).kind, 'none');
});

// ── cloudflare ──────────────────────────────────────────────────────────────

test('cloudflare: cf-ray + 403 → block (high)', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'cf-ray': '8abc-FRA' } }));
  assert.equal(s.kind, 'cloudflare');
  assert.equal(s.confidence, 'high');
});

test('cloudflare: cf-ray on a clean 200 is PRESENCE, not a block', () => {
  const s = detectChallenge(mk({ status: 200, headers: { 'cf-ray': '8abc-FRA' } }));
  assert.equal(s.kind, 'none', 'cf-ray rides on every CF-served page; presence ≠ block');
});

test('cloudflare: challenge markers in body alone → medium', () => {
  const s = detectChallenge(mk({ body: '<script>window.__cf_chl_tk</script>' }));
  assert.equal(s.kind, 'cloudflare');
  assert.equal(s.confidence, 'medium');
});

test('cloudflare: cf-mitigated header → block even on unusual status', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'cf-ray': '8abc-FRA', 'cf-mitigated': 'challenge' } }));
  assert.equal(s.kind, 'cloudflare');
  assert.equal(s.confidence, 'high');
});

// ── vercel ──────────────────────────────────────────────────────────────────

test('vercel: x-vercel-mitigated: challenge + 429 → Security Checkpoint (high), not ratelimit', () => {
  // the finder.porsche.com case: the checkpoint must not fall through to ratelimit
  const s = detectChallenge(mk({
    status: 429,
    headers: { server: 'Vercel', 'x-vercel-id': 'fra1::abc-123', 'x-vercel-mitigated': 'challenge' },
    body: '',
  }));
  assert.equal(s.kind, 'vercel');
  assert.equal(s.confidence, 'high');
  assert.match(s.evidence, /x-vercel-mitigated/);
});

test('vercel: checkpoint wins over the bare-429 unknown-gate fallthrough', () => {
  const s = detectChallenge(mk({
    status: 429,
    headers: { server: 'Vercel', 'x-vercel-id': 'fra1::abc-123', 'x-vercel-mitigated': 'challenge' },
    body: '',
  }));
  assert.notEqual(s.kind, 'unknown-gate');
  assert.notEqual(s.kind, 'ratelimit');
});

test('vercel: 200 serving the checkpoint page itself → block via body marker', () => {
  const s = detectChallenge(mk({ status: 200, body: '<html><head><title>Vercel Security Checkpoint</title></head></html>' }));
  assert.equal(s.kind, 'vercel');
  assert.equal(s.confidence, 'high');
  assert.equal(s.source, 'body');
});

test('vercel: x-vercel-id on a clean 200 is PRESENCE, not a block', () => {
  const s = detectChallenge(mk({ status: 200, headers: { server: 'Vercel', 'x-vercel-id': 'fra1::abc-123' } }));
  assert.equal(s.kind, 'none');
});

test('vercel: 429 challenge maps to browser layer with PoW advice', () => {
  const a = analyze(mk({ status: 429, headers: { server: 'Vercel', 'x-vercel-mitigated': 'challenge' }, body: '' }));
  assert.equal(a.blocked, true);
  assert.equal(a.layer, 'browser');
  assert.match(a.hint, /proof-of-work/);
});

test('vercel: prose mention on a 200 is NOT a block', () => {
  const s = detectChallenge(mk({
    status: 200,
    body: '<article><h1>How the Vercel Security Checkpoint works</h1><p>A field report about Vercel Security Checkpoint.</p></article>',
  }));
  assert.equal(s.kind, 'none');
});

test('vendors: vercel fingerprinted via x-vercel-mitigated header', () => {
  const hits = fingerprintVendors({
    headers: { server: 'Vercel', 'x-vercel-id': 'fra1::abc-123', 'x-vercel-mitigated': 'challenge' },
    body: '<html>ok</html>',
  });
  const v = hits.find((h) => h.name === 'vercel');
  assert.ok(v);
  assert.ok(v.evidence.length >= 2);
});

// ── datadome ────────────────────────────────────────────────────────────────

test('datadome: captcha-delivery interstitial + 403 → block (high)', () => {
  const s = detectChallenge(mk({
    status: 403,
    body: '<iframe src="https://geo.captcha-delivery.com/captcha/"></iframe>',
  }));
  assert.equal(s.kind, 'datadome');
  assert.equal(s.confidence, 'high');
});

test('datadome: embedded api-js on a 200 is PRESENCE (low), not a block', () => {
  const s = detectChallenge(mk({
    status: 200,
    body: '<script src="https://api-js.datadome.co/tags.js"></script>',
  }));
  assert.equal(s.kind, 'datadome');
  assert.equal(s.confidence, 'low');
});

test('datadome: x-datadome header + 403 → block (high)', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'x-datadome': '1' } }));
  assert.equal(s.kind, 'datadome');
  assert.equal(s.confidence, 'high');
});

// ── perimeterx ──────────────────────────────────────────────────────────────

test('perimeterx: px-captcha marker → high', () => {
  const s = detectChallenge(mk({ status: 403, body: '<div id="px-captcha"></div>' }));
  assert.equal(s.kind, 'perimeterx');
  assert.equal(s.confidence, 'high');
});

test('perimeterx: prose mention on a 200 is NOT a block', () => {
  const s = detectChallenge(mk({
    status: 200,
    body: '<article><h1>How PerimeterX sensor JS works</h1><p>PerimeterX, now HUMAN…</p></article>',
  }));
  assert.equal(s.kind, 'none');
});

test('perimeterx: px-captcha on a 200 is PRESENCE (low), not a block', () => {
  const s = detectChallenge(mk({ status: 200, body: '<div id="px-captcha"></div>' }));
  assert.equal(s.kind, 'perimeterx');
  assert.equal(s.confidence, 'low');
});

// ── akamai ──────────────────────────────────────────────────────────────────

test('akamai: AkamaiGHost server + 403 + Reference # → high', () => {
  const s = detectChallenge(mk({
    status: 403,
    headers: { server: 'AkamaiGHost' },
    body: 'Access Denied. Reference #18.abc123',
  }));
  assert.equal(s.kind, 'akamai');
});

test('akamai: AkamaiGHost server on a clean 200 is presence, not a block', () => {
  const s = detectChallenge(mk({ status: 200, headers: { server: 'AkamaiGHost' } }));
  assert.equal(s.kind, 'none');
});

test('akamai: _abck sensor cookie + 403 → medium block', () => {
  const s = detectChallenge(mk({
    status: 403,
    headers: { 'set-cookie': '_abck=abc123~-1~; Path=/' },
  }));
  assert.equal(s.kind, 'akamai');
  assert.equal(s.source, 'cookie');
});

// ── kasada ──────────────────────────────────────────────────────────────────

test('kasada: x-kpsdk-ct + 429 → high', () => {
  const s = detectChallenge(mk({ status: 429, headers: { 'x-kpsdk-ct': 'token-value' } }));
  assert.equal(s.kind, 'kasada');
  assert.equal(s.confidence, 'high');
});

test('kasada: ips.js body marker + 403 → medium', () => {
  const s = detectChallenge(mk({ status: 403, body: '<script src="/149e9513/ips.js?x-kpsdk-v=j-0.0.0"></script>' }));
  assert.equal(s.kind, 'kasada');
});

// ── imperva ─────────────────────────────────────────────────────────────────

test('imperva: incident ID page → high', () => {
  const s = detectChallenge(mk({
    status: 403,
    body: '<html>Request unsuccessful. Incapsula incident ID: 12345</html>',
  }));
  assert.equal(s.kind, 'imperva');
});

test('imperva: incap_ses cookie + 403 → high', () => {
  const s = detectChallenge(mk({
    status: 403,
    headers: { 'set-cookie': 'incap_ses_123_456=abc; Path=/' },
  }));
  assert.equal(s.kind, 'imperva');
});

// ── aws waf ─────────────────────────────────────────────────────────────────

test('awswaf: x-amzn-waf-action: challenge → high', () => {
  const s = detectChallenge(mk({ status: 202, headers: { 'x-amzn-waf-action': 'challenge' } }));
  assert.equal(s.kind, 'awswaf');
});

test('awswaf: aws-waf-token cookie + 403 → medium', () => {
  const s = detectChallenge(mk({
    status: 403,
    headers: { 'set-cookie': 'aws-waf-token=xyz; Path=/' },
  }));
  assert.equal(s.kind, 'awswaf');
});

// ── extended waf detection ──────────────────────────────────────────────────

test('distil: interstitial → high', () => {
  const s = detectChallenge(mk({ status: 403, body: '<html>Pardon Our Interruption... distil_r_captcha</html>' }));
  assert.equal(s.kind, 'distil');
  assert.equal(s.confidence, 'high');
});

test('queueit: redirect into queue-it.net → block', () => {
  const s = detectChallenge(mk({ url: 'https://queue-it.net/1234/event/' }));
  assert.equal(s.kind, 'queueit');
});

test('sucuri: block page → high', () => {
  const s = detectChallenge(mk({ status: 403, body: '<html>Access Denied - Sucuri Website Firewall</html>' }));
  assert.equal(s.kind, 'sucuri');
  assert.equal(s.confidence, 'high');
});

test('sucuri: x-sucuri-id + 403 → high', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'x-sucuri-id': '12345' } }));
  assert.equal(s.kind, 'sucuri');
});

test('wordfence: 503 rate-limit page → block', () => {
  const s = detectChallenge(mk({
    status: 503,
    body: '<html>Your access to this site has been limited... Generated by Wordfence</html>',
  }));
  assert.equal(s.kind, 'wordfence');
});

test('wordfence: mention on a clean 200 is presence, not a block', () => {
  const s = detectChallenge(mk({ status: 200, body: '<html>protected by wordfence</html>' }));
  assert.equal(s.kind, 'none');
});

test('f5bigip: rejection page → high', () => {
  const s = detectChallenge(mk({
    status: 403,
    body: 'The requested URL was rejected. Please consult with your administrator. Your support ID is: 123',
  }));
  assert.equal(s.kind, 'f5bigip');
});

test('ddosguard: ddos-guard server + 403 → high', () => {
  const s = detectChallenge(mk({ status: 403, headers: { server: 'ddos-guard' } }));
  assert.equal(s.kind, 'ddosguard');
});

test('modsecurity: 406 + mod_security marker → high', () => {
  const s = detectChallenge(mk({ status: 406, body: 'Not Acceptable! This error was generated by mod_security.' }));
  assert.equal(s.kind, 'modsecurity');
});

test('radware: reese84 cookie + 403 → medium', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'set-cookie': 'reese84=abc; Path=/' } }));
  assert.equal(s.kind, 'radware');
});

test('reblaze: rbzid cookie + 403 → medium', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'set-cookie': 'rbzid=abc; Path=/' } }));
  assert.equal(s.kind, 'reblaze');
});

test('geetest widget → geetest', () => {
  const s = detectChallenge(mk({ body: '<script>initGeetest({gt: "abc"})</script>' }));
  assert.equal(s.kind, 'geetest');
});

test('analyze: wordfence block → layer application', () => {
  const a = analyze(mk({ status: 503, body: 'Generated by Wordfence' }));
  assert.equal(a.blocked, true);
  assert.equal(a.layer, 'application');
});

// ── captcha widgets ─────────────────────────────────────────────────────────

test('turnstile widget → turnstile', () => {
  const s = detectChallenge(mk({ body: '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>' }));
  assert.equal(s.kind, 'turnstile');
});

test('funcaptcha/arkose marker → funcaptcha', () => {
  const s = detectChallenge(mk({ body: '<script src="https://client-api.arkoselabs.com/v2/api.js"></script>' }));
  assert.equal(s.kind, 'funcaptcha');
});

test('recaptcha widget → recaptcha', () => {
  const s = detectChallenge(mk({ body: '<div class="g-recaptcha"></div>' }));
  assert.equal(s.kind, 'recaptcha');
});

test('hcaptcha widget → hcaptcha', () => {
  const s = detectChallenge(mk({ body: '<div class="h-captcha"></div>' }));
  assert.equal(s.kind, 'hcaptcha');
});

test('generic: 403 + "captcha" text, no vendor markers → captcha-generic', () => {
  const s = detectChallenge(mk({ status: 403, body: 'Please complete this captcha to proceed' }));
  assert.equal(s.kind, 'captcha-generic');
});

// ── priority ────────────────────────────────────────────────────────────────

test('priority: datadome interstitial wins over generic captcha text', () => {
  const s = detectChallenge(mk({
    status: 403,
    body: 'captcha https://geo.captcha-delivery.com/interstitial/',
  }));
  assert.equal(s.kind, 'datadome');
});

test('botdefense JSON envelope → recaptcha (not captcha-generic)', () => {
  const s = detectChallenge(mk({
    status: 403,
    body: '{"status":"failure","metadata":{"botdefense":{"state":"challenge","provider":"RECAPTCHA","reCaptchaTokenStatus":null}}}',
  }));
  assert.equal(s.kind, 'recaptcha');
  assert.equal(s.confidence, 'high');
});

// ── fake 429 / soft-block disguise (the jofogas case) ───────────────────────

test('bare 429 with no rate-limit markers → unknown-gate (fake rate limit)', () => {
  const s = detectChallenge(mk({
    status: 429,
    headers: { 'x-amz-cf-id': 'abc==', 'x-amz-cf-pop': 'SIN2-P11', via: '1.1 x.cloudfront.net (CloudFront)' },
    body: '',
  }));
  assert.equal(s.kind, 'unknown-gate');
  assert.equal(s.confidence, 'medium');
  assert.match(s.evidence, /bare 429/);
});

test('429 with Retry-After → genuine ratelimit, not unknown-gate', () => {
  const s = detectChallenge(mk({ status: 429, headers: { 'retry-after': '30' }, body: '' }));
  assert.equal(s.kind, 'ratelimit');
  assert.equal(s.confidence, 'high');
});

test('429 with X-RateLimit-Remaining → genuine ratelimit', () => {
  const s = detectChallenge(mk({ status: 429, headers: { 'x-ratelimit-remaining': '0' }, body: '' }));
  assert.equal(s.kind, 'ratelimit');
});

test('429 whose body says "rate limit" → genuine ratelimit', () => {
  const s = detectChallenge(mk({ status: 429, body: 'Rate limit exceeded, slow down' }));
  assert.equal(s.kind, 'ratelimit');
});

test('analyze: bare 429 → blocked, transport layer', () => {
  const a = analyze(mk({ status: 429, headers: { 'x-amz-cf-id': 'abc==' }, body: '' }));
  assert.equal(a.blocked, true);
  assert.equal(a.layer, 'transport');
});

// ── cloudfront edge error page ──────────────────────────────────────────────

test('cloudfront "request could not be satisfied" 403 → unknown-gate (high)', () => {
  const s = detectChallenge(mk({
    status: 403,
    headers: { server: 'CloudFront', 'x-cache': 'Error from cloudfront', 'x-amz-cf-id': 'abc==' },
    body: '<TITLE>ERROR: The request could not be satisfied</TITLE><H2>The request could not be satisfied.</H2>Request blocked.<BR>Generated by cloudfront (CloudFront)',
  }));
  assert.equal(s.kind, 'unknown-gate');
  assert.equal(s.confidence, 'high');
  assert.match(s.evidence, /CloudFront edge error page/);
});

test('cloudfront error page served as fake 429 → still unknown-gate (high)', () => {
  const s = detectChallenge(mk({
    status: 429,
    headers: { server: 'CloudFront', 'x-cache': 'Error from cloudfront' },
    body: '<H1>429 ERROR</H1><H2>The request could not be satisfied.</H2>Generated by cloudfront (CloudFront)',
  }));
  assert.equal(s.kind, 'unknown-gate');
  assert.equal(s.confidence, 'high');
});

// ── bare edge denial ────────────────────────────────────────────────────────

test('bare 403 with tiny empty body behind cloudfront → unknown-gate', () => {
  const s = detectChallenge(mk({ status: 403, headers: { 'x-amz-cf-id': 'abc==' }, body: '' }));
  assert.equal(s.kind, 'unknown-gate');
  assert.equal(s.confidence, 'medium');
});

test('403 with real app error body → none (app-level, not a gate)', () => {
  const s = detectChallenge(mk({
    status: 403,
    headers: { 'x-amz-cf-id': 'abc==' },
    body: JSON.stringify({ error: 'insufficient_scope', detail: 'token lacks orders:read for this resource and action' }),
  }));
  assert.equal(s.kind, 'none');
});

// ── interstitials, _sec, redirect chains ────────────────────────────────────

test('"checking your browser" interstitial → unknown-gate', () => {
  const s = detectChallenge(mk({ status: 503, body: '<html>Checking your browser before accessing the site.</html>' }));
  assert.equal(s.kind, 'unknown-gate');
});

test('akamai _sec challenge path → akamai', () => {
  const s = detectChallenge(mk({ status: 200, body: '<script src="/_sec/cpt_challenge/ak-challenge.js"></script>' }));
  assert.equal(s.kind, 'akamai');
});

test('redirect chain through challenge path → unknown-gate', () => {
  const s = detectChallenge(mk({
    url: 'https://shop.example/products',
    redirectChain: ['https://shop.example/products', 'https://shop.example/cdn-cgi/challenge/x', 'https://shop.example/products'],
  }));
  assert.equal(s.kind, 'unknown-gate');
});

// ── differential probing, three-way ─────────────────────────────────────────

test('diff: node blocked + impersonated clean → transport-layer conclusion', () => {
  const honest = analyze(mk({ status: 429, headers: { 'x-amz-cf-id': 'a' }, body: '' }));
  const browser = analyze(mk({ status: 429, headers: { 'x-amz-cf-id': 'b' }, body: '' }));
  const impersonated = analyze(mk({ status: 200, body: '<html>real page</html>' }));
  const s = classifyDiff(honest, browser, impersonated);
  assert.match(s, /TRANSPORT layer/);
  assert.match(s, /TLS/);
});

test('diff: all three blocked → above-transport conclusion', () => {
  const blocked = analyze(mk({ status: 403, headers: { 'cf-ray': 'x-FRA' } }));
  const s = classifyDiff(blocked, blocked, blocked);
  assert.match(s, /regardless of transport fingerprint/);
});

test('diff: three-way all clean → no block conclusion', () => {
  const clean = analyze(mk({}));
  assert.match(classifyDiff(clean, clean, clean), /No block for any identity/);
});

test('diff: two-way fallback still works without impersonated side', () => {
  const honest = analyze(mk({ status: 403, headers: { 'cf-ray': '8abc-FRA' } }));
  const browser = analyze(mk({ status: 200, headers: { 'cf-ray': '8abc-FRA', server: 'cloudflare' } }));
  assert.match(classifyDiff(honest, browser), /identity discrimination confirmed/);
});

// ── suspicious rate-limit markers & timing evidence ─────────────────────────

test('429 with Retry-After: 0 → camouflage, unknown-gate not ratelimit', () => {
  const s = detectChallenge(mk({ status: 429, headers: { 'retry-after': '0' }, body: '' }));
  assert.equal(s.kind, 'unknown-gate');
  assert.match(s.evidence, /implausible Retry-After/);
});

test('429 with absurd Retry-After (>24h) → unknown-gate', () => {
  const s = detectChallenge(mk({ status: 429, headers: { 'retry-after': '604800' }, body: '' }));
  assert.equal(s.kind, 'unknown-gate');
});

test('bare 429 with fast edge timing → evidence notes edge-generated', () => {
  const s = detectChallenge(mk({ status: 429, headers: { 'x-amz-cf-id': 'a' }, body: '', elapsedMs: 62 }));
  assert.equal(s.kind, 'unknown-gate');
  assert.match(s.evidence, /62ms.*edge/);
});

test('bare 429 without timing info → plain evidence, no crash', () => {
  const s = detectChallenge(mk({ status: 429, body: '' }));
  assert.equal(s.kind, 'unknown-gate');
  assert.doesNotMatch(s.evidence, /Served in/);
});

// ── curl-impersonate binary selection ───────────────────────────────────────

import { pickImpersonateBinary, cookieHeaderFrom } from '../src/probe.js';

test('impersonate pick: newest chrome version wins', () => {
  assert.equal(
    pickImpersonateBinary(['curl_chrome110', 'curl_chrome150', 'curl_chrome131', 'curl-impersonate-chrome']),
    'curl_chrome150',
  );
});

test('impersonate pick: falls back to unversioned wrapper', () => {
  assert.equal(pickImpersonateBinary(['curl-impersonate-chrome']), 'curl-impersonate-chrome');
  assert.equal(pickImpersonateBinary(['curl-impersonate']), 'curl-impersonate');
});

test('impersonate pick: nothing found → null', () => {
  assert.equal(pickImpersonateBinary(['curl', 'wget']), null);
  assert.equal(pickImpersonateBinary([]), null);
});

// ── session + repeat classifiers ────────────────────────────────────────────

import { classifySession, summarizeSequence } from '../src/rounds.js';

test('session: blocked → clean with cookies = cookie gate', () => {
  const first = analyze(mk({ status: 403, headers: { 'set-cookie': 'incap_ses_1_2=x; Path=/' } }));
  const second = analyze(mk({ status: 200 }));
  assert.match(classifySession(first, second, false), /cookie-gated session/);
});

test('session: still blocked with cookies → not a cookie gate', () => {
  const first = analyze(mk({ status: 429, body: '' }));
  const second = analyze(mk({ status: 429, body: '' }));
  assert.match(classifySession(first, second, false), /not a simple cookie gate/);
});

test('session: no cookies set → single-request conclusion', () => {
  assert.match(classifySession(analyze(mk({})), null, false), /No cookies were set/);
});

test('session: cookie loop → roundtrip gate conclusion', () => {
  assert.match(classifySession(analyze(mk({})), null, true), /cookie-roundtrip gate/);
});

test('cookieHeaderFrom: strips attributes, keeps name=value', () => {
  assert.equal(
    cookieHeaderFrom(['incap_ses_1_2=abc; Path=/; HttpOnly', 'visid_incap_2=def; Max-Age=3600']),
    'incap_ses_1_2=abc; visid_incap_2=def',
  );
});

test('sequence: all clean → no volume trigger', () => {
  const seq = Array.from({ length: 10 }, () => ({ status: 200, blocked: false, kind: 'none', elapsedMs: 100 }));
  assert.match(summarizeSequence(seq), /10\/10 clean/);
});

test('sequence: degradation at request 8 → volume gate with threshold', () => {
  const seq = Array.from({ length: 12 }, (_, i) => ({
    status: i < 7 ? 200 : 429,
    blocked: i >= 7,
    kind: i >= 7 ? 'unknown-gate' : 'none',
    elapsedMs: 100,
  }));
  const s = summarizeSequence(seq);
  assert.match(s, /then blocked from request 8/);
  assert.match(s, /volume\/behavior gate/);
});

test('sequence: blocked from request 1 → not volume', () => {
  const seq = Array.from({ length: 5 }, () => ({ status: 403, blocked: true, kind: 'cloudflare', elapsedMs: 80 }));
  assert.match(summarizeSequence(seq), /not a volume gate/);
});

test('sequence: flapping → adaptive scoring', () => {
  const seq = [true, false, true, false].map((b) => ({ status: b ? 429 : 200, blocked: b, kind: b ? 'unknown-gate' : 'none', elapsedMs: 100 }));
  assert.match(summarizeSequence(seq), /Unstable verdicts/);
});

// ── passive vendor fingerprinting ───────────────────────────────────────────

test('vendors: cloudflare detected on clean 200 via cf-ray + __cf_bm', () => {
  const hits = fingerprintVendors({
    headers: { 'cf-ray': '8abc-FRA', server: 'cloudflare', 'set-cookie': '__cf_bm=xyz; Path=/' },
    body: '<html>normal page</html>',
  });
  const cf = hits.find((h) => h.name === 'cloudflare');
  assert.ok(cf, 'cloudflare should be detected');
  assert.ok(cf.evidence.length >= 2, 'multiple evidence lines expected');
});

test('vendors: akamai detected via _abck cookie alone', () => {
  const hits = fingerprintVendors({
    headers: { 'set-cookie': '_abck=abc~-1~; Path=/' },
    body: '<html>normal</html>',
  });
  assert.ok(hits.some((h) => h.name === 'akamai'));
});

test('vendors: nothing on a plain nginx response', () => {
  const hits = fingerprintVendors({
    headers: { server: 'nginx/1.24.0' },
    body: '<html>normal</html>',
  });
  assert.equal(hits.length, 0);
});

// ── extended vendor fingerprints ────────────────────────────────────────────

test('vendors: sucuri via x-sucuri-id header', () => {
  const hits = fingerprintVendors({ headers: { 'x-sucuri-id': '12345' }, body: '<html>ok</html>' });
  assert.ok(hits.some((h) => h.name === 'sucuri'));
});

test('vendors: wordfence via authcookie', () => {
  const hits = fingerprintVendors({
    headers: { 'set-cookie': 'wfwaf-authcookie-abc=xyz; Path=/' },
    body: '<html>ok</html>',
  });
  assert.ok(hits.some((h) => h.name === 'wordfence'));
});

test('vendors: ddos-guard via server header and __ddg cookie', () => {
  const hits = fingerprintVendors({
    headers: { server: 'ddos-guard', 'set-cookie': '__ddgid_=abc; Path=/' },
    body: '<html>ok</html>',
  });
  const ddg = hits.find((h) => h.name === 'ddosguard');
  assert.ok(ddg);
  assert.ok(ddg.evidence.length >= 2);
});

test('vendors: radware via reese84 cookie', () => {
  const hits = fingerprintVendors({
    headers: { 'set-cookie': 'reese84=abc; Path=/' },
    body: '<html>ok</html>',
  });
  assert.ok(hits.some((h) => h.name === 'radware'));
});

test('vendors: queue-it via waiting-room marker', () => {
  const hits = fingerprintVendors({ headers: {}, body: '<script src="https://assets.queue-it.net/queue.js"></script>' });
  assert.ok(hits.some((h) => h.name === 'queueit'));
});

test('vendors: azure front door via x-azure-ref', () => {
  const hits = fingerprintVendors({ headers: { 'x-azure-ref': '0abc123' }, body: '<html>ok</html>' });
  assert.ok(hits.some((h) => h.name === 'azure'));
});

test('vendors: f5 big-ip via cookie and rejection page', () => {
  const hits = fingerprintVendors({
    headers: { 'set-cookie': 'BIGipServerpool=123; Path=/' },
    body: 'The requested URL was rejected. Please consult with your administrator. Support ID: 999',
  });
  assert.ok(hits.some((h) => h.name === 'f5bigip'));
});

test('vendors: alibaba edge via eagleid', () => {
  const hits = fingerprintVendors({ headers: { eagleid: 'abc123', server: 'Tengine' }, body: '<html>ok</html>' });
  assert.ok(hits.some((h) => h.name === 'alibaba'));
});

test('vendors: geetest via widget script', () => {
  const hits = fingerprintVendors({ headers: {}, body: '<script src="https://api.geetest.com/gettype.php"></script>' });
  assert.ok(hits.some((h) => h.name === 'geetest'));
});

// ── analyze() verdict shape ─────────────────────────────────────────────────

test('analyze: blocked cloudflare response → blocked=true, layer=browser', () => {
  const a = analyze(mk({ status: 403, headers: { 'cf-ray': '8abc-FRA' } }));
  assert.equal(a.blocked, true);
  assert.equal(a.layer, 'browser');
  assert.ok(a.hint.length > 0);
});

test('analyze: clean 200 behind cloudflare → blocked=false but vendor listed', () => {
  const a = analyze(mk({ status: 200, headers: { 'cf-ray': '8abc-FRA', server: 'cloudflare' } }));
  assert.equal(a.blocked, false);
  assert.ok(a.vendors.some((v) => v.name === 'cloudflare'));
});

// ── differential probing ────────────────────────────────────────────────────

import { classifyDiff } from '../src/diff.js';

test('diff: honest blocked + browser clean → identity confirmed, transport exonerated', () => {
  const honest = analyze(mk({ status: 403, headers: { 'cf-ray': '8abc-FRA' } }));
  const browser = analyze(mk({ status: 200, headers: { 'cf-ray': '8abc-FRA', server: 'cloudflare' } }));
  const s = classifyDiff(honest, browser);
  assert.match(s, /identity discrimination confirmed/);
  assert.match(s, /transport is exonerated/);
});

test('diff: both blocked by same vendor → challenge itself must be solved', () => {
  const honest = analyze(mk({ status: 403, headers: { 'cf-ray': '8abc-FRA' } }));
  const browser = analyze(mk({ status: 403, headers: { 'cf-ray': '9def-LHR' } }));
  const s = classifyDiff(honest, browser);
  assert.match(s, /regardless of client identity/);
});

test('diff: both clean → volume/behavior conclusion', () => {
  const clean = analyze(mk({}));
  assert.match(classifyDiff(clean, clean), /No block for either profile/);
});

test('diff: browser blocked but honest clean → behavioral conclusion', () => {
  const honest = analyze(mk({}));
  const browser = analyze(mk({ status: 403, body: '<div class="g-recaptcha"></div>' }));
  assert.match(classifyDiff(honest, browser), /unusual/i);
});

// ── fleet scan ──────────────────────────────────────────────────────────────

import { computeStats, normalizeUrl, renderMarkdownReport, type FleetRow } from '../src/fleet.js';

test('normalizeUrl: adds scheme, skips blanks and comments', () => {
  assert.equal(normalizeUrl('example.com'), 'https://example.com');
  assert.equal(normalizeUrl('http://a.com'), 'http://a.com');
  assert.equal(normalizeUrl('  '), null);
  assert.equal(normalizeUrl('# comment'), null);
});

const row = (over: Partial<FleetRow>): FleetRow => ({
  url: 'https://x.com',
  status: 200,
  verdict: 'clean',
  challenge: 'none',
  layer: 'none',
  vendors: [],
  elapsedMs: 100,
  ...over,
});

test('computeStats: counts verdicts, vendors, block layers', () => {
  const stats = computeStats([
    row({ verdict: 'blocked', challenge: 'cloudflare', layer: 'browser', vendors: ['cloudflare'] }),
    row({ verdict: 'blocked', challenge: 'datadome', layer: 'behavior', vendors: ['datadome'] }),
    row({ verdict: 'clean', vendors: ['cloudflare'] }),
    row({ verdict: 'error', status: null, error: 'timeout' }),
  ]);
  assert.equal(stats.total, 4);
  assert.equal(stats.blocked, 2);
  assert.equal(stats.clean, 1);
  assert.equal(stats.errors, 1);
  assert.equal(stats.byVendor['cloudflare'], 2);
  assert.equal(stats.byLayer['browser'], 1);
  assert.equal(stats.byLayer['behavior'], 1);
});

test('renderMarkdownReport: summary, vendor table, details table', () => {
  const res = {
    rows: [row({ verdict: 'blocked', challenge: 'cloudflare', layer: 'browser', vendors: ['cloudflare'] })],
    stats: computeStats([row({ verdict: 'blocked', challenge: 'cloudflare', layer: 'browser', vendors: ['cloudflare'] })]),
    elapsedMs: 500,
  };
  const md = renderMarkdownReport(res);
  assert.match(md, /# whichwaf fleet report/);
  assert.match(md, /\*\*blocked:\*\* 1 \(100%\)/);
  assert.match(md, /\| cloudflare \| 1 \|/);
  assert.match(md, /\| https:\/\/x\.com \| 200 \| blocked \| cloudflare \|/);
});
