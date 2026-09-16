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
