# whichwaf

**Which anti-bot is protecting this site — and which layer is blocking you.**

```
$ whichwaf https://some-protected-site.com

BLOCKED — datadome (high confidence)
  evidence: datadome interstitial + status 403

stack:
  datadome (bot-manager)
    · header: x-datadome
    · cookie: datadome
    · Behavioral scoring + device fingerprint. Session continuity matters more than raw volume.

layer: behavior
  Behavioral + device fingerprint. Session continuity (same cookies, same fingerprint,
  human cadence) beats volume.
```

## Why

Every scraper hits a 403 and asks the same question: *what am I actually up against?*
The existing answers are blog posts or stale signature lists. `whichwaf` is a CLI and
library that classifies the response, shows the **exact evidence** that fired the
verdict, and maps the block to the **layer** you need to fix — identity, transport,
session, browser, behavior, or application.

Three design rules set it apart:

1. **Presence ≠ block.** A DataDome script tag on a clean 200 is not a block. cf-ray
   rides on every Cloudflare-served page. whichwaf separates "this vendor is in the
   stack" from "this response is a challenge" — misreading the first as the second
   sends clean traffic to solvers and burns money.
2. **Evidence or it didn't happen.** Every verdict prints the matched header, cookie,
   or body marker. No opaque scoring.
3. **A bare 429 is not rate limiting.** A genuine rate limiter identifies itself —
   `Retry-After`, `X-RateLimit-*` headers, or a body that says so. A first-request 429
   with none of those is a soft-block in disguise (usually a TLS/HTTP fingerprint
   rejection or IP reputation gate). whichwaf flags it as `unknown-gate` instead of
   reporting CLEAN — same for CloudFront edge error pages ("The request could not be
   satisfied") served with any status, and bare 403s generated at the CDN edge.

## Install

[![npm](https://img.shields.io/npm/v/whichwaf)](https://www.npmjs.com/package/whichwaf)

```bash
npm i -g whichwaf
```

Or from source:

```bash
git clone https://github.com/Oussama-Rahmouni/whichwaf.git
cd whichwaf
npm install
npm run build
npm link   # puts `whichwaf` on your PATH
```

Or run without linking:

```bash
npm run whichwaf -- https://example.com
```

## Usage

```bash
whichwaf <url>              # probe a URL, print the verdict
whichwaf <url> --json       # machine-readable output
whichwaf <url> --diff       # probe as plain client AND as browser, compare verdicts
whichwaf <url> --session    # probe twice: without cookies, then honoring set-cookie
whichwaf <url> --probe 20   # probe 20 times, find the volume threshold [--delay 500]
whichwaf --file urls.txt    # probe a list of URLs, aggregate summary
whichwaf --file urls.txt --report out.md   # + markdown report
whichwaf --stdin            # classify a captured raw HTTP response from stdin
whichwaf --list             # list every vendor signature
```

Exit codes: `0` clean · `2` block/challenge detected · `1` error — so it drops into
CI and shell scripts directly.

```bash
# classify a response you captured in DevTools / mitmproxy
curl -sD - https://target.com -o /dev/null | whichwaf --stdin
```

## Differential probing

`--diff` sends the same request up to three times and diffs the verdicts:

| profile | what varies |
|---|---|
| `honest` | the `whichwaf` UA, over Node's TLS stack |
| `browser` | Chrome **headers**, but still Node's TLS/HTTP2 fingerprint |
| `tls (impersonated)` | a real Chrome TLS ClientHello + HTTP/2 SETTINGS, via [curl-impersonate](https://github.com/lwthiker/curl-impersonate) — used automatically when a binary is on PATH (or set `WHICHWAF_CURL_IMPERSONATE`) |

```
$ whichwaf https://auto.jofogas.hu/magyarorszag/auto --diff

honest  (whichwaf UA):  BLOCKED — unknown-gate (high) · status 403 · 614ms
browser (chrome UA):    BLOCKED — unknown-gate (high) · status 403 · 486ms
tls     (impersonated): CLEAN · status 200 · 512ms

diff: Node-TLS probes blocked but the TLS-impersonated client passes clean — the
stack discriminates at the TRANSPORT layer (TLS JA3/JA4, HTTP/2 SETTINGS). Spoofing
headers is not enough: ship requests through curl-impersonate or a real browser.
```

Why three profiles: `honest` and `browser` share Node's TLS fingerprint, so a
two-way diff cannot tell a transport gate apart from a challenge that fires for
everyone — both look like "blocked either way". The impersonated profile isolates
the transport layer. The browser-header and impersonated requests carry the same
Chrome headers (matched to a versioned `curl_chromeNNN` binary when available), so
headers do not become a second variable. Without curl-impersonate installed,
`--diff` falls back to the two-way comparison and says so.

Reading the matrix:

- **honest blocked, browser + impersonated pass** → identity discrimination (UA, header set/order)
- **honest + browser blocked, impersonated passes** → transport discrimination (TLS/JA3/JA4, HTTP/2) — fix the fingerprint, not the headers
- **only one Node-TLS profile blocked** → identity/mixed verdict, not proof of a transport gate
- **all three blocked** → the gate is above transport: IP/ASN reputation, session token, or a challenge that must be solved
- **all clean** → if production traffic still gets blocked, the trigger is volume/behavior over time — test it with `--probe`

The impersonate binary is discovered automatically: every PATH entry is scanned
for `curl_chromeNNN` binaries and the newest Chrome impersonation wins
(`curl_chrome150` beats `curl_chrome131`); the unversioned `curl-impersonate-chrome`
wrapper is the fallback. Pin one explicitly with `WHICHWAF_CURL_IMPERSONATE`.

## Session probing

`--session` answers the state question a single request can't: *does honoring the
set-cookie lift the gate?* It probes once, then replays carrying whatever cookies
the first response set.

- **blocked → clean with cookies** → cookie-gated session (Imperva/Akamai pattern): solve once, ride the cookies
- **blocked → still blocked** → not a cookie gate; transport, identity, or an active challenge
- **redirect chain revisits the same URL while setting cookies** → cookie-roundtrip gate; clients without a cookie jar loop forever

## Volume probing

`--probe N [--delay ms]` fires N identical requests and watches for degradation.
The transition point is the diagnosis:

- **blocked from request 1, every time** → not volume; the trigger travels with the request
- **clean for 7, blocked from 8 onward** → a volume gate with a threshold around 7 requests at this cadence
- **flapping verdicts** → adaptive scoring, not a simple counter

## Fixture corpus

`fixtures/cases/` holds every live-target scenario the classifier has learned,
as raw HTTP dumps + expected verdicts, executed in `npm test`. When you meet a
new scenario in the wild, capture it (`curl -sD - -o -`), record the expected
verdict, and it can never regress silently. See `fixtures/README.md`.

## Fleet scan

Point it at a list and get the aggregate picture — who protects what, and at which
layer blocks actually happen:

```bash
whichwaf --file top-targets.txt --report report.md
```

```
scanned 5 urls in 0s
blocked: 2 · present: 0 · clean: 3 · errors: 0

vendors:
  cloudflare       4
  fastly           1

block layers:
  browser          2
```

The markdown report is a ready-to-publish dataset: summary, vendor distribution,
layer distribution, and a per-URL details table.

## Library

```ts
import { analyze, detectChallenge, fingerprintVendors, probe, diffProbe, scanUrls } from 'whichwaf';

const result = await probe('https://example.com');
const verdict = analyze(result);

verdict.blocked;            // boolean
verdict.challenge.kind;     // 'cloudflare' | 'datadome' | 'kasada' | ...
verdict.challenge.evidence; // the matched marker, for your logs
verdict.vendors;            // every vendor in the stack, block or no block
verdict.layer;              // 'identity' | 'transport' | 'session' | 'browser' | 'behavior' | 'application'
verdict.hint;               // what to fix first

const diff = await diffProbe('https://example.com');
diff.summary;               // where the stack discriminates: identity/transport vs everyone

const fleet = await scanUrls(['https://a.com', 'https://b.com']);
fleet.stats.byVendor;       // { cloudflare: 12, datadome: 3, ... }
```

`detectChallenge({ status, headers, body })` and `fingerprintVendors({ headers, body })`
are pure functions — no network — if you already have the response.

## Coverage

31 signatures, each with evidence-level output (`whichwaf --list` shows all).

**Challenge-classified** (block vs presence, with layer mapping):
Cloudflare · Vercel (Security Checkpoint) · DataDome · PerimeterX/HUMAN · Akamai · Kasada · Imperva/Incapsula ·
AWS WAF · Distil (Imperva ABP) · Queue-it · Sucuri · Wordfence · F5 BIG-IP ASM ·
DDoS-Guard · ModSecurity/OWASP CRS · Radware Bot Manager · Reblaze

**CAPTCHA platforms:**
Turnstile · reCAPTCHA · hCaptcha · funcaptcha (Arkose) · GeeTest

**Anomaly-classified** (no vendor marker, still a block):
fake 429s (bare, no Retry-After/X-RateLimit — TLS/IP soft-block disguise) · genuine
rate limiting (`ratelimit`) · CloudFront edge error pages ("The request could not be
satisfied") · bare edge-generated 403/503s · browser-check interstitial text ·
redirect chains through challenge paths — all reported as `unknown-gate` at the
transport layer

**CDN / edge fingerprinting** (presence):
Fastly · CloudFront · Vercel · BunnyCDN · Netlify · Alibaba (Tengine) ·
Azure Front Door · Google front end / Cloud Armor · Signal Sciences (Fastly Next-Gen WAF) · SafeLine

The list deliberately favors vendors a scraper actually meets over the full
enterprise-appliance zoo — every signature ships with a "what this means for a
scraper" note.

## What it is not

This is a **diagnostic** tool. It does not bypass anything. Diagnosis first —
bypass is a different craft, and it starts with knowing which layer fired.

## License

MIT · [Oussama Rahmouni](https://rahmounidev.com)
