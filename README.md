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

Two design rules set it apart:

1. **Presence ≠ block.** A DataDome script tag on a clean 200 is not a block. cf-ray
   rides on every Cloudflare-served page. whichwaf separates "this vendor is in the
   stack" from "this response is a challenge" — misreading the first as the second
   sends clean traffic to solvers and burns money.
2. **Evidence or it didn't happen.** Every verdict prints the matched header, cookie,
   or body marker. No opaque scoring.

## Install

Not on npm yet — install from source:

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

`--diff` sends the same request twice — once with the honest `whichwaf` UA, once as
current Chrome — and diffs the verdicts:

```
$ whichwaf https://claude.ai --diff

honest  (whichwaf UA):  BLOCKED — cloudflare (high) · status 403 · 82ms
browser (chrome UA):    BLOCKED — cloudflare (high) · status 200 · 128ms

diff: Both profiles blocked by cloudflare — the check fires regardless of client
identity. Fingerprint work alone won't help; the browser layer challenge itself
must be solved.
```

If the plain client is blocked but the browser profile passes, discrimination is at
identity/transport (UA, TLS, header order) — that's where the fix goes. If both are
blocked identically, don't waste time on fingerprints; solve the challenge.

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
Cloudflare · DataDome · PerimeterX/HUMAN · Akamai · Kasada · Imperva/Incapsula ·
AWS WAF · Distil (Imperva ABP) · Queue-it · Sucuri · Wordfence · F5 BIG-IP ASM ·
DDoS-Guard · ModSecurity/OWASP CRS · Radware Bot Manager · Reblaze

**CAPTCHA platforms:**
Turnstile · reCAPTCHA · hCaptcha · funcaptcha (Arkose) · GeeTest

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
