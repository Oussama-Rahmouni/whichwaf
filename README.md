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
whichwaf --stdin            # classify a captured raw HTTP response from stdin
whichwaf --list             # list every vendor signature
```

Exit codes: `0` clean · `2` block/challenge detected · `1` error — so it drops into
CI and shell scripts directly.

```bash
# classify a response you captured in DevTools / mitmproxy
curl -sD - https://target.com -o /dev/null | whichwaf --stdin
```

## Library

```ts
import { analyze, detectChallenge, fingerprintVendors, probe } from 'whichwaf';

const result = await probe('https://example.com');
const verdict = analyze(result);

verdict.blocked;            // boolean
verdict.challenge.kind;     // 'cloudflare' | 'datadome' | 'kasada' | ...
verdict.challenge.evidence; // the matched marker, for your logs
verdict.vendors;            // every vendor in the stack, block or no block
verdict.layer;              // 'identity' | 'transport' | 'session' | 'browser' | 'behavior' | 'application'
verdict.hint;               // what to fix first
```

`detectChallenge({ status, headers, body })` and `fingerprintVendors({ headers, body })`
are pure functions — no network — if you already have the response.

## Coverage

| Vendor | Headers | Cookies | Body markers | Challenge classification |
|---|---|---|---|---|
| Cloudflare (incl. managed challenge) | ✓ | ✓ | ✓ | ✓ |
| DataDome | ✓ | ✓ | ✓ | ✓ (block vs presence) |
| PerimeterX / HUMAN | ✓ | ✓ | ✓ | ✓ |
| Akamai Bot Manager | ✓ | ✓ (`_abck`, `ak_bmsc`) | ✓ | ✓ |
| Kasada | ✓ (`x-kpsdk-*`) | — | ✓ | ✓ |
| Imperva / Incapsula | ✓ | ✓ | ✓ | ✓ |
| AWS WAF | ✓ (`x-amzn-waf-*`) | ✓ | — | ✓ |
| Turnstile / reCAPTCHA / hCaptcha / funcaptcha (Arkose) | — | — | ✓ | ✓ |
| Fastly / CloudFront / Vercel (CDN layer) | ✓ | — | — | presence only |

## What it is not

This is a **diagnostic** tool. It does not bypass anything. Diagnosis first —
bypass is a different craft, and it starts with knowing which layer fired.

## License

MIT · [Oussama Rahmouni](https://rahmounidev.com)
