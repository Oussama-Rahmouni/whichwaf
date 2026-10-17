# Changelog

## 0.4.0 — Vercel Security Checkpoint detection

### Detection

- **New kind: `vercel`.** A response carrying `x-vercel-mitigated: challenge` is Vercel's
  Security Checkpoint — a JS proof-of-work, not a rate limit. It previously fell
  through to `unknown-gate` (or could read as a fake 429). Also detects the
  200-status variant serving the checkpoint page itself ("Vercel Security Checkpoint").
- Layer mapping: **browser** — a real browser can execute the PoW. Classification alone
  does not claim that curl-impersonate passes; use `--diff` to measure transport effects.
- Body-only detection requires the actual checkpoint `<title>`, so an article discussing
  Vercel Security Checkpoint is not misclassified as a block.
- Passive fingerprint extended: `x-vercel-mitigated` header and the checkpoint page
  title now count as Vercel evidence.
- New fixture: `porsche-finder-vercel-checkpoint-429`.

### Differential-probe corrections

- A transport conclusion now requires **both** Node-TLS profiles to be blocked while the
  impersonated profile is clean. Honest-blocked/browser-clean is correctly reported as
  identity discrimination instead.
- Browser-header and impersonated probes share the same Chrome headers, derived from the
  selected `curl_chromeNNN` binary when available. Probe UA updated to `whichwaf/0.4`.

## 0.3.0 — soft-block detection + transport-aware diffing

### Detection

- **Fake 429s**: a bare 429 (no `Retry-After`, no `X-RateLimit-*`, body doesn't
  mention rate limiting) now reports `BLOCKED — unknown-gate` instead of CLEAN.
  First-request 429 is a classic soft-block disguise (TLS/HTTP fingerprint or IP
  reputation rejection), not real rate limiting.
- **Genuine rate limiting**: 429s that DO carry `Retry-After` / `X-RateLimit-*`
  classify as `ratelimit` (behavior layer — throttle, don't change fingerprints).
- **Camouflage markers**: `Retry-After: 0` or absurd backoffs (>24h) classify as
  `unknown-gate` — real limiters never say "retry immediately".
- **CloudFront edge error pages** ("The request could not be satisfied") detected
  on any status, including fake-429 variants.
- **Bare edge-generated 403/503s** behind CloudFront/Akamai/Fastly/Vercel with
  tiny unexplained bodies → `unknown-gate`.
- New signals: Akamai `_sec` challenge paths, browser-check interstitial text,
  redirect chains through challenge paths, edge-latency evidence (<150ms errors).
- New kinds: `unknown-gate` (transport layer) and `ratelimit` (behavior layer).

### Probing

- `--diff` is now **three-way** when a curl-impersonate binary is installed:
  honest (tool UA) / browser (Chrome headers, Node TLS) / impersonated (real
  Chrome TLS + HTTP/2). Isolates identity vs transport discrimination —
  a Node-TLS block that the impersonated client passes is a TLS/JA3 gate;
  header spoofing alone will never fix it.
- curl-impersonate binaries are **auto-discovered on PATH** — the newest
  `curl_chromeNNN` wins (e.g. `curl_chrome150` beats `curl_chrome131`);
  `WHICHWAF_CURL_IMPERSONATE` pins one explicitly.
- `--session`: probe twice — without cookies, then honoring `set-cookie`.
  Distinguishes cookie-gated sessions (Imperva/Akamai pattern) from hard blocks.
- `--probe N [--delay ms]`: fire N identical requests, report the degradation
  point — volume/behavior gates fire at request N, identity gates at request 1.
- Redirects are now followed manually: the full hop chain is recorded and used
  as evidence (a 302 into a challenge path is a tell).

### Testing

- **Fixture corpus** (`fixtures/cases/`): raw HTTP dumps + expected verdicts,
  executed in `npm test`. Every live-target scenario once captured can never
  regress silently. See `fixtures/README.md` for how to add one.
