/**
 * DIFFERENTIAL PROBE — same URL, up to three client identities, one conclusion.
 *
 *   honest       — the whichwaf UA over Node's TLS stack
 *   browser      — Chrome HEADERS, but still Node's TLS/HTTP2 fingerprint
 *   impersonated — curl-impersonate, real Chrome TLS ClientHello + HTTP/2
 *                  (only when a curl-impersonate binary is installed)
 *
 * The key insight: `browser` spoofs headers but shares `honest`'s transport
 * fingerprint. A stack that blocks BOTH but passes `impersonated` gates on
 * TLS/JA3/JA4 or HTTP/2 — header spoofing alone will never fix that. A stack
 * that blocks `honest` but passes `browser` discriminates on identity (UA,
 * headers). A stack that blocks all three challenges everyone.
 */

import { probe, probeImpersonate, findImpersonateBinary, browserHeadersForImpersonate, type ProbeResult } from './probe.js';
import { analyze, type Analysis } from './analyze.js';

export interface DiffResult {
  url: string;
  honest: { probe: ProbeResult; verdict: Analysis };
  browser: { probe: ProbeResult; verdict: Analysis };
  /** present only when a curl-impersonate binary was found on PATH */
  impersonated?: { probe: ProbeResult; verdict: Analysis; binary: string };
  /** one-paragraph operator conclusion */
  summary: string;
}

export function classifyDiff(
  honest: Analysis,
  browser: Analysis,
  impersonated?: Analysis,
): string {
  const h = honest.challenge.kind;
  const b = browser.challenge.kind;

  // ── Three-way: the transport fingerprint is the variable under test ───────
  if (impersonated) {
    const blockedCount = [honest, browser, impersonated].filter((v) => v.blocked).length;

    if (honest.blocked && browser.blocked && !impersonated.blocked) {
      return (
        `Node-TLS probes blocked (${h === b ? h : `${h}/${b}`}) but the TLS-impersonated client passes clean — ` +
        `the stack discriminates at the TRANSPORT layer (TLS JA3/JA4, HTTP/2 SETTINGS). ` +
        `Spoofing headers is not enough: ship requests through curl-impersonate or a real browser, ` +
        `or replay the target browser's ClientHello in your HTTP stack.`
      );
    }
    if (honest.blocked && !browser.blocked && !impersonated.blocked) {
      return (
        `Plain client blocked (${h}) while the browser-header and TLS-impersonated profiles pass — ` +
        `identity discrimination confirmed. The two Node-TLS probes isolate the UA / header set; ` +
        `transport is not the differentiator in this matrix.`
      );
    }
    if (blockedCount === 3) {
      return (
        `All three identities blocked (honest: ${h}, browser: ${b}, impersonated: ${impersonated.challenge.kind}) — ` +
        `the check fires regardless of transport fingerprint AND headers. The gate is above transport: ` +
        `IP/ASN reputation, a session token, or an active challenge that must be solved.`
      );
    }
    if (!honest.blocked && !browser.blocked && impersonated.blocked) {
      return (
        `Only the TLS-impersonated profile was blocked (${impersonated.challenge.kind}) — unusual. ` +
        `The stack may score the browser path harder (it expects browser traffic to carry cookies/JS state).`
      );
    }
    if (!honest.blocked && !browser.blocked && !impersonated.blocked) {
      return 'No block for any identity, including the TLS-impersonated one. If production traffic still gets blocked, the trigger is volume, behavior over time, or a session token — not the first request.';
    }
    // mixed: e.g. honest clean, browser blocked, impersonated clean
    return (
      `Mixed verdicts (honest: ${h}${honest.blocked ? ' blocked' : ' clean'}, browser: ${b}${browser.blocked ? ' blocked' : ' clean'}, ` +
      `impersonated: ${impersonated.challenge.kind}${impersonated.blocked ? ' blocked' : ' clean'}) — ` +
      `the stack scores identity signals inconsistently; treat the impersonated verdict as ground truth for browser traffic.`
    );
  }

  // ── Two-way fallback (no curl-impersonate installed) ─────────────────────
  if (honest.blocked && browser.blocked && h === b) {
    return `Both profiles blocked by ${h} — the check fires regardless of client identity. Fingerprint work alone won't help; the ${honest.layer} layer challenge itself must be solved. (No curl-impersonate binary found — transport-layer discrimination can't be ruled out; install curl-impersonate to test it.)`;
  }
  if (honest.blocked && browser.blocked) {
    return `Both profiles blocked, but differently (${h} vs ${b}) — the stack escalates based on client identity. The browser profile triggers the lighter check; start there.`;
  }
  if (honest.blocked && !browser.blocked) {
    return (
      `Plain client blocked (${h}) while the browser profile passes — identity discrimination confirmed. ` +
      `Both probes shared Node's TLS fingerprint, so transport is exonerated: the gate keys on the UA / header set. ` +
      `Shipping coherent browser headers is the fix; no TLS work needed.`
    );
  }
  if (!honest.blocked && browser.blocked) {
    return `Browser profile blocked (${b}) while the plain client passes — unusual. The trigger is likely behavioral/session state tied to the browser path, not identity.`;
  }
  return 'No block for either profile. If production traffic still gets blocked, the trigger is volume or behavior over time, not the first request. (Both probes share Node\'s TLS fingerprint — a transport-layer gate that lets both through would look exactly like this.)';
}

export async function diffProbe(url: string, opts: { timeoutMs?: number } = {}): Promise<DiffResult> {
  const impersonateBin = await findImpersonateBinary();
  const browserHeaders = browserHeadersForImpersonate(impersonateBin);

  const [honestProbe, browserProbe, impersonatedProbe] = await Promise.all([
    probe(url, { ...opts, profile: 'honest' }),
    probe(url, { ...opts, profile: 'browser', extraHeaders: browserHeaders }),
    impersonateBin
      ? probeImpersonate(url, impersonateBin, { ...opts, extraHeaders: browserHeaders }).catch(() => null)
      : Promise.resolve(null),
  ]);

  const toVerdict = (p: ProbeResult): Analysis =>
    analyze({
      status: p.status,
      headers: p.headers,
      body: p.body,
      url: p.finalUrl,
      redirectChain: p.redirectChain,
      elapsedMs: p.elapsedMs,
    });

  const honestVerdict = toVerdict(honestProbe);
  const browserVerdict = toVerdict(browserProbe);
  const impersonatedVerdict = impersonatedProbe ? toVerdict(impersonatedProbe) : undefined;

  return {
    url,
    honest: { probe: honestProbe, verdict: honestVerdict },
    browser: { probe: browserProbe, verdict: browserVerdict },
    impersonated:
      impersonatedProbe && impersonatedVerdict
        ? { probe: impersonatedProbe, verdict: impersonatedVerdict, binary: impersonateBin! }
        : undefined,
    summary: classifyDiff(honestVerdict, browserVerdict, impersonatedVerdict),
  };
}
