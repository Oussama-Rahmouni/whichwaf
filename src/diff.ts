/**
 * DIFFERENTIAL PROBE — same URL, two client identities, one conclusion.
 *
 * Probe once with the honest whichwaf UA and once with a current Chrome profile,
 * then compare the verdicts. A stack that blocks the plain client but passes the
 * browser profile discriminates at the identity/transport layer — that's where the
 * fix goes. A stack that blocks both identically fires the challenge for everyone,
 * so fingerprint work alone won't help.
 */

import { probe, type ProbeResult } from './probe.js';
import { analyze, type Analysis } from './analyze.js';

export interface DiffResult {
  url: string;
  honest: { probe: ProbeResult; verdict: Analysis };
  browser: { probe: ProbeResult; verdict: Analysis };
  /** one-paragraph operator conclusion */
  summary: string;
}

export function classifyDiff(honest: Analysis, browser: Analysis): string {
  const h = honest.challenge.kind;
  const b = browser.challenge.kind;

  if (honest.blocked && browser.blocked && h === b) {
    return `Both profiles blocked by ${h} — the check fires regardless of client identity. Fingerprint work alone won't help; the ${honest.layer} layer challenge itself must be solved.`;
  }
  if (honest.blocked && browser.blocked) {
    return `Both profiles blocked, but differently (${h} vs ${b}) — the stack escalates based on client identity. The browser profile triggers the lighter check; start there.`;
  }
  if (honest.blocked && !browser.blocked) {
    return `Plain client blocked (${h}) while the browser profile passes — discrimination happens at identity/transport (UA, TLS, header order). A coherent browser fingerprint is the first fix, before any solver.`;
  }
  if (!honest.blocked && browser.blocked) {
    return `Browser profile blocked (${b}) while the plain client passes — unusual. The trigger is likely behavioral/session state tied to the browser path, not identity.`;
  }
  return 'No block for either profile. If production traffic still gets blocked, the trigger is volume or behavior over time, not the first request.';
}

export async function diffProbe(url: string, opts: { timeoutMs?: number } = {}): Promise<DiffResult> {
  const [honestProbe, browserProbe] = await Promise.all([
    probe(url, { ...opts, profile: 'honest' }),
    probe(url, { ...opts, profile: 'browser' }),
  ]);

  const honestVerdict = analyze({
    status: honestProbe.status,
    headers: honestProbe.headers,
    body: honestProbe.body,
    url: honestProbe.finalUrl,
  });
  const browserVerdict = analyze({
    status: browserProbe.status,
    headers: browserProbe.headers,
    body: browserProbe.body,
    url: browserProbe.finalUrl,
  });

  return {
    url,
    honest: { probe: honestProbe, verdict: honestVerdict },
    browser: { probe: browserProbe, verdict: browserVerdict },
    summary: classifyDiff(honestVerdict, browserVerdict),
  };
}
