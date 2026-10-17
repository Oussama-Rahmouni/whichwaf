/**
 * ROUNDS — pure classifiers over multi-request probe results.
 *
 * A single request is blind in two dimensions. These functions read what a
 * sequence of probes says along each:
 *
 *   STATE  — probeWithSession: does honoring set-cookie lift the gate?
 *   TIME   — probeRepeat: does request N get blocked when request 1 was clean?
 */

import type { Analysis } from './analyze.js';

/**
 * Interpret a session probe: first request without cookies, second carrying
 * whatever the first set.
 */
export function classifySession(
  first: Analysis,
  second: Analysis | null,
  cookieLoop: boolean,
): string {
  if (cookieLoop) {
    return (
      `The redirect chain revisits the same URL while setting cookies — a cookie-roundtrip gate. ` +
      `Clients that don't persist cookies loop forever; clients that do, pass. Honor the set-cookie and replay.`
    );
  }
  if (second === null) {
    return 'No cookies were set — the response does not attempt session setup. The verdict stands on a single stateless request.';
  }
  if (first.blocked && !second.blocked) {
    return (
      `Blocked without cookies, clean once the set-cookie is honored — a cookie-gated session (Imperva/Akamai pattern). ` +
      `Solve once, ride the session cookies; no transport or solver work needed.`
    );
  }
  if (first.blocked && second.blocked) {
    const same = first.challenge.kind === second.challenge.kind;
    return (
      `Block persists after honoring cookies (${same ? second.challenge.kind : `${first.challenge.kind} → ${second.challenge.kind}`}) — ` +
      `not a simple cookie gate. The block is keyed on transport, identity, or an active challenge that cookies alone don't clear.`
    );
  }
  if (!first.blocked && second.blocked) {
    return 'Clean without cookies but blocked with them — the issued cookie is itself a flag (poisoned session). Discard and re-fetch cookies per session.';
  }
  return 'Clean with and without cookies — no session gate on this path.';
}

export interface SequenceEntry {
  status: number;
  blocked: boolean;
  kind: string;
  elapsedMs: number;
}

/**
 * Interpret a repeat probe: N identical requests at a fixed cadence.
 * The transition point IS the diagnosis — a gate that fires at request 7 is
 * counting; a gate that fires at request 1 is fingerprinting.
 */
export function summarizeSequence(seq: SequenceEntry[]): string {
  if (seq.length === 0) return 'no probes ran';

  const firstBlocked = seq.findIndex((e) => e.blocked);

  if (firstBlocked === -1) {
    const statuses = [...new Set(seq.map((e) => e.status))].join('/');
    return `${seq.length}/${seq.length} clean (status ${statuses}) — no volume trigger within ${seq.length} requests at this cadence. If production still degrades, the threshold is higher or the trigger is behavioral over longer windows.`;
  }

  if (firstBlocked === 0 && seq.every((e) => e.blocked && e.kind === seq[0].kind)) {
    return `Blocked from request 1, every time (${seq[0].kind}) — not a volume gate. The trigger travels with the request itself: identity, transport, or an active challenge.`;
  }

  if (firstBlocked > 0 && seq.slice(firstBlocked).every((e) => e.blocked)) {
    return (
      `Clean for ${firstBlocked} request${firstBlocked === 1 ? '' : 's'}, then blocked from request ${firstBlocked + 1} onward ` +
      `(${seq[firstBlocked].kind}, status ${seq[firstBlocked].status}) — a volume/behavior gate with a threshold around ${firstBlocked} requests at this cadence. ` +
      `Spread load below that line or rotate egress.`
    );
  }

  const blockedN = seq.filter((e) => e.blocked).length;
  return `Unstable verdicts — ${blockedN}/${seq.length} blocked with no clean threshold. Adaptive scoring is in play; the gate reacts to more than simple request count.`;
}
