/**
 * Public API.
 *
 *   import { analyze, detectChallenge, fingerprintVendors, probe } from 'whichwaf';
 */
export { detectChallenge } from './detect.js';
export type { ChallengeKind, ChallengeSignal, Confidence, DetectInput, SignalSource } from './detect.js';

export { fingerprintVendors, SIGNATURES } from './vendors.js';
export type { VendorHit, VendorKind, VendorSignature } from './vendors.js';

export { analyze } from './analyze.js';
export type { Analysis, Layer } from './analyze.js';

export { probe, probeImpersonate, probeWithSession, probeRepeat, findImpersonateBinary, pickImpersonateBinary } from './probe.js';
export type { ProbeResult, ProbeProfile, SessionProbe } from './probe.js';

export { diffProbe, classifyDiff } from './diff.js';
export type { DiffResult } from './diff.js';

export { classifySession, summarizeSequence } from './rounds.js';
export type { SequenceEntry } from './rounds.js';

export { parseRawResponse } from './raw.js';

export { scanUrls, computeStats, normalizeUrl, renderMarkdownReport } from './fleet.js';
export type { FleetResult, FleetRow, FleetStats } from './fleet.js';
