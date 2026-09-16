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

export { probe } from './probe.js';
export type { ProbeResult } from './probe.js';
