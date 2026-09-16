/**
 * ANALYZE — combine passive vendor fingerprinting with active challenge detection
 * into one verdict, and map the block to the layer that fired it.
 *
 * The layer model (identity → transport → session → browser → behavior → application)
 * is the diagnostic frame: a block happens at ONE layer, and the vendor's product
 * shape tells you which one to fix first.
 */

import { detectChallenge, type ChallengeKind, type ChallengeSignal, type DetectInput } from './detect.js';
import { fingerprintVendors, type VendorHit } from './vendors.js';

export type Layer =
  | 'identity'      // IP/ASN reputation
  | 'transport'     // TLS/JA3/JA4, HTTP/2 settings
  | 'session'       // cookies, clearance tokens
  | 'browser'       // JS challenge, fingerprint JS
  | 'behavior'      // timing, mouse, request patterns
  | 'application'   // API-level gating, CAPTCHA on action
  | 'none';

export interface Analysis {
  /** is THIS response a block/challenge, or clean? */
  blocked: boolean;
  challenge: ChallengeSignal;
  /** every vendor detected in the response, block or no block */
  vendors: VendorHit[];
  /** the layer most likely firing, given the vendor's product shape */
  layer: Layer;
  /** one-line operator hint */
  hint: string;
}

const LAYER_BY_KIND: Record<ChallengeKind, { layer: Layer; hint: string }> = {
  cloudflare: {
    layer: 'browser',
    hint: 'Managed/JS challenge. Check TLS fingerprint coherence first, then expect a JS turnstile-style check. A solved cf_clearance rides in cookies.',
  },
  datadome: {
    layer: 'behavior',
    hint: 'Behavioral + device fingerprint. Session continuity (same cookies, same fingerprint, human cadence) beats volume.',
  },
  perimeterx: {
    layer: 'behavior',
    hint: 'Sensor JS builds a behavioral score. Mobile SDK variant common on app APIs — consider the mobile endpoints.',
  },
  akamai: {
    layer: 'transport',
    hint: 'Edge TLS scoring + _abck sensor cookie. Fix the TLS fingerprint before anything else; the sensor cookie needs the JS to run.',
  },
  kasada: {
    layer: 'browser',
    hint: 'Client puzzle (ips.js) must execute. Headless-with-real-browser or a solved x-kpsdk token; no passive bypass.',
  },
  imperva: {
    layer: 'session',
    hint: 'Cookie-gated sessions with occasional JS challenge. Solve once, ride the incap_ses/visid cookies.',
  },
  awswaf: {
    layer: 'session',
    hint: 'AWS WAF challenge action. The aws-waf-token cookie IS the clearance — obtain it once, reuse it.',
  },
  turnstile: {
    layer: 'browser',
    hint: 'Turnstile token required for this action. Non-interactive but scored; token has a short TTL.',
  },
  recaptcha: {
    layer: 'application',
    hint: 'reCAPTCHA on the action, not the page. v3: score follows your session quality. v2: solve per action.',
  },
  hcaptcha: {
    layer: 'application',
    hint: 'hCaptcha on the action. Token per request; enterprise variant scores passively.',
  },
  funcaptcha: {
    layer: 'application',
    hint: 'Arkose challenge on the action. Interactive and expensive — avoid triggering it rather than solving it.',
  },
  'captcha-generic': {
    layer: 'application',
    hint: 'Unidentified CAPTCHA. Capture the full response and identify the widget source manually.',
  },
  none: { layer: 'none', hint: 'No active block detected in this response.' },
};

export function analyze(input: DetectInput): Analysis {
  const challenge = detectChallenge(input);
  const vendors = fingerprintVendors(input);
  const blocked = challenge.kind !== 'none' && challenge.confidence !== 'low';
  const { layer, hint } = LAYER_BY_KIND[challenge.kind];
  return { blocked, challenge, vendors, layer, hint };
}
