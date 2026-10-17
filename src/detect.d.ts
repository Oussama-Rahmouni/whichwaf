/**
 * CHALLENGE DETECTOR — pure classifier.
 *
 * Input: response status + headers + body (+ cookies). Output: which WAF/challenge,
 * if any, is sitting in front of the target.
 *
 * The critical property: PRESENCE of a WAF (embedded JS, benign headers on a 200) is
 * NOT a BLOCK. Misclassifying presence as a block sends clean traffic to solvers and
 * burns money; missing a real block loops forever.
 *
 * Each signal is small and additive (header tells > body tells). Returns the FIRST
 * positive match by priority — WAF blocks first, then CAPTCHA widgets, then "none".
 */
export type ChallengeKind = 'cloudflare' | 'vercel' | 'datadome' | 'perimeterx' | 'akamai' | 'kasada' | 'imperva' | 'awswaf' | 'distil' | 'queueit' | 'sucuri' | 'wordfence' | 'f5bigip' | 'ddosguard' | 'modsecurity' | 'radware' | 'reblaze' | 'turnstile' | 'recaptcha' | 'hcaptcha' | 'funcaptcha' | 'geetest' | 'captcha-generic' | 'ratelimit' | 'unknown-gate' | 'none';
export type Confidence = 'high' | 'medium' | 'low';
export type SignalSource = 'status' | 'header' | 'cookie' | 'body' | 'multi';
export interface ChallengeSignal {
    kind: ChallengeKind;
    confidence: Confidence;
    source: SignalSource;
    evidence: string;
}
export interface DetectInput {
    status: number;
    headers: Record<string, string | string[] | undefined>;
    body: string;
    url?: string;
    /** every hop the probe followed, oldest first (includes the final URL) */
    redirectChain?: string[];
    /** response time — corroborating evidence: edge rejections are near-instant */
    elapsedMs?: number;
}
export declare function headerVal(headers: DetectInput['headers'], name: string): string | null;
export declare function hasHeader(headers: DetectInput['headers'], name: string): boolean;
export declare function detectChallenge(input: DetectInput): ChallengeSignal;
