import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyDiff } from '../src/diff.js';
import type { Analysis } from '../src/analyze.js';
import type { ChallengeKind } from '../src/detect.js';

function verdict(kind: ChallengeKind, blocked: boolean): Analysis {
  return {
    blocked,
    challenge: { kind, confidence: 'high', source: 'status', evidence: 'test fixture' },
    vendors: [],
    layer: blocked ? 'transport' : 'none',
    hint: '',
  };
}

test('diff: transport conclusion requires BOTH Node-TLS profiles blocked', () => {
  const summary = classifyDiff(
    verdict('unknown-gate', true),
    verdict('unknown-gate', true),
    verdict('none', false),
  );
  assert.match(summary, /TRANSPORT layer/);
});

test('diff: honest blocked, browser and impersonated clean is identity, not transport', () => {
  const summary = classifyDiff(
    verdict('unknown-gate', true),
    verdict('none', false),
    verdict('none', false),
  );
  assert.match(summary, /identity discrimination confirmed/);
  assert.doesNotMatch(summary, /TRANSPORT layer/);
});

test('diff: browser-only block with impersonated clean stays mixed, not transport', () => {
  const summary = classifyDiff(
    verdict('none', false),
    verdict('vercel', true),
    verdict('none', false),
  );
  assert.match(summary, /Mixed verdicts/);
  assert.doesNotMatch(summary, /TRANSPORT layer/);
});

test('diff: all three blocked is above transport', () => {
  const summary = classifyDiff(
    verdict('vercel', true),
    verdict('vercel', true),
    verdict('vercel', true),
  );
  assert.match(summary, /above transport/);
});
