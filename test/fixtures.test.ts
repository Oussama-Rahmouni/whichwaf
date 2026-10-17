/**
 * FIXTURE SUITE — every captured live-target scenario runs through the exact
 * classifier path used by `whichwaf --stdin`. A scenario once captured can
 * never silently regress.
 *
 * Add cases by dropping a pair into fixtures/cases/ — see fixtures/README.md.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseRawResponse } from '../src/raw.js';
import { analyze } from '../src/analyze.js';

const CASES_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'fixtures', 'cases');

interface Expectation {
  kind: string;
  blocked: boolean;
  layer: string;
  note?: string;
}

const cases = (await readdir(CASES_DIR)).filter((f) => f.endsWith('.http'));

test('fixtures: corpus is not empty', () => {
  assert.ok(cases.length > 0, 'no fixtures found — the corpus is the regression net');
});

for (const file of cases) {
  const name = file.replace(/\.http$/, '');
  test(`fixture: ${name}`, async () => {
    const raw = await readFile(join(CASES_DIR, file), 'utf8');
    const expect: Expectation = JSON.parse(await readFile(join(CASES_DIR, `${name}.expect.json`), 'utf8'));

    const verdict = analyze(parseRawResponse(raw));

    assert.equal(
      verdict.challenge.kind,
      expect.kind,
      `kind mismatch — expected ${expect.kind}, got ${verdict.challenge.kind} (${verdict.challenge.evidence})`,
    );
    assert.equal(verdict.blocked, expect.blocked, `blocked mismatch — expected ${expect.blocked}`);
    assert.equal(verdict.layer, expect.layer, `layer mismatch — expected ${expect.layer}, got ${verdict.layer}`);
  });
}
