#!/usr/bin/env node
/**
 * whichwaf CLI
 *
 *   whichwaf <url>              probe a URL, print the verdict
 *   whichwaf <url> --json       machine-readable verdict
 *   whichwaf --stdin            classify a captured raw HTTP response from stdin
 *   whichwaf --list             list every vendor signature
 *
 * Exit codes: 0 = no active block · 2 = block/challenge detected · 1 = usage/probe error
 */

import { analyze, type Analysis } from './analyze.js';
import { probe, type ProbeResult } from './probe.js';
import { diffProbe, type DiffResult } from './diff.js';
import { SIGNATURES } from './vendors.js';
import type { DetectInput } from './detect.js';

const BOLD = '[1m';
const DIM = '[2m';
const RED = '[31m';
const GREEN = '[32m';
const YELLOW = '[33m';
const PURPLE = '[35m';
const RESET = '[0m';

function usage(): never {
  console.log(`whichwaf — which anti-bot/WAF is protecting this site, and which layer blocks you

usage:
  whichwaf <url> [--json]     probe a URL and classify the response
  whichwaf <url> --diff       probe as plain client AND as browser, compare verdicts
  whichwaf --stdin [--json]   classify a raw HTTP response piped to stdin
  whichwaf --list             list every vendor signature
  whichwaf --help             this text

exit codes: 0 = clean · 2 = block/challenge detected · 1 = error`);
  process.exit(0);
}

/** Parse a raw HTTP response dump: status line, headers, blank line, body. */
function parseRawResponse(raw: string): DetectInput {
  const sep = raw.indexOf('\r\n\r\n') !== -1 ? '\r\n\r\n' : '\n\n';
  const [head, ...rest] = raw.split(sep);
  const body = rest.join(sep);
  const lines = head.split(/\r?\n/);
  const statusMatch = lines[0].match(/^HTTP\/[\d.]+\s+(\d+)/);
  const headers: Record<string, string> = {};
  for (const line of lines.slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return { status: statusMatch ? parseInt(statusMatch[1], 10) : 0, headers, body };
}

function printVerdict(a: Analysis, meta?: { url: string; finalUrl: string; status: number; elapsedMs: number }): void {
  if (meta) {
    console.log(`${DIM}${meta.url}${meta.finalUrl !== meta.url ? ` → ${meta.finalUrl}` : ''}${RESET}`);
    console.log(`${DIM}status ${meta.status} · ${meta.elapsedMs}ms${RESET}`);
    console.log();
  }

  const { challenge } = a;
  if (a.blocked) {
    console.log(`${RED}${BOLD}BLOCKED${RESET} — ${BOLD}${challenge.kind}${RESET} (${challenge.confidence} confidence)`);
  } else if (challenge.kind !== 'none') {
    console.log(`${YELLOW}${BOLD}PRESENT${RESET} — ${BOLD}${challenge.kind}${RESET} detected but not blocking this response (${challenge.confidence})`);
  } else {
    console.log(`${GREEN}${BOLD}CLEAN${RESET} — no active challenge in this response`);
  }
  console.log(`  evidence: ${challenge.evidence}`);

  if (a.vendors.length > 0) {
    console.log();
    console.log(`${PURPLE}stack:${RESET}`);
    for (const v of a.vendors) {
      console.log(`  ${BOLD}${v.name}${RESET} ${DIM}(${v.kind})${RESET}`);
      for (const e of v.evidence.slice(0, 4)) console.log(`    ${DIM}·${RESET} ${e}`);
      console.log(`    ${DIM}${v.note}${RESET}`);
    }
  }

  if (a.blocked) {
    console.log();
    console.log(`${PURPLE}layer:${RESET} ${a.layer}`);
    console.log(`${DIM}${a.hint}${RESET}`);
  }
}

function verdictLine(label: string, p: ProbeResult, a: Analysis): void {
  const tag = a.blocked
    ? `${RED}${BOLD}BLOCKED${RESET} — ${BOLD}${a.challenge.kind}${RESET} (${a.challenge.confidence})`
    : a.challenge.kind !== 'none'
      ? `${YELLOW}${BOLD}PRESENT${RESET} — ${a.challenge.kind} not blocking`
      : `${GREEN}${BOLD}CLEAN${RESET}`;
  console.log(`${label}  ${tag} ${DIM}· status ${p.status} · ${p.elapsedMs}ms${RESET}`);
}

function printDiff(d: DiffResult): void {
  console.log(`${DIM}${d.url}${RESET}`);
  console.log();
  verdictLine('honest  (whichwaf UA):', d.honest.probe, d.honest.verdict);
  verdictLine('browser (chrome UA):  ', d.browser.probe, d.browser.verdict);
  console.log();
  console.log(`${PURPLE}diff:${RESET} ${d.summary}`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  if (args.length === 0 || args.includes('--help') || args.includes('-h')) usage();

  if (args.includes('--list')) {
    for (const s of SIGNATURES) {
      console.log(`${BOLD}${s.name}${RESET} ${DIM}(${s.kind})${RESET} — ${s.note}`);
    }
    process.exit(0);
  }

  const json = args.includes('--json');

  if (args.includes('--diff')) {
    const url = args.find((a) => !a.startsWith('--'));
    if (!url) usage();
    let diff: DiffResult;
    try {
      diff = await diffProbe(url);
    } catch (err) {
      console.error(`probe failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
    const anyBlocked = diff.honest.verdict.blocked || diff.browser.verdict.blocked;
    if (json) {
      const slim = (side: DiffResult['honest']) => ({
        status: side.probe.status,
        finalUrl: side.probe.finalUrl,
        elapsedMs: side.probe.elapsedMs,
        verdict: side.verdict,
      });
      console.log(
        JSON.stringify({ url: diff.url, honest: slim(diff.honest), browser: slim(diff.browser), summary: diff.summary }, null, 2),
      );
    } else {
      printDiff(diff);
    }
    process.exit(anyBlocked ? 2 : 0);
  }

  let input: DetectInput;
  let meta: { url: string; finalUrl: string; status: number; elapsedMs: number } | undefined;

  if (args.includes('--stdin')) {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
    input = parseRawResponse(Buffer.concat(chunks).toString('utf8'));
  } else {
    const url = args.find((a) => !a.startsWith('--'));
    if (!url) usage();
    try {
      const result = await probe(url);
      input = { status: result.status, headers: result.headers, body: result.body, url: result.finalUrl };
      meta = { url: result.url, finalUrl: result.finalUrl, status: result.status, elapsedMs: result.elapsedMs };
    } catch (err) {
      console.error(`probe failed: ${err instanceof Error ? err.message : String(err)}`);
      process.exit(1);
    }
  }

  const verdict = analyze(input);
  if (json) {
    console.log(JSON.stringify({ ...meta, ...verdict }, null, 2));
  } else {
    printVerdict(verdict, meta);
  }
  process.exit(verdict.blocked ? 2 : 0);
}

main();
