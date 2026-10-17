/**
 * RAW RESPONSE PARSER — shared by the CLI (--stdin) and the fixture corpus.
 *
 * Format: status line, headers, blank line, body — exactly what
 * `curl -sD - -o -` or a DevTools/mitmproxy dump produces.
 */

import type { DetectInput } from './detect.js';

export function parseRawResponse(raw: string): DetectInput {
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
