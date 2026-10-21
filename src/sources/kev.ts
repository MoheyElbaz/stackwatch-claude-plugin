// SPDX-License-Identifier: GPL-3.0-or-later
import { fetchCached } from '../http.ts';
import type { Source } from '../types.ts';

export interface KevEntry {
  cveID: string;
  vulnerabilityName?: string;
  dateAdded?: string;
}

/** CISA's catalog of vulnerabilities exploited in the wild, by CVE id. */
export type Kev = Map<string, KevEntry>;

export async function loadKev(source: Source, problems: string[], timeoutMs: number): Promise<Kev> {
  try {
    const res = await fetchCached(source.url, { ttlMs: (source.ttlMinutes ?? 360) * 60_000, timeoutMs });
    if (res.stale) problems.push(`${source.name}: unreachable, using the last copy`);
    return parseKev(res.body);
  } catch (error) {
    problems.push(`${source.name}: ${(error as Error).message}`);
    return new Map();
  }
}

export function parseKev(body: string): Kev {
  const catalog = JSON.parse(body) as { vulnerabilities?: KevEntry[] };
  return new Map((catalog.vulnerabilities ?? []).map((v) => [v.cveID, v]));
}
