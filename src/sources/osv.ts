// SPDX-License-Identifier: GPL-3.0-or-later
import { cvss3Score, levelFromLabel, levelFromScore } from '../cvss.ts';
import { fetchCached, mapLimit } from '../http.ts';
import { isReleaseVersion } from '../version.ts';
import type { Component, Item, Level, Source } from '../types.ts';
import type { Kev } from './kev.ts';

const HOUR = 3600_000;
const BATCH = 500;

export interface OsvRecord {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  published?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: {
    package?: { name?: string; ecosystem?: string };
    ranges?: { events?: { introduced?: string; fixed?: string }[] }[];
  }[];
}

/** Every vulnerability OSV knows for the exact versions given. */
export async function queryOsv(source: Source, components: Component[], problems: string[], timeoutMs: number): Promise<Map<Component, OsvRecord[]>> {
  const checkable = components.filter((c) => c.ecosystem && isReleaseVersion(c.version));
  const hits: { component: Component; id: string; modified: string }[] = [];

  for (let i = 0; i < checkable.length; i += BATCH) {
    const chunk = checkable.slice(i, i + BATCH);
    const body = JSON.stringify({
      queries: chunk.map((c) => ({ package: { name: c.name, ecosystem: c.ecosystem }, version: c.version.replace(/^v(?=\d)/, '') })),
    });
    try {
      const res = await fetchCached(`${source.url}/querybatch`, { method: 'POST', body, ttlMs: (source.ttlMinutes ?? 60) * 60_000, timeoutMs });
      if (res.stale) problems.push(`${source.name}: unreachable, package results are from the last successful check`);
      const parsed = JSON.parse(res.body) as { results: { vulns?: { id: string; modified: string }[] }[] };
      parsed.results.forEach((r, j) => r.vulns?.forEach((v) => hits.push({ component: chunk[j]!, id: v.id, modified: v.modified })));
    } catch (error) {
      problems.push(`${source.name}: ${(error as Error).message}`);
    }
  }

  // Distribution bug-fix and enhancement advisories (ALBA, RLBA, ...) are not security issues.
  const security = hits.filter((h) => !/^(AL|RL|RH)[BE]A-/.test(h.id));
  hits.length = 0;
  hits.push(...security);
  const records = new Map<string, OsvRecord>();
  const unique = [...new Map(hits.map((h) => [h.id, h])).values()];
  await mapLimit(unique, 8, async (h) => {
    try {
      // A record only changes when OSV's "modified" does, so that is part of the cache key.
      const res = await fetchCached(`${source.url}/vulns/${encodeURIComponent(h.id)}`, { ttlMs: 30 * 24 * HOUR, timeoutMs, cacheKey: `osv-${h.id}-${h.modified}` });
      records.set(h.id, JSON.parse(res.body) as OsvRecord);
    } catch (error) {
      problems.push(`${source.name} ${h.id}: ${(error as Error).message}`);
    }
  });

  const out = new Map<Component, OsvRecord[]>();
  for (const h of hits) out.set(h.component, [...(out.get(h.component) ?? []), records.get(h.id) ?? { id: h.id }]);
  return out;
}

export function osvItem(source: Source, project: string, component: Component, record: OsvRecord, kev: Kev, now: string): Item {
  const aliases = (record.aliases ?? []).filter((a) => a !== record.id);
  const cves = [record.id, ...aliases].filter((id) => id.startsWith('CVE-'));
  const exploited = cves.some((cve) => kev.has(cve));
  const fixed = fixedVersions(record, component);

  return {
    id: `${source.id}:${project}:${component.name}:${record.id}`,
    source: source.id,
    kind: 'finding',
    title: record.summary || firstLine(record.details) || record.id,
    url: `https://osv.dev/vulnerability/${encodeURIComponent(record.id)}`,
    published: record.published,
    firstSeen: now,
    cves,
    versions: fixed,
    ids: [record.id, ...aliases].filter((id) => !id.startsWith('CVE-')),
    level: exploited ? 'critical' : osvLevel(record),
    exploited,
    confirmed: true,
    matches: [{
      project, component: component.name, version: component.version,
      ...(fixed[0] ? { fixed: fixed[0] } : {}), ...(component.dev ? { dev: true } : {}),
      ...(component.ecosystem?.includes(':') ? { os: component.ecosystem } : {}),
    }],
    read: false,
  };
}

/**
 * GitHub's reviewed label when there is one, then a distribution's own rating ("Important: kernel
 * security update"), then the CVSS v3 score; unknown counts as medium.
 */
export function osvLevel(record: OsvRecord): Level {
  const label = levelFromLabel(record.database_specific?.severity);
  if (label) return label;
  const rating = record.summary?.match(/^(Critical|Important|Moderate|Low):/)?.[1];
  if (rating) return ({ Critical: 'critical', Important: 'high', Moderate: 'medium', Low: 'low' } as const)[rating as 'Critical'];
  for (const s of record.severity ?? []) {
    const score = cvss3Score(s.score);
    if (score !== null) return levelFromScore(score);
  }
  return 'medium';
}

function fixedVersions(record: OsvRecord, component: Component): string[] {
  const fixed = new Set<string>();
  for (const a of record.affected ?? []) {
    if (a.package?.name !== component.name) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) fixed.add(e.fixed);
  }
  return [...fixed];
}

function firstLine(text: string | undefined): string {
  return (text ?? '').split('\n').find((l) => l.trim())?.trim() ?? '';
}
