// SPDX-License-Identifier: GPL-3.0-or-later
import { fetchCached } from '../http.ts';
import { compareVersions } from '../version.ts';
import { levelFromLabel } from '../cvss.ts';
import type { Component, Item, Source } from '../types.ts';
import type { Kev } from './kev.ts';

interface CpeMatch {
  vulnerable?: boolean;
  criteria?: string;
  versionStartIncluding?: string;
  versionStartExcluding?: string;
  versionEndExcluding?: string;
  versionEndIncluding?: string;
}

interface NvdCve {
  id: string;
  published?: string;
  vulnStatus?: string;
  descriptions?: { lang: string; value: string }[];
  metrics?: Record<string, { cvssData?: { baseScore?: number; baseSeverity?: string } }[]>;
  configurations?: { nodes?: { cpeMatch?: CpeMatch[] }[] }[];
}

/**
 * NVD's CVEs for the exact version of a runtime that was not installed by the OS (PHP or Apache
 * compiled by a panel, say): the distribution's advisories don't cover those. NVD allows few
 * requests without a key, so answers are cached for long and a quick refresh only reads the cache.
 */
export async function loadNvd(source: Source, cpe: string, version: string, problems: string[], timeoutMs: number, quick: boolean): Promise<NvdCve[]> {
  const url = `${source.url}?virtualMatchString=${encodeURIComponent(`cpe:2.3:a:${cpe}:${version}`)}&noRejected&resultsPerPage=2000`;
  const key = process.env.STACKWATCH_NVD_API_KEY;
  try {
    const res = await fetchCached(url, { ttlMs: (source.ttlMinutes ?? 720) * 60_000, timeoutMs: Math.max(timeoutMs, 30000), cacheOnly: quick, ...(key ? { headers: { apiKey: key } } : {}) });
    if (res.stale) problems.push(`${source.name} (${cpe}): unreachable, using the last copy`);
    return ((JSON.parse(res.body) as { vulnerabilities?: { cve: NvdCve }[] }).vulnerabilities ?? []).map((v) => v.cve);
  } catch (error) {
    if (!quick) problems.push(`${source.name} (${cpe}): ${(error as Error).message}`);
    return [];
  }
}

/** NVD answers 5 requests per 30 s without a key: space them out. */
export const NVD_SPACING_MS = process.env.STACKWATCH_NVD_API_KEY ? 700 : 6500;

export function nvdItems(source: Source, project: string, component: Component, cpe: string, cves: NvdCve[], kev: Kev, now: string): Item[] {
  return cves
    .filter((c) => c.vulnStatus !== 'Rejected')
    .map((cve) => {
      const exploited = kev.has(cve.id);
      const fixed = fixedFor(cve, cpe, component.version);
      const metric = ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'].map((k) => cve.metrics?.[k]?.[0]?.cvssData).find(Boolean);
      const description = cve.descriptions?.find((d) => d.lang === 'en')?.value ?? cve.id;
      return {
        id: `${source.id}:${project}:${component.name}:${cve.id}`,
        source: source.id,
        kind: 'finding' as const,
        title: description,
        url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
        published: cve.published ? new Date(cve.published).toISOString() : undefined,
        firstSeen: now,
        cves: [cve.id],
        versions: fixed ? [fixed] : [],
        level: exploited ? 'critical' : (levelFromLabel(metric?.baseSeverity) ?? 'medium'),
        exploited,
        confirmed: true,
        matches: [{ project, component: component.name, version: component.version, ...(fixed ? { fixed } : {}) }],
        read: false,
      };
    });
}

/** The first version NVD says is no longer affected, from the range that holds this version. */
function fixedFor(cve: NvdCve, cpe: string, version: string): string | undefined {
  for (const config of cve.configurations ?? []) {
    for (const node of config.nodes ?? []) {
      for (const m of node.cpeMatch ?? []) {
        if (!m.vulnerable || !m.criteria?.startsWith(`cpe:2.3:a:${cpe}:`) || !m.versionEndExcluding) continue;
        const above = m.versionStartIncluding ? compareVersions(version, m.versionStartIncluding) >= 0 : m.versionStartExcluding ? compareVersions(version, m.versionStartExcluding) > 0 : true;
        if (above && compareVersions(version, m.versionEndExcluding) < 0) return m.versionEndExcluding;
      }
    }
  }
  return undefined;
}
