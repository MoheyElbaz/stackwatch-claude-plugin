// SPDX-License-Identifier: GPL-3.0-or-later
import { fetchCached } from '../http.ts';
import { compareVersions } from '../version.ts';
import type { Component, Item, Source } from '../types.ts';

export interface EolRelease {
  name: string;
  isEol?: boolean;
  eolFrom?: string | null;
  latest?: { name: string; date?: string; link?: string | null } | null;
}

export async function loadEol(source: Source, product: string, problems: string[], timeoutMs: number): Promise<EolRelease[]> {
  try {
    const res = await fetchCached(source.url + encodeURIComponent(product), { ttlMs: (source.ttlMinutes ?? 360) * 60_000, timeoutMs });
    if (res.stale) problems.push(`${source.name} (${product}): unreachable, using the last copy`);
    return (JSON.parse(res.body) as { result?: { releases?: EolRelease[] } }).result?.releases ?? [];
  } catch (error) {
    problems.push(`${source.name} (${product}): ${(error as Error).message}`);
    return [];
  }
}

/** The release line a version belongs to: the longest release name it starts with ("10.11.6" -> "10.11"). */
export function releaseFor(version: string, releases: EolRelease[]): EolRelease | null {
  const v = version.replace(/^v/, '');
  return releases.filter((r) => v === r.name || v.startsWith(`${r.name}.`)).sort((a, b) => b.name.length - a.name.length)[0] ?? null;
}

/**
 * Is the release line still supported, and is a newer patch out? A newer patch alone is not proof
 * of a vulnerability, so it is medium; advisories come from the feeds and OSV.
 */
export function eolItems(source: Source, project: string, component: Component, product: string, releases: EolRelease[], now: string): Item[] {
  const release = releaseFor(component.version, releases);
  if (!release) return [];
  const page = `https://endoflife.date/${encodeURIComponent(product)}`;
  const item = (suffix: string, fields: Pick<Item, 'title' | 'level' | 'url' | 'published'> & { fixed?: string }): Item => ({
    id: `${source.id}:${project}:${component.name}:${suffix}`,
    source: source.id,
    kind: 'finding',
    title: fields.title,
    url: fields.url,
    published: fields.published,
    firstSeen: now,
    cves: [],
    versions: fields.fixed ? [fields.fixed] : [],
    level: fields.level,
    exploited: false,
    confirmed: true,
    matches: [{ project, component: component.name, version: component.version, ...(fields.fixed ? { fixed: fields.fixed } : {}) }],
    read: false,
  });

  const items: Item[] = [];
  if (release.isEol) {
    items.push(item(`${release.name}-eol`, {
      title: component.packaged
        ? `${component.name} ${release.name} reached its upstream end of life${release.eolFrom ? ` on ${release.eolFrom}` : ''}; this one is the OS's ${component.packaged} package, which may still get backported fixes: check the OS's support for it`
        : `${component.name} ${release.name} reached end of life${release.eolFrom ? ` on ${release.eolFrom}` : ''}: no more security fixes`,
      level: component.packaged ? 'medium' : 'high',
      url: page,
      published: release.eolFrom ?? undefined,
    }));
  }
  const latest = release.latest?.name;
  // An OS package keeps its version number while fixes are backported, so "newer upstream" says nothing.
  if (latest && component.exact !== false && !component.packaged && compareVersions(latest, component.version) > 0) {
    items.push(item(latest, {
      title: `${component.name} ${latest} is out; this runs ${component.version}`,
      level: 'medium',
      url: release.latest?.link || page,
      published: release.latest?.date,
      fixed: latest,
    }));
  }
  return items;
}
