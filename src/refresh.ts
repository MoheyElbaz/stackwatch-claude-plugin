// SPDX-License-Identifier: GPL-3.0-or-later
import { createHash } from 'node:crypto';
import { mapLimit } from './http.ts';
import { classify, extractFacts, productOf } from './match.ts';
import { loadRegistry } from './registry.ts';
import { eolItems, loadEol, type EolRelease } from './sources/endoflife.ts';
import { loadFeed, type FeedItem } from './sources/feed.ts';
import { loadKev, type Kev } from './sources/kev.ts';
import { NVD_SPACING_MS, loadNvd, nvdItems } from './sources/nvd.ts';
import { osvItem, queryOsv } from './sources/osv.ts';
import { componentsOf, loadData, updateData } from './store.ts';
import { LEVELS, type Item, type Level, type Registry, type Source, type Stack } from './types.ts';

const DAY = 24 * 3600_000;
const TEXT_LIMIT = 1500;
const MAX_ITEMS = 4000;
/** Products that are the operating system: news about them is checked against the OS's own advisories. */
const OS_PRODUCTS = new Set(['almalinux', 'rocky-linux', 'debian', 'ubuntu']);

export interface RefreshResult {
  items: Item[];
  added: Item[];
  problems: string[];
  refreshedAt: string;
}

export interface RefreshOptions {
  timeoutMs?: number;
  /** For a session that is starting: slow sources (NVD) answer from cache only. */
  quick?: boolean;
}

/**
 * Reads every source in sources.json, recomputes the findings (OSV, NVD, endoflife.date) for the
 * current stacks, merges the news into the store and re-matches all of it, and saves. Read marks
 * are kept by id, including ones made while this ran.
 */
export async function refresh(options: RefreshOptions = {}): Promise<RefreshResult> {
  const timeoutMs = options.timeoutMs ?? 15000;
  const registry = loadRegistry();
  const start = loadData();
  const stacks = Object.values(start.stacks);
  const problems: string[] = [];
  const now = new Date().toISOString();
  const firstRun = !start.lastRefresh;

  const kevSource = registry.sources.find((s) => s.type === 'kev');
  const kev: Kev = kevSource ? await loadKev(kevSource, problems, timeoutMs) : new Map();

  const feeds = registry.sources.filter((s) => s.type === 'feed');
  const [fetched, findings] = await Promise.all([
    mapLimit(feeds, 8, (s) => loadFeed(s, timeoutMs, problems)),
    computeFindings(registry, stacks, kev, start.items, problems, timeoutMs, now, !!options.quick),
  ]);

  const stored = new Map(start.items.filter((i) => i.kind === 'news').map((i) => [i.id, i]));
  feeds.forEach((source, i) => {
    for (const entry of fetched[i] ?? []) {
      const item = newsItem(source, entry, stored.get(newsId(source, entry)), now);
      stored.set(item.id, item);
    }
  });
  const news = matchNews([...stored.values()], registry, stacks, kev, now, firstRun, false, openOsCves(stacks, findings));
  const items = retain([...news, ...findings], Date.parse(now));

  const saved = updateData((current) => {
    const latest = new Map(current.items.map((i) => [i.id, i]));
    current.items = items.map((i) => {
      const other = latest.get(i.id);
      return other?.read && !i.read ? { ...i, read: true, readAt: other.readAt, note: other.note } : i;
    });
    current.lastRefresh = now;
    current.problems = [...new Set(problems)];
    return current.items;
  });

  return { items: saved, added: saved.filter((i) => i.firstSeen === now), problems: [...new Set(problems)], refreshedAt: now };
}

/** Re-matches stored news against the current stacks without fetching anything (after a stack changes). */
export function rematch(items: Item[], stacks: Stack[]): Item[] {
  const registry = loadRegistry();
  const now = new Date().toISOString();
  const findings = items.filter((i) => i.kind === 'finding');
  return [...matchNews(items.filter((i) => i.kind === 'news'), registry, stacks, new Map(), now, false, true, openOsCves(stacks, findings)), ...findings];
}

function newsId(source: Source, entry: FeedItem): string {
  return `${source.id}:${createHash('sha256').update(entry.guid).digest('hex').slice(0, 12)}`;
}

function newsItem(source: Source, entry: FeedItem, previous: Item | undefined, now: string): Item {
  return {
    id: newsId(source, entry),
    source: source.id,
    kind: 'news',
    title: entry.title,
    url: entry.url,
    published: entry.published,
    firstSeen: previous?.firstSeen ?? now,
    ...extractFacts(entry.title, entry.text),
    text: entry.text.slice(0, TEXT_LIMIT),
    level: previous?.level ?? 'info',
    exploited: previous?.exploited ?? false,
    confirmed: previous?.confirmed ?? true,
    matches: previous?.matches ?? [],
    read: previous?.read ?? false,
    ...(previous?.readAt ? { readAt: previous.readAt } : {}),
    ...(previous?.note ? { note: previous.note } : {}),
  };
}

/**
 * For each project whose server packages are known: the CVEs its OS advisories still list as open.
 * A news item about an OS CVE outside that set is about something already patched there.
 */
function openOsCves(stacks: Stack[], findings: Item[]): Map<string, Set<string>> {
  const out = new Map<string, Set<string>>();
  for (const stack of stacks) {
    const osPackages = new Set((stack.probed ?? []).filter((c) => c.ecosystem && c.ecosystem.includes(':')).map((c) => c.name));
    if (!osPackages.size) continue;
    const cves = new Set<string>();
    for (const f of findings) for (const m of f.matches) if (m.project === stack.project && osPackages.has(m.component)) f.cves.forEach((c) => cves.add(c));
    out.set(stack.project, cves);
  }
  return out;
}

function matchNews(items: Item[], registry: Registry, stacks: Stack[], kev: Kev, now: string, firstRun: boolean, keepExploited: boolean, osCves: Map<string, Set<string>>): Item[] {
  const sources = new Map(registry.sources.map((s) => [s.id, s]));
  const bySource = new Map<string, Item[]>();
  for (const item of items) bySource.set(item.source, [...(bySource.get(item.source) ?? []), item]);
  const productByComponent = new Map(stacks.flatMap((s) => componentsOf(s).map((c) => [`${s.project}:${c.name}`, productOf(c, registry)] as const)));

  const out: Item[] = [];
  for (const [sourceId, group] of bySource) {
    const source = sources.get(sourceId);
    if (!source) continue; // removed from sources.json: its news goes with it
    for (const item of group) {
      const result = classify(item, source, stacks, registry, kev, group);
      // The server's own advisories say the OS has this CVE fixed: the news no longer concerns it.
      const matches = result.matches.filter((m) => {
        const open = osCves.get(m.project);
        const product = productByComponent.get(`${m.project}:${m.component}`);
        return !(open && product && OS_PRODUCTS.has(product) && item.cves.length && !item.cves.some((c) => open.has(c)));
      });
      const patched = matches.length < result.matches.length && !matches.length;
      // Without a KEV copy (a re-match), keep what the last refresh learned from it.
      const exploited = result.exploited || (keepExploited && item.exploited);
      const level: Level = patched ? 'low' : exploited && matches.length ? 'critical' : result.level;
      const next: Item = { ...item, ...result, matches, exploited, level };
      // The first refresh pulls in months of background news; only what concerns the user starts unread.
      if (firstRun && item.firstSeen === now && !next.matches.length) next.read = true;
      out.push(next);
    }
  }
  return out;
}

async function computeFindings(registry: Registry, stacks: Stack[], kev: Kev, previous: Item[], problems: string[], timeoutMs: number, now: string, quick: boolean): Promise<Item[]> {
  const before = new Map(previous.filter((i) => i.kind === 'finding').map((i) => [i.id, i]));
  const keep = (item: Item): Item => {
    const old = before.get(item.id);
    return old ? { ...item, firstSeen: old.firstSeen, read: old.read, ...(old.readAt ? { readAt: old.readAt } : {}), ...(old.note ? { note: old.note } : {}) } : item;
  };
  const items: Item[] = [];

  const osv = registry.sources.find((s) => s.type === 'osv');
  const eol = registry.sources.find((s) => s.type === 'endoflife');
  const nvd = registry.sources.find((s) => s.type === 'nvd');
  const releases = new Map<string, Promise<EolRelease[]>>();
  let lastNvd = 0;

  for (const stack of stacks) {
    const components = componentsOf(stack);
    if (osv) {
      for (const [component, records] of await queryOsv(osv, components, problems, timeoutMs)) {
        for (const record of records) items.push(keep(osvItem(osv, stack.project, component, record, kev, now)));
      }
    }
    for (const component of components.filter((c) => c.product)) {
      const product = productOf(component, registry)!;
      const info = registry.products[product];
      if (eol && info && info.endoflife !== false) {
        const eolId = info?.endoflife || product;
        if (!releases.has(eolId)) releases.set(eolId, loadEol(eol, eolId, problems, timeoutMs));
        for (const item of eolItems(eol, stack.project, component, eolId, await releases.get(eolId)!, now)) items.push(keep(item));
      }
      // An OS package's CVEs come from the OS advisories (OSV above); NVD is for what was built by hand or a panel.
      if (nvd && info?.cpe && !component.packaged && component.exact !== false) {
        for (const cpe of info.cpe) {
          if (!quick) await new Promise((r) => setTimeout(r, Math.max(0, lastNvd + NVD_SPACING_MS - Date.now())));
          const cves = await loadNvd(nvd, cpe, component.version, problems, timeoutMs, quick);
          if (!quick) lastNvd = Date.now();
          for (const item of nvdItems(nvd, stack.project, component, cpe, cves, kev, now)) items.push(keep(item));
        }
      }
    }
  }
  return items;
}

/** Findings always stay (they leave when fixed). News: what concerns you for a year, the rest for 30 days. */
function retain(items: Item[], now: number): Item[] {
  const rank = (l: Level) => LEVELS.indexOf(l);
  const kept = items.filter((i) => {
    if (i.kind === 'finding') return true;
    const age = now - Date.parse(i.published ?? i.firstSeen);
    return i.matches.length && rank(i.level) <= rank('medium') ? age < 365 * DAY : age < 30 * DAY;
  });
  return kept
    .sort((a, b) => Number(b.kind === 'finding') - Number(a.kind === 'finding') || rank(a.level) - rank(b.level) || (b.published ?? '').localeCompare(a.published ?? ''))
    .slice(0, MAX_ITEMS);
}
