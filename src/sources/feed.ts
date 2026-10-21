// SPDX-License-Identifier: GPL-3.0-or-later
import { XMLParser } from 'fast-xml-parser';
import { fetchCached } from '../http.ts';
import type { Source } from '../types.ts';

/** One entry of any RSS 2.0, RSS 1.0 (RDF) or Atom feed. */
export interface FeedItem {
  guid: string;
  title: string;
  url: string;
  published?: string;
  text: string;
}

export async function loadFeed(source: Source, timeoutMs: number, problems: string[]): Promise<FeedItem[] | null> {
  try {
    const res = await fetchCached(source.url, { ttlMs: (source.ttlMinutes ?? 60) * 60_000, timeoutMs });
    if (res.stale) problems.push(`${source.name}: unreachable, using the last copy`);
    return parseFeed(res.body);
  } catch (error) {
    problems.push(`${source.name}: ${(error as Error).message}`);
    return null;
  }
}

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@',
  removeNSPrefix: true,
  // Bodies are HTML or XHTML; keep them as raw text and flatten them ourselves.
  stopNodes: ['*.content', '*.summary', '*.description', '*.encoded'],
  isArray: (name) => name === 'item' || name === 'entry' || name === 'link',
});

export function parseFeed(xml: string): FeedItem[] {
  const doc = parser.parse(xml) as Record<string, any>;
  const entries: Record<string, unknown>[] = doc.rss?.channel?.item ?? doc.feed?.entry ?? doc.RDF?.item ?? [];
  return entries
    .map((e) => {
      const url = linkOf((e.link as unknown[]) ?? []);
      const title = plain(textOf(e.title));
      return {
        guid: textOf(e.guid) || textOf(e.id) || url || title,
        title,
        url,
        published: isoDate(textOf(e.pubDate) || textOf(e.published) || textOf(e.updated) || textOf(e.date)),
        text: plain(textOf(e.encoded) || textOf(e.content) || textOf(e.description) || textOf(e.summary)),
      };
    })
    .filter((i) => i.title || i.url);
}

/** Atom: <link rel="alternate" href>; RSS: <link>url</link>. */
function linkOf(links: unknown[]): string {
  const attr = (l: unknown) => (l && typeof l === 'object' ? (l as Record<string, string>) : null);
  const alternate = links.map(attr).find((l) => l?.['@href'] && (l['@rel'] ?? 'alternate') === 'alternate');
  if (alternate) return alternate['@href']!;
  const text = links.map(textOf).find((t) => t.trim());
  if (text) return text.trim();
  return links.map(attr).find((l) => l?.['@href'])?.['@href'] ?? '';
}

function textOf(value: unknown): string {
  if (value == null) return '';
  if (typeof value === 'string' || typeof value === 'number') return String(value);
  if (Array.isArray(value)) return textOf(value[0]);
  if (typeof value === 'object') return textOf((value as Record<string, unknown>)['#text']);
  return '';
}

/** HTML (escaped or not, in CDATA or not) to one line of plain text. */
export function plain(html: string): string {
  const once = decode(html.replace(/<!\[CDATA\[|\]\]>/g, '')).replace(/<[^>]*>/g, ' ');
  return decode(once).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
}

function decode(text: string): string {
  return text
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => safeChar(Number.parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => safeChar(Number.parseInt(d, 10)))
    .replace(/&(lt|gt|quot|apos|nbsp|#39);/g, (_, e: string) => ({ lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ', '#39': "'" })[e]!)
    .replace(/&amp;/g, '&');
}

function safeChar(code: number): string {
  return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : ' ';
}

function isoDate(text: string): string | undefined {
  const time = Date.parse(text);
  return Number.isNaN(time) ? undefined : new Date(time).toISOString();
}
