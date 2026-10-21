// SPDX-License-Identifier: GPL-3.0-or-later
import { componentsOf } from './store.ts';
import { branchOf, compareVersions } from './version.ts';
import type { Kev } from './sources/kev.ts';
import type { Component, Item, Level, Match, Registry, Source, Stack } from './types.ts';

/** The fields of a news item matching needs; stored with every item so a stack change can re-match it. */
export type NewsFacts = Pick<Item, 'title' | 'text' | 'cves' | 'versions' | 'published'>;

export interface Classified {
  level: Level;
  exploited: boolean;
  confirmed: boolean;
  matches: Match[];
}

const SECURITY = /security|vulnerab|advisory|CVE-\d|exploit|zero-day|0-day|patch(es|ed)? .*flaw/i;
const SEVERE = /critical|remote code execution|\bRCE\b/i;
/** An advance notice older than this was answered by a release or never mattered. */
const NOTICE_DAYS = 14;
/**
 * Words that show a text means a package: the registry's name within three words ("axios versions
 * on npm"), or "package" right next to it ("the debug package"); "select the update package" is not.
 */
const ECOSYSTEM_WORDS: Record<string, string> = { Packagist: '(?:composer|packagist)', npm: '(?:npm|node\\.?js|javascript)' };
const PACKAGE_WORDS = '(?:package|library|module)s?';
/** What a headline says about a product when it is the subject: "PHP RCE flaws", "flaw in OpenSSL". */
const ISSUE_WORDS = '(?:flaws?|vulnerab\\w*|bugs?|rce|patch\\w*|updat\\w*|releas\\w*|exploit\\w*|zero-days?|0-days?|security|advisor\\w*|cve-\\d)';

export function productOf(component: Component, registry: Registry): string | undefined {
  if (component.product) return component.product;
  return Object.entries(registry.products).find(([, p]) => p.packages?.includes(component.name))?.[0];
}

const patterns = new Map<string, RegExp>();
function cached(key: string, build: () => RegExp): RegExp {
  let re = patterns.get(key);
  if (!re) patterns.set(key, (re = build()));
  return re;
}
const escape = (name: string) => name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function mentions(text: string, name: string): boolean {
  return cached(`m:${name}`, () => new RegExp(`(^|[^\\w/@.-])${escape(name)}($|[^\\w/-])`, 'i')).test(text);
}

/** The headline is about the product, not just naming it ("PHP object injection in <some app>" is not). */
function headlineAbout(title: string, name: string): boolean {
  const n = escape(name);
  return cached(`h:${name}`, () => new RegExp(
    `(^|[^\\w/@.-])${n}(?:\\W+[\\w.-]+){0,3}?\\W+${ISSUE_WORDS}\\b|${ISSUE_WORDS}\\W+(?:in|on|affecting|for)\\W+(?:[\\w.-]+\\W+){0,2}?${n}($|[^\\w/-])`, 'i',
  )).test(title);
}

/** The package name sits next to a word that shows the text means the package. */
function nearEcosystem(text: string, name: string, ecosystem: string): boolean {
  const n = escape(name);
  const eco = ECOSYSTEM_WORDS[ecosystem]!;
  return cached(`e:${ecosystem}:${name}`, () => new RegExp(
    `${eco}\\W+(?:[\\w@/.-]+\\W+){0,3}?${n}($|[^\\w/-])|(^|[^\\w/@.-])${n}\\W+(?:[\\w@/.-]+\\W+){0,3}?${eco}\\b` +
      `|(^|[^\\w/@.-])${n}\\W+(?:${eco}\\W+)?${PACKAGE_WORDS}\\b|${PACKAGE_WORDS}\\W+${n}($|[^\\w/-])`, 'i',
  )).test(text);
}

/** Does this item concern this component at all, whatever the version? */
function concerns(title: string, text: string, component: Component, product: string | undefined, source: Source, registry: Registry): boolean {
  // A product's own feed is about that product, named or not ("8.3.36 Released!").
  if (source.products?.length) return !!product && source.products.includes(product);
  // Elsewhere a product counts when the headline is about it: news names PHP or Node in passing.
  const names = product ? (registry.products[product]?.names ?? [product]) : [];
  if (names.some((n) => headlineAbout(title, n))) return true;
  if (!component.ecosystem || !ECOSYSTEM_WORDS[component.ecosystem]) return false;
  // "laravel/framework" or "@scope/pkg" is unmistakable; "debug" or "select" needs "npm" or "package" next to it.
  const distinctive = component.name.includes('/') || component.name.startsWith('@');
  return distinctive ? mentions(text, component.name) : nearEcosystem(text, component.name, component.ecosystem);
}

/**
 * Which of the user's components a news item concerns, and how urgent it is for them.
 *
 * - critical: names a CVE CISA lists as exploited, or a fix newer than the version run, described
 *   as critical / remote code execution;
 * - high: names a fix newer than the version run with a CVE or security wording; or an official
 *   advance notice of a security release, from the last two weeks, that no later post has answered
 *   (unconfirmed);
 * - medium: concerns a component and talks about security;
 * - low / info: everything else (still kept, readable as news).
 *
 * An item naming a version in the component's own release line that the component already has is
 * about something it is patched for, so it does not match.
 */
export function classify(item: NewsFacts, source: Source, stacks: Stack[], registry: Registry, kev: Kev, peers: NewsFacts[], now = Date.now()): Classified {
  const text = `${item.title} ${item.text ?? ''}`;
  const exploited = item.cves.some((c) => kev.has(c));
  const security = item.cves.length > 0 || SECURITY.test(item.title);
  const matches: Match[] = [];

  for (const stack of stacks) {
    for (const component of componentsOf(stack)) {
      const product = productOf(component, registry);
      if (!concerns(item.title, text, component, product, source, registry)) continue;
      const branch = branchOf(component.version);
      const inBranch = item.versions.filter((v) => branchOf(v) === branch);
      // Only the release line is known ("8.3" from a Docker tag): whether it has the fix can't be told.
      const newer = component.exact === false ? [] : inBranch.filter((v) => compareVersions(v, component.version) > 0).sort(compareVersions);
      if (inBranch.length && !newer.length && component.exact !== false) continue;
      // A product's own post about other release lines only ("PHP 8.4.27 Released!") is not about this one.
      if (source.products?.length && item.versions.length && !inBranch.length) continue;
      matches.push({
        project: stack.project,
        component: component.name,
        version: component.version,
        ...(newer[0] ? { fixed: newer[0] } : {}),
        ...(component.dev ? { dev: true } : {}),
      });
    }
  }

  if (!matches.length) return { level: security ? 'low' : 'info', exploited, confirmed: true, matches };
  if (exploited) return { level: 'critical', exploited, confirmed: true, matches };

  const fixes = matches.some((m) => m.fixed);
  if (fixes && security) return { level: SEVERE.test(text) ? 'critical' : 'high', exploited, confirmed: true, matches };

  const recent = item.published ? now - Date.parse(item.published) < NOTICE_DAYS * 24 * 3600_000 : false;
  if (source.official && SECURITY.test(item.title) && !item.versions.length && recent) {
    // An advance notice is answered by the release that follows it; that post carries the alert.
    const published = item.published ?? '';
    const answered = peers.some((p) => p !== item && (p.published ?? '') >= published && p.versions.some((v) => matches.some((m) => branchOf(v) === branchOf(m.version))));
    if (answered) return { level: 'low', exploited, confirmed: true, matches };
    return { level: SEVERE.test(item.title) ? 'critical' : 'high', exploited, confirmed: false, matches };
  }

  // A vendor's own post needs a CVE to count: "security best practices" is not an issue.
  const issue = item.cves.length > 0 || (!source.products?.length && security);
  return { level: issue ? 'medium' : 'info', exploited, confirmed: true, matches };
}

/** CVE ids and dotted versions named anywhere in the text. */
export function extractFacts(title: string, text: string): Pick<Item, 'cves' | 'versions'> {
  const all = `${title} ${text}`;
  return {
    cves: [...new Set(all.match(/CVE-\d{4}-\d{4,}/g) ?? [])],
    versions: [...new Set(all.match(/\b\d+\.\d+\.\d+\b/g) ?? [])].slice(0, 50),
  };
}
