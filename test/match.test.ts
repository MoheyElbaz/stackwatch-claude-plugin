import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { classify, extractFacts, type NewsFacts } from '../src/match.ts';
import { parseFeed } from '../src/sources/feed.ts';
import type { Registry, Source, Stack } from '../src/types.ts';

const registry: Registry = JSON.parse(readFileSync(join(import.meta.dirname, '..', 'plugin', 'sources.json'), 'utf8'));
const source = (id: string) => registry.sources.find((s) => s.id === id)!;
const news: Source = { id: 'news', name: 'News', type: 'feed', url: 'https://news.example' };

const facts = (file: string): NewsFacts[] =>
  parseFeed(readFileSync(join(import.meta.dirname, 'fixtures', file), 'utf8')).map((e) => ({ title: e.title, text: e.text, published: e.published, ...extractFacts(e.title, e.text) }));
const php = facts('php-feed.atom');
const rss = facts('news.rss');

const stack = (phpVersion: string): Stack => ({
  project: 'shop',
  updated: '',
  manual: [{ name: 'php', version: phpVersion, product: 'php', source: 'manual' }],
  detected: [
    { name: 'symfony/http-kernel', version: 'v7.1.5', ecosystem: 'Packagist', source: 'composer.lock' },
    { name: 'axios', version: '1.7.0', ecosystem: 'npm', source: 'package-lock.json' },
    { name: 'debug', version: '4.3.4', ecosystem: 'npm', dev: true, source: 'package-lock.json' },
  ],
});
const noKev = new Map();
const NOW = Date.parse('2026-10-21T12:00:00Z');

test("php.net's advisory is critical for a PHP behind it, with the fix in its own branch", () => {
  const result = classify(php[0]!, source('php-news'), [stack('8.2.20')], registry, noKev, php, NOW);
  assert.equal(result.level, 'critical');
  assert.equal(result.confirmed, true);
  assert.deepEqual(result.matches, [{ project: 'shop', component: 'php', version: '8.2.20', fixed: '8.2.35' }]);
});

test('the same advisory does not match once PHP is patched', () => {
  const result = classify(php[0]!, source('php-news'), [stack('8.2.35')], registry, noKev, php, NOW);
  assert.deepEqual(result.matches, []);
  assert.notEqual(result.level, 'high');
});

test("a product's own post about other release lines only does not match", () => {
  const other = { title: 'PHP 8.4.27 Released!', text: 'Fixes CVE-2026-109618.', published: '2026-10-21T00:00:00Z', ...extractFacts('PHP 8.4.27 Released!', 'Fixes CVE-2026-109618.') };
  assert.deepEqual(classify(other, source('php-news'), [stack('8.2.20')], registry, noKev, [other], NOW).matches, []);
});

test('an advance notice is an unconfirmed alert until the release answers it', () => {
  const notice = php.find((f) => f.title.startsWith('Upcoming'))!;
  const before = classify(notice, source('php-news'), [stack('8.2.34')], registry, noKev, [notice], NOW);
  assert.equal(before.level, 'critical');
  assert.equal(before.confirmed, false);

  const after = classify(notice, source('php-news'), [stack('8.2.34')], registry, noKev, php, NOW);
  assert.equal(after.level, 'low', 'the release post that followed carries the alert now');
});

test('general news names the product: an early warning before php.net or any database', () => {
  const result = classify(rss[0]!, news, [stack('8.2.20')], registry, noKev, rss, NOW);
  assert.equal(result.level, 'critical');
  assert.equal(result.matches[0]!.fixed, '8.2.35');
});

test('a package name matches only in text about its ecosystem', () => {
  const worm = classify(rss[1]!, news, [stack('8.2.35')], registry, noKev, rss, NOW);
  assert.deepEqual(worm.matches.map((m) => m.component).sort(), ['axios', 'debug'], 'npm text: both packages named');
  assert.equal(worm.matches.find((m) => m.component === 'debug')!.dev, true);

  const ransomware = classify(rss[2]!, news, [stack('8.2.35')], registry, noKev, rss, NOW);
  assert.deepEqual(ransomware.matches, [], '"debug" in ordinary prose is not the npm package');
  assert.equal(ransomware.level, 'info');
});

test('an old official security post is not an advance notice', () => {
  const old = { title: 'Security update for our platform', text: '', published: '2026-06-01T00:00:00Z', cves: [], versions: [] };
  const result = classify(old, source('php-news'), [stack('8.2.20')], registry, noKev, [old], NOW);
  assert.equal(result.confirmed, true);
  assert.equal(result.level, 'info', 'a vendor post needs a CVE to be an issue');
});

const general = (title: string, text = '') => ({ title, text, published: '2026-10-21T00:00:00Z', ...extractFacts(title, text) });

test('news counts for a product only when the headline is about it', () => {
  const about = ['Critical PHP Vulnerability (CVE-2026-109618)', 'PHP ships emergency patches for critical flaws', 'PHP 8.2.35 released to fix CVE-2026-109618', 'Remote code execution flaw in PHP patched'];
  for (const title of about) assert.equal(classify(general(title), news, [stack('8.2.20')], registry, noKev, [], NOW).matches.length, 1, title);

  const inPassing = ['[remote] CVE-2026-80428 Unauthenticated PHP Object Injection via Shibboleth - ILIAS < 9.22', 'Ten PHP frameworks compared', 'PHP2Shell explained'];
  for (const title of inPassing) assert.deepEqual(classify(general(title), news, [stack('8.2.20')], registry, noKev, [], NOW).matches, [], title);
});

test('an ordinary word is not an npm package unless the text says so', () => {
  const cisa = general('Moxa AIG-302 ThingsPro Edge', 'Users should select the firmware update package from the vendor portal. CVE-2026-109813');
  const s: Stack = { ...stack('8.2.35'), detected: [{ name: 'select', version: '1.1.2', ecosystem: 'npm', source: 'package-lock.json' }] };
  assert.deepEqual(classify(cisa, news, [s], registry, noKev, [], NOW).matches, []);

  const worm = general('Malicious select versions published to npm', 'The select package was hijacked.');
  assert.equal(classify(worm, news, [s], registry, noKev, [], NOW).matches.length, 1);
});

test('a runtime known only by its release line is flagged for checking, never declared behind', () => {
  const line: Stack = { project: 'docker', updated: '', manual: [], detected: [{ name: 'php', version: '8.3', product: 'php', exact: false, source: 'Dockerfile' }] };
  const result = classify(rss[0]!, news, [line], registry, noKev, rss, NOW);
  assert.equal(result.matches.length, 1);
  assert.equal(result.matches[0]!.fixed, undefined);
  assert.equal(result.level, 'medium');
});

test('a CVE on the exploited list makes a matching item critical and exploited', () => {
  const kev = new Map([['CVE-2026-109618', { cveID: 'CVE-2026-109618' }]]);
  const item = { title: 'PHP flaw CVE-2026-109618 under attack', text: '', published: '2026-10-22T00:00:00Z', ...extractFacts('PHP flaw CVE-2026-109618 under attack', '') };
  const result = classify(item, news, [stack('8.2.20')], registry, kev, [item], NOW);
  assert.equal(result.level, 'critical');
  assert.equal(result.exploited, true);
});
