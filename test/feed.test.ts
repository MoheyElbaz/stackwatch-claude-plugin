import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { test } from 'node:test';
import { parseFeed, plain } from '../src/sources/feed.ts';

const fixture = (name: string) => readFileSync(join(import.meta.dirname, 'fixtures', name), 'utf8');

test('atom: entries with their alternate link, date and plain text', () => {
  const items = parseFeed(fixture('php-feed.atom'));
  assert.equal(items.length, 4);
  assert.equal(items[0]!.url, 'https://www.php.net/index.php#2026-10-21-5');
  assert.equal(items[0]!.published, '2026-10-21T00:35:26.000Z');
  assert.equal(items[0]!.guid, 'https://www.php.net/archive/2026.php#2026-10-21-5');
  assert.match(items[0]!.text, /CVE-2026-109618 and CVE-2026-109619/);
  assert.doesNotMatch(items[0]!.text, /<|strong/);
});

test('rss: CDATA, escaped HTML, guid and dc:date', () => {
  const items = parseFeed(fixture('news.rss'));
  assert.equal(items.length, 3);
  assert.equal(items[0]!.guid, 'news-1');
  assert.equal(items[0]!.url, 'https://news.example/php-rce');
  assert.equal(items[0]!.text, 'Researchers say PHP before 8.2.35 & 8.3.36 is affected .');
  assert.equal(items[1]!.text, 'Attackers published malicious versions of axios to npm.');
  assert.equal(items[2]!.published, '2026-10-19T10:00:00.000Z');
});

test('html is flattened whether escaped once, twice or not at all', () => {
  assert.equal(plain('&lt;b&gt;x&lt;/b&gt; &amp;amp; y'), 'x & y');
  assert.equal(plain('<![CDATA[<p>a</p>]]>'), 'a');
  assert.equal(plain('&#x41;&#66;'), 'AB');
});
