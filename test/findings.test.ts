import assert from 'node:assert/strict';
import { test } from 'node:test';
import { eolItems, releaseFor } from '../src/sources/endoflife.ts';
import { parseKev } from '../src/sources/kev.ts';
import { osvItem, osvLevel } from '../src/sources/osv.ts';
import type { Component, Source } from '../src/types.ts';

const osv: Source = { id: 'osv', name: 'OSV', type: 'osv', url: 'https://api.osv.dev/v1' };
const eol: Source = { id: 'endoflife', name: 'endoflife.date', type: 'endoflife', url: 'https://endoflife.date/api/v1/products/' };
const NOW = '2026-10-21T12:00:00.000Z';

test('osv levels come from the reviewed label, else the CVSS vector, else medium', () => {
  assert.equal(osvLevel({ id: 'A', database_specific: { severity: 'HIGH' } }), 'high');
  assert.equal(osvLevel({ id: 'B', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] }), 'critical');
  assert.equal(osvLevel({ id: 'C' }), 'medium');
});

test('an OSV hit on the exploited list is critical, with the fixed version on its match', () => {
  const kev = parseKev(JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-2025-10001' }] }));
  const component: Component = { name: 'acme/framework', version: 'v8.0.0', ecosystem: 'Packagist', source: 'composer.lock' };
  const item = osvItem(osv, 'shop', component, {
    id: 'GHSA-aaaa-bbbb-cccc',
    summary: 'Query binding injection',
    aliases: ['CVE-2025-10001'],
    database_specific: { severity: 'MODERATE' },
    affected: [{ package: { name: 'acme/framework' }, ranges: [{ events: [{ introduced: '8.0.0' }, { fixed: '8.22.1' }] }] }],
  }, kev, NOW);

  assert.equal(item.id, 'osv:shop:acme/framework:GHSA-aaaa-bbbb-cccc');
  assert.equal(item.kind, 'finding');
  assert.equal(item.level, 'critical');
  assert.equal(item.exploited, true);
  assert.deepEqual(item.cves, ['CVE-2025-10001']);
  assert.deepEqual(item.matches, [{ project: 'shop', component: 'acme/framework', version: 'v8.0.0', fixed: '8.22.1' }]);
});

test('endoflife.date: the longest matching release line, end of life, newer patches', () => {
  const releases = [
    { name: '7', isEol: true },
    { name: '7.4', isEol: false, latest: { name: '7.4.1' } },
    { name: '7.0', isEol: true, eolFrom: '2026-02-28', latest: { name: '7.0.15' } },
  ];
  assert.equal(releaseFor('7.4.0', releases)?.name, '7.4');

  const cache = (version: string): Component => ({ name: 'redis', version, product: 'redis', source: 'manual' });
  assert.deepEqual(eolItems(eol, 'shop', cache('7.4.0'), 'redis', releases, NOW).map((i) => [i.level, i.matches[0]!.fixed]), [['medium', '7.4.1']]);
  assert.deepEqual(eolItems(eol, 'shop', cache('7.0.15'), 'redis', releases, NOW).map((i) => i.level), ['high']);
  assert.deepEqual(eolItems(eol, 'shop', cache('7.4.1'), 'redis', releases, NOW), []);
});
