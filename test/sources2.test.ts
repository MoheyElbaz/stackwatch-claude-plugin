import assert from 'node:assert/strict';
import { test } from 'node:test';
import { eolItems } from '../src/sources/endoflife.ts';
import { nvdItems } from '../src/sources/nvd.ts';
import { osvLevel } from '../src/sources/osv.ts';
import type { Component, Source } from '../src/types.ts';

const NOW = '2026-10-21T12:00:00.000Z';
const nvd: Source = { id: 'nvd', name: 'NVD', type: 'nvd', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0' };
const eol: Source = { id: 'endoflife', name: 'endoflife.date', type: 'endoflife', url: 'https://endoflife.date/api/v1/products/' };

test('NVD: level from its rating, the fix from the range that holds this version, rejected CVEs dropped', () => {
  const apache: Component = { name: 'apache', version: '2.4.58', product: 'apache-http-server', source: 'server h' };
  const range = (start: string, end: string) => [{ nodes: [{ cpeMatch: [{ vulnerable: true, criteria: 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*', versionStartIncluding: start, versionEndExcluding: end }] }] }];
  const items = nvdItems(nvd, 'shop', apache, 'apache:http_server', [
    { id: 'CVE-2024-42516', vulnStatus: 'Modified', descriptions: [{ lang: 'en', value: 'HTTP response splitting' }], metrics: { cvssMetricV31: [{ cvssData: { baseSeverity: 'HIGH' } }] }, configurations: range('2.4.0', '2.4.64') },
    { id: 'CVE-2099-0001', vulnStatus: 'Rejected' },
  ], new Map([['CVE-2024-42516', { cveID: 'CVE-2024-42516' }]]), NOW);

  assert.equal(items.length, 1);
  assert.equal(items[0]!.level, 'critical', 'on the exploited list');
  assert.equal(items[0]!.matches[0]!.fixed, '2.4.64');
});

test("a distribution advisory's rating sets its level", () => {
  assert.equal(osvLevel({ id: 'RLSA-2026:1', summary: 'Important: kernel security update' }), 'high');
  assert.equal(osvLevel({ id: 'RLSA-2026:2', summary: 'Moderate: openssl security update' }), 'medium');
});

test('an OS package past its upstream end of life is a hint, not an alert; no "newer upstream" either', () => {
  const releases = [{ name: '8.0', isEol: true, eolFrom: '2026-04-30', latest: { name: '8.0.43' } }];
  const packaged: Component = { name: 'mysql', version: '8.0.39', product: 'mysql', packaged: 'mysql-server', source: 'server h' };
  const items = eolItems(eol, 'shop', packaged, 'mysql', releases, NOW);
  assert.deepEqual(items.map((i) => i.level), ['medium']);
  assert.match(items[0]!.title, /OS's mysql-server package/);
});
