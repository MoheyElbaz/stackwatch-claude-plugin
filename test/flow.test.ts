import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { beforeEach, test } from 'node:test';
import { sessionStartHook } from '../src/hook.ts';
import { notifyNew } from '../src/notify.ts';
import { addComponent, describeProjects, markRead, markUnread, setAlertLevel } from '../src/ops.ts';
import { loadRegistry } from '../src/registry.ts';
import { componentsOf, loadData, saveData, updateData } from '../src/store.ts';
import type { Item } from '../src/types.ts';

const NOW = Date.parse('2026-10-21T12:00:00Z');

const alert = (id: string, fields: Partial<Item> = {}): Item => ({
  id, source: 'php-news', kind: 'news', title: 'Security advisory', url: 'https://www.php.net/', published: '2026-10-21T00:35:26.000Z',
  firstSeen: '2026-10-21T01:00:00.000Z', cves: [`CVE-2026-${[...id].reduce((n, c) => n + c.charCodeAt(0), 1000)}`], versions: ['8.2.35'], text: '', level: 'critical', exploited: false,
  confirmed: true, matches: [{ project: 'shop', component: 'php', version: '8.2.20', fixed: '8.2.35' }], read: false, ...fields,
});

let refreshes = 0;
const fakeRefresh = async () => {
  refreshes++;
  updateData((d) => { d.lastRefresh = new Date(NOW).toISOString(); });
};

beforeEach(() => {
  process.env.STACKWATCH_HOME = mkdtempSync(join(tmpdir(), 'stackwatch-'));
  refreshes = 0;
});

function seed(items: Item[], lastRefresh?: string): void {
  saveData({ version: 1, stacks: { shop: { project: 'shop', updated: '', detected: [], manual: [{ name: 'php', version: '8.2.20', product: 'php', source: 'manual' }] } }, items, lastRefresh });
}

test('the hook stays silent until a project is registered', async () => {
  assert.equal(await sessionStartHook(NOW, fakeRefresh), null);
  assert.equal(refreshes, 0);
});

test('unread alerts are raised every session until marked read, then reminded in one line', async () => {
  seed([alert('php-news:a'), alert('php-news:b', { level: 'high' }), alert('dev', { matches: [{ project: 'shop', component: 'debug', version: '1', dev: true }] }), alert('medium', { level: 'medium' })]);

  const first = await sessionStartHook(NOW, fakeRefresh);
  assert.equal(refreshes, 1, 'never checked before, so it refreshes');
  assert.match(first!.systemMessage!, /2 unread security alerts/);
  assert.match(first!.hookSpecificOutput!.additionalContext, /php 8\.2\.20 → 8\.2\.35[\s\S]*\+1 more issue for this component/);
  assert.doesNotMatch(first!.hookSpecificOutput!.additionalContext, /id: (dev|medium)\b/, 'dev-only and medium items never interrupt a session');

  const again = await sessionStartHook(NOW + 10 * 60_000, fakeRefresh);
  assert.equal(refreshes, 1, 'checked ten minutes ago, so it reuses that');
  assert.match(again!.systemMessage!, /2 unread/, 'still unread, still raised');

  assert.match(markRead({ alerts: true, note: 'upgrading tonight' }), /Marked 2 items read/);
  const read = await sessionStartHook(NOW + 20 * 60_000, fakeRefresh);
  assert.equal(read!.hookSpecificOutput, undefined);
  assert.match(read!.systemMessage!, /2 security alerts read but still open/);
  assert.equal(loadData().items.find((i) => i.id === 'php-news:a')!.note, 'upgrading tonight');

  markUnread(['php-news:a']);
  assert.match((await sessionStartHook(NOW + 30 * 60_000, fakeRefresh))!.systemMessage!, /1 unread security alert \(1 thing to fix\), \+1 read but open/);
});

test('reports of the same CVE are one alert, and reading one reads them all', async () => {
  const cve = { cves: ['CVE-2026-109618', 'CVE-2026-109619'] };
  seed([
    alert('php-news:advisory', cve),
    alert('php-news:release', { ...cve, level: 'critical' }),
    alert('thehackernews:x', { cves: ['CVE-2026-109619'], level: 'medium', source: 'thehackernews' }),
    alert('other', { level: 'high' }),
  ], new Date(NOW).toISOString());

  const out = await sessionStartHook(NOW, fakeRefresh);
  assert.match(out!.systemMessage!, /2 unread security alerts/);
  assert.match(out!.hookSpecificOutput!.additionalContext, /also reported 2× by php\.net, The Hacker News/);

  markRead({ ids: ['thehackernews:x'] });
  assert.deepEqual(loadData().items.filter((i) => i.read).map((i) => i.id).sort(), ['php-news:advisory', 'php-news:release', 'thehackernews:x']);
});

test('a failing refresh never breaks the session', async () => {
  seed([alert('php-news:a')]);
  const failing = await sessionStartHook(NOW, async () => { throw new Error('offline'); });
  assert.match(failing!.systemMessage!, /1 unread/, 'falls back to what is stored');
});

test('changing a stack re-matches stored news at once: upgrading PHP clears its alert', () => {
  seed([alert('php-news:a', { text: 'CVE-2026-109618 is fixed in 8.2.35.', title: 'Security advisory: update now' })], new Date(NOW).toISOString());
  addComponent('shop', { name: 'php', version: '8.2.35', product: 'php' });

  const data = loadData();
  assert.deepEqual(data.items[0]!.matches, []);
  assert.equal(data.lastRefresh, undefined, 'findings for the new version are recomputed at the next view');
});

test('the alert level decides what interrupts a session, per project or for all', async () => {
  seed([alert('high', { level: 'high' }), alert('medium', { level: 'medium' })], new Date(NOW).toISOString());
  assert.match((await sessionStartHook(NOW, fakeRefresh))!.systemMessage!, /1 unread/);

  setAlertLevel('medium', 'shop');
  assert.match((await sessionStartHook(NOW, fakeRefresh))!.systemMessage!, /2 unread/);

  setAlertLevel('critical');
  assert.match((await sessionStartHook(NOW, fakeRefresh))!.systemMessage!, /2 unread/, "the project's own level beats the global one");

  updateData((d) => { delete d.stacks.shop!.alertLevel; });
  assert.equal(await sessionStartHook(NOW, fakeRefresh), null, 'nothing is critical');
  assert.throws(() => setAlertLevel('info'), /level must be/);
});

test("a project's risk is its worst open issue, read or not", () => {
  seed([alert('a', { level: 'high', read: true }), alert('b', { level: 'medium' }), alert('dev', { level: 'critical', matches: [{ project: 'shop', component: 'x', version: '1', dev: true }] })], new Date(NOW).toISOString());
  assert.match(describeProjects(), /shop · risk: HIGH \(1 high, 1 medium\) · alerts at high\+/);
});

test('for a runtime, typed by hand beats the server, which beats the project files', () => {
  const php = (version: string, source: string) => ({ name: 'php', version, product: 'php', source });
  const stack = { project: 'p', updated: '', manual: [php('8.2.35', 'manual')], probed: [php('8.2.20', 'server h')], detected: [php('8.2.0', 'Dockerfile'), { name: 'a/b', version: '1.0.0', ecosystem: 'Packagist' as const, source: 'composer.lock' }] };
  assert.deepEqual(componentsOf(stack).map((c) => `${c.name} ${c.version}`), ['php 8.2.35', 'a/b 1.0.0']);
  assert.deepEqual(componentsOf({ ...stack, manual: [] }).map((c) => `${c.name} ${c.version}`), ['php 8.2.20', 'a/b 1.0.0']);
});

test("news about an OS CVE the server's own advisories no longer list is not an alert", () => {
  const os = { name: 'rocky', version: '9.4', product: 'rocky-linux', source: 'server h' };
  const kernel = { name: 'kernel', version: '5.14.0-427.13.1.el9_4', ecosystem: 'Rocky Linux:9', source: 'server h' };
  const advisory = (cve: string): Item => alert(`thehackernews:${cve}`, { source: 'thehackernews', title: `Kernel flaw (${cve}) in Rocky Linux patched`, cves: [cve], versions: [], exploited: true, matches: [] });
  const finding = alert('osv:shop:kernel:ALSA-1', { kind: 'finding', source: 'osv', cves: ['CVE-2026-0002'], level: 'high', matches: [{ project: 'shop', component: 'kernel', version: kernel.version }] });
  saveData({ version: 1, stacks: { shop: { project: 'shop', updated: '', detected: [], manual: [], probed: [os, kernel] } }, items: [advisory('CVE-2026-0001'), advisory('CVE-2026-0002'), finding], lastRefresh: new Date(NOW).toISOString() });

  addComponent('shop', { name: 'note', version: '1.0.0' }); // any stack change re-matches the news
  const items = new Map(loadData().items.map((i) => [i.id, i]));
  assert.deepEqual(items.get('thehackernews:CVE-2026-0001')!.matches, [], 'patched on this server');
  assert.equal(items.get('thehackernews:CVE-2026-0001')!.level, 'low');
  assert.equal(items.get('thehackernews:CVE-2026-0002')!.matches.length, 1, 'still open there');
  assert.equal(items.get('thehackernews:CVE-2026-0002')!.level, 'critical');
});

test("a server's OS package advisories are one alert with one fix", async () => {
  const pkg = (name: string, level: Item['level'], fixed: string) =>
    alert(`osv:shop:${name}:RLSA-${name}`, { kind: 'finding', source: 'osv', level, title: `Important: ${name} security update`, matches: [{ project: 'shop', component: name, version: '1', fixed, os: 'Rocky Linux:9' }] });
  seed([pkg('kernel', 'high', '2'), pkg('openssl', 'high', '2'), pkg('glibc', 'critical', '2'), alert('php-news:a')], new Date(NOW).toISOString());

  const out = await sessionStartHook(NOW, fakeRefresh);
  assert.match(out!.systemMessage!, /4 unread security alerts \(2 things to fix\)/);
  const context = out!.hookSpecificOutput!.additionalContext;
  assert.match(context, /shop: 3 Rocky Linux:9 packages with security updates \(1 critical, 2 high\)/);
  assert.match(context, /fix: `dnf upgrade --security`, then reboot/);
});

test('notifications outside Claude are off until turned on', async () => {
  seed([alert('php-news:a')], new Date(NOW).toISOString());
  assert.match(await notifyNew(), /Notifications are off/);
  assert.equal(loadData().items[0]!.notifiedAt, undefined);
});

test('~/.stackwatch/sources.json adds sources and disables shipped ones', () => {
  writeFileSync(join(process.env.STACKWATCH_HOME!, 'sources.json'), JSON.stringify({
    sources: [{ id: 'thehackernews', enabled: false }, { id: 'my-vendor', name: 'My vendor', type: 'feed', url: 'https://vendor.example/feed.xml', official: true, products: ['php'] }],
    products: { mytool: { names: ['MyTool'] } },
  }));
  const registry = loadRegistry();
  assert.ok(!registry.sources.some((s) => s.id === 'thehackernews'));
  assert.ok(registry.sources.some((s) => s.id === 'my-vendor' && s.official));
  assert.ok(registry.products.mytool && registry.products.php, 'products merge');
});

test('a corrupt data file is refused, not replaced by an empty one', () => {
  writeFileSync(join(process.env.STACKWATCH_HOME!, 'data.json'), '{ not json');
  assert.throws(() => loadData(), /not valid JSON/);
});
