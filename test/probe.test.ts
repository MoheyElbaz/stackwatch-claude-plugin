import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PROBE_SCRIPT, parseProbe } from '../src/probe.ts';

test('a panel server reports every runtime it runs', () => {
  const output = [
    'os=rocky 9.4',
    'php=8.2.21|-',
    'php=7.4.33|-',
    'nginx=1.26.2|-',
    'db=mysql  Ver 8.0.39 for Linux on x86_64 (Source distribution)|-',
    'nodejs=v22.11.0|nodejs',
    'openssl=3.2.2|openssl',
    'aapanel=7.0.21|-',
    'kernel=5.14.0-427.13.1.el9_4.x86_64',
  ].join('\n');
  const { components, notes } = parseProbe(output, '203.0.113.7');

  assert.deepEqual(components.map((c) => `${c.product} ${c.version}`), [
    'rocky-linux 9.4', 'php 8.2.21', 'php 7.4.33', 'nginx 1.26.2', 'mysql 8.0.39', 'nodejs 22.11.0', 'openssl 3.2.2', 'aapanel 7.0.21',
  ]);
  assert.ok(components.every((c) => c.source === 'server 203.0.113.7'));
  assert.deepEqual(components.filter((c) => c.packaged).map((c) => c.packaged), ['nodejs', 'openssl']);
  assert.match(notes.join(' '), /kernel 5\.14\.0-427/);
});

test('mariadb, empty and unknown lines', () => {
  const { components, notes } = parseProbe('db=mysql  Ver 15.1 Distrib 11.4.3-MariaDB, for Linux|mariadb-server\nnginx=\nos=gentoo 2.15\ngarbage', 'h');
  assert.deepEqual(components.map((c) => `${c.product} ${c.version} ${c.packaged}`), ['mariadb 11.4.3 mariadb-server']);
  assert.match(notes[0]!, /gentoo/);
});

test('OS packages are read for OSV, with only the running kernel kept', () => {
  const output = [
    'os=rocky 9.4',
    'db=mysql  Ver 8.0.39 for Linux on x86_64|mysql-server',
    'nginx=1.26.2|-',
    'openssl=3.2.2-fips|openssl',
    'kernel=5.14.0-427.13.1.el9_4.x86_64',
    'pkg=openssl 1:3.2.2-6.el9_4',
    'pkg=kernel-core (none):5.14.0-362.8.1.el9_3',
    'pkg=kernel-core (none):5.14.0-427.13.1.el9_4',
    'pkg=kernel-core (none):5.14.0-427.20.1.el9_4',
    'pkg=bash (none):5.1.8-9.el9',
  ].join('\n');
  const { components, notes } = parseProbe(output, 'h');

  assert.deepEqual(components.filter((c) => c.ecosystem).map((c) => `${c.ecosystem} ${c.name} ${c.version}`), [
    'Rocky Linux:9 openssl 1:3.2.2-6.el9_4',
    'Rocky Linux:9 bash 5.1.8-9.el9',
    'Rocky Linux:9 kernel 5.14.0-427.13.1.el9_4',
  ]);
  assert.equal(components.find((c) => c.product === 'mysql')!.packaged, 'mysql-server', 'installed by the OS');
  assert.equal(components.find((c) => c.product === 'nginx')!.packaged, undefined, 'built by a panel');
  assert.equal(components.find((c) => c.product === 'openssl')!.packaged, 'openssl');
  assert.equal(components.find((c) => c.product === 'openssl')!.version, '3.2.2');
  assert.ok(notes.some((n) => n.includes('5.14.0-427.20.1.el9_4') && n.includes('reboot')));
});

test('the server script only reads versions', () => {
  const lines = PROBE_SCRIPT.split('\n').filter((l) => l.trim());
  assert.ok(!/\b(rm|mv|cp|tee|curl|wget|chmod|chown|kill|systemctl|service|install|yum|apt|cat \/etc\/shadow|\.env)\b|>\s*\/(?!dev\/null)/.test(PROBE_SCRIPT), 'no writes, downloads or secrets');
  assert.ok(lines.length < 25);
});
