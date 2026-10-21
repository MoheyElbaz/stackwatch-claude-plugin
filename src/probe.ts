// SPDX-License-Identifier: GPL-3.0-or-later
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';
import type { Component, SshTarget } from './types.ts';

/**
 * Read-only: every line only prints a version or a package list. Nothing is installed, written or
 * read from files that hold secrets. Covers plain installs and hosting panels (aaPanel / BaoTa,
 * cPanel, Plesk).
 * Each runtime is printed as key=version|owning OS package ("-" when compiled by hand or a panel).
 */
export const PROBE_SCRIPT = String.raw`
owner() { if command -v rpm >/dev/null 2>&1; then rpm -qf --qf '%{NAME}' "$1" 2>/dev/null | grep -v ' ' || echo -; elif command -v dpkg >/dev/null 2>&1; then dpkg -S "$1" 2>/dev/null | head -1 | cut -d: -f1 || echo -; else echo -; fi; }
say() { [ -n "$2" ] && echo "$1=$2|$(owner "$3")"; }
. /etc/os-release 2>/dev/null && echo "os=$ID $VERSION_ID"
for p in /www/server/php/*/bin/php /opt/cpanel/ea-php*/root/usr/bin/php /opt/plesk/php/*/bin/php /opt/remi/php*/root/usr/bin/php /usr/bin/php /usr/local/bin/php; do [ -x "$p" ] && say php "$("$p" -r 'echo PHP_VERSION;' 2>/dev/null)" "$p"; done
for b in /www/server/apache/bin/httpd /usr/sbin/httpd /usr/sbin/apache2; do [ -x "$b" ] && say apache "$("$b" -v 2>/dev/null | sed -n 's|.*Apache/\([0-9.]*\).*|\1|p')" "$b"; done
for b in /www/server/nginx/sbin/nginx /usr/sbin/nginx /usr/local/nginx/sbin/nginx; do [ -x "$b" ] && say nginx "$("$b" -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')" "$b"; done
b=$(command -v mariadb || command -v mysql) && say db "$("$b" --version 2>/dev/null)" "$(readlink -f "$b")"
b=$(command -v psql) && say postgresql "$("$b" --version 2>/dev/null | awk '{print $3}')" "$(readlink -f "$b")"
b=$(command -v redis-server) && say redis "$("$b" --version 2>/dev/null | sed -n 's/.*v=\([0-9.]*\).*/\1/p')" "$(readlink -f "$b")"
b=$(command -v node) && say nodejs "$("$b" -v 2>/dev/null)" "$(readlink -f "$b")"
b=$(command -v openssl) && say openssl "$("$b" version 2>/dev/null | awk '{print $2}')" "$(readlink -f "$b")"
[ -f /www/server/panel/class/common.py ] && echo "aapanel=$(sed -n "s/.*g\.version = '\([0-9.]*\)'.*/\1/p" /www/server/panel/class/common.py | head -1)|-"
echo "kernel=$(uname -r)"
if command -v rpm >/dev/null 2>&1; then rpm -qa --qf 'pkg=%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE}\n'; elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='pkg=${'$'}{Package} ${'$'}{Version}\n'; fi
`;

const TARGET = /^[A-Za-z0-9._-]+@[A-Za-z0-9.:_-]+$|^[A-Za-z0-9.:_-]+$/;

/** Runs the version script on the server with the user's own SSH setup (key or agent, never a password). */
export function runProbe(ssh: SshTarget, timeoutMs = 30000): Promise<string> {
  if (!TARGET.test(ssh.target)) throw new Error(`"${ssh.target}" is not a user@host`);
  // BatchMode: never prompt (no passwords). Host keys are the user's own known_hosts: an unknown
  // host fails rather than being trusted silently.
  const args = ['-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10'];
  if (ssh.port) args.push('-p', String(ssh.port));
  if (ssh.identity) args.push('-i', ssh.identity.replace(/^~(?=\/)/, homedir()));
  args.push(ssh.target, 'sh -s');

  return new Promise((resolve, reject) => {
    // No shell: the target and key path are arguments, never parsed as commands.
    const child = spawn('ssh', args, { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => (out += d));
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => { clearTimeout(timer); reject(e); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code === 0 || out.includes('kernel=')) resolve(out);
      else reject(new Error(`ssh ${ssh.target} failed (${code ?? 'timed out'}): ${err.trim().split('\n').pop() ?? ''}`));
    });
    child.stdin.end(PROBE_SCRIPT);
  });
}

const OS: Record<string, string> = { almalinux: 'almalinux', rocky: 'rocky-linux', ubuntu: 'ubuntu', debian: 'debian' };
/** OSV's names for the distributions whose package advisories it carries. */
const OSV_ECOSYSTEM: Record<string, (major: string) => string> = { almalinux: (m) => `AlmaLinux:${m}`, rocky: (m) => `Rocky Linux:${m}`, debian: (m) => `Debian:${m}` };

/** key=value lines from the script -> components. Unknown or empty values are skipped. */
export function parseProbe(output: string, host: string): { components: Component[]; notes: string[] } {
  const components: Component[] = [];
  const notes: string[] = [];
  const source = `server ${host}`;
  const add = (name: string, product: string, raw: string | undefined) => {
    const [version, owner] = (raw ?? '').split('|');
    if (!version || !/^\d/.test(version)) return;
    if (components.some((c) => c.product === product && c.version === version)) return;
    components.push({ name, version, product, source, ...(owner && owner !== '-' ? { packaged: owner } : {}) });
  };
  const lines = output.split('\n');
  const osLine = lines.find((l) => l.startsWith('os='))?.slice(3).trim().split(' ') ?? [];
  const ecosystem = osLine[0] && osLine[1] ? OSV_ECOSYSTEM[osLine[0]]?.(osLine[1].split('.')[0]!) : undefined;
  const running = lines.find((l) => l.startsWith('kernel='))?.slice(7).trim();
  const packages: Component[] = [];

  for (const line of lines) {
    const at = line.indexOf('=');
    if (at < 1) continue;
    const key = line.slice(0, at).trim();
    const value = line.slice(at + 1).trim();
    switch (key) {
      case 'os': {
        const [id, version] = value.split(' ');
        if (id && OS[id]) add(id, OS[id]!, version);
        else if (id) notes.push(`OS ${value} is not tracked yet`);
        if (id && !OSV_ECOSYSTEM[id]) notes.push(`${id} packages are not checked yet (no advisory source for it)`);
        break;
      }
      case 'pkg': {
        if (!ecosystem) break;
        const [name, version] = value.split(' ');
        // rpm prints "(none):" when a package has no epoch.
        if (name && version) packages.push({ name, version: version.replace(/^\(none\):/, ''), ecosystem, source });
        break;
      }
      case 'php': add('php', 'php', value); break;
      case 'apache': add('apache', 'apache-http-server', value); break;
      case 'nginx': add('nginx', 'nginx', value); break;
      case 'db': {
        // "mysql  Ver 15.1 Distrib 10.6.18-MariaDB, for Linux" / "mysql  Ver 8.0.36 for Linux" / "mariadb from 11.4.2-MariaDB"
        const [text, owner = '-'] = value.split('|');
        const maria = text!.match(/(\d+\.\d+\.\d+)-MariaDB/i)?.[1];
        const mysql = text!.match(/Ver (\d+\.\d+\.\d+)/)?.[1];
        if (maria) add('mariadb', 'mariadb', `${maria}|${owner}`);
        else if (mysql) add('mysql', 'mysql', `${mysql}|${owner}`);
        break;
      }
      case 'postgresql': add('postgresql', 'postgresql', value); break;
      case 'redis': add('redis', 'redis', value); break;
      case 'nodejs': add('node', 'nodejs', value.replace(/^v/, '')); break;
      case 'openssl': {
        // "3.2.2|openssl" or "3.0.13-fips|-": keep the version's numbers and the owner.
        const [text, owner = '-'] = value.split('|');
        const version = text!.match(/^\d+\.\d+\.\d+/)?.[0];
        if (version) add('openssl', 'openssl', `${version}|${owner}`);
        break;
      }
      case 'aapanel': add('aapanel', 'aapanel', value); break;
    }
  }

  // Installed kernels that are not running don't matter; the running one is what an attacker meets.
  if (packages.length) {
    const kernels = packages.filter((p) => /^kernel(-core|-modules.*)?$/.test(p.name));
    const runningVersion = running?.replace(/\.(x86_64|aarch64|ppc64le|s390x|noarch)$/, '');
    const others = packages.filter((p) => !p.name.startsWith('kernel'));
    if (runningVersion) others.push({ name: 'kernel', version: runningVersion, ecosystem: ecosystem!, source, note: 'running kernel' });
    const newest = kernels.map((k) => k.version.replace(/^\d+:/, '')).sort().pop();
    if (runningVersion && newest && newest !== runningVersion && newest > runningVersion) notes.push(`a newer kernel (${newest}) is installed but ${runningVersion} is running: reboot to use it`);
    components.push(...others);
    notes.push(`${others.length} ${ecosystem} packages read from the server`);
  } else if (running) {
    notes.push(`kernel ${running}`);
  }
  return { components, notes };
}
