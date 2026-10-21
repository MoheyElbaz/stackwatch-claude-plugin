// SPDX-License-Identifier: GPL-3.0-or-later
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import type { Component } from './types.ts';

/** Directories that hold installed copies, build output or data rather than the project's own lockfiles. */
const SKIP = new Set(['node_modules', 'vendor', '.git', 'storage', 'dist', 'build', 'public', 'coverage', '.next', '.nuxt', '.cache', 'bootstrap']);
const MAX_DEPTH = 5;

export interface Detection {
  components: Component[];
  /** Lockfiles read, relative to the project. */
  files: string[];
  /** Things found that need a human: runtimes without an exact version, lockfiles not read yet. */
  hints: string[];
}

export function detect(root: string, exclude: string[] = []): Detection {
  const result: Detection = { components: [], files: [], hints: [] };
  const excluded = (rel: string) => exclude.some((e) => rel === e || rel.startsWith(e.replace(/\/+$/, '') + '/'));

  const walk = (dir: string, depth: number) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      const rel = relative(root, path).split(sep).join('/');
      if (excluded(rel)) continue;
      if (entry.isDirectory()) {
        if (depth < MAX_DEPTH && !SKIP.has(entry.name) && !entry.name.startsWith('.') && !entry.name.endsWith('.worktrees')) walk(path, depth + 1);
        continue;
      }
      if (!entry.isFile()) continue;
      try {
        read(entry.name, path, rel, result);
      } catch (error) {
        result.hints.push(`${rel}: could not be read (${(error as Error).message})`);
      }
    }
  };

  walk(root, 0);
  result.components = dedupe(result.components);
  return result;
}

function read(name: string, path: string, rel: string, result: Detection): void {
  switch (name) {
    case 'composer.lock':
      result.files.push(rel);
      result.components.push(...composerLock(JSON.parse(readFileSync(path, 'utf8')), rel));
      break;
    case 'package-lock.json':
      result.files.push(rel);
      result.components.push(...npmLock(JSON.parse(readFileSync(path, 'utf8')), rel));
      break;
    case 'composer.json': {
      const php = (JSON.parse(readFileSync(path, 'utf8')) as { require?: Record<string, string> }).require?.php;
      if (php) result.hints.push(`${rel} requires PHP ${php}: add the exact PHP the server runs as a manual component (product "php")`);
      break;
    }
    case 'package.json': {
      const node = (JSON.parse(readFileSync(path, 'utf8')) as { engines?: Record<string, string> }).engines?.node;
      if (node) result.hints.push(`${rel} expects Node ${node}: add the exact Node version as a manual component (product "nodejs")`);
      break;
    }
    case '.php-version':
    case '.nvmrc':
    case '.node-version': {
      const version = readFileSync(path, 'utf8').trim().replace(/^v/, '');
      const runtime = runtimeComponent(name === '.php-version' ? 'php' : 'nodejs', version, rel);
      if (runtime) result.components.push(runtime);
      if (runtime) result.files.push(rel);
      break;
    }
    case '.tool-versions':
      for (const line of readFileSync(path, 'utf8').split('\n')) {
        const [tool, version] = line.trim().split(/\s+/);
        const product = tool ? TOOLS[tool] : undefined;
        const runtime = product && version ? runtimeComponent(product, version, rel) : null;
        if (runtime) result.components.push(runtime);
      }
      result.files.push(rel);
      break;
    default:
      if (name === 'Dockerfile' || /^Dockerfile\.|\.Dockerfile$/.test(name)) {
        result.files.push(rel);
        for (const line of readFileSync(path, 'utf8').split('\n')) image(line.match(/^\s*FROM\s+(?:--\S+\s+)*(\S+)/i)?.[1], rel, result);
      } else if (/^(docker-)?compose([.-][\w.-]+)?\.ya?ml$/.test(name)) {
        result.files.push(rel);
        for (const line of readFileSync(path, 'utf8').split('\n')) image(line.match(/^\s*image:\s*["']?([^"'\s#]+)/)?.[1], rel, result);
      }
      break;
    case 'yarn.lock':
    case 'pnpm-lock.yaml':
    case 'bun.lockb':
      result.hints.push(`${rel} is not read yet: its packages are not checked`);
      break;
  }
}

/** .tool-versions (asdf / mise) names. */
const TOOLS: Record<string, string> = { php: 'php', nodejs: 'nodejs', node: 'nodejs', postgres: 'postgresql', postgresql: 'postgresql', mysql: 'mysql', redis: 'redis', nginx: 'nginx' };

/** Official Docker image names -> products. */
const IMAGES: Record<string, string> = {
  php: 'php', node: 'nodejs', mysql: 'mysql', mariadb: 'mariadb', postgres: 'postgresql', redis: 'redis', nginx: 'nginx',
  httpd: 'apache-http-server', ubuntu: 'ubuntu', debian: 'debian', almalinux: 'almalinux', 'rockylinux': 'rocky-linux',
};

/** "php:8.3.20-fpm-alpine" -> php 8.3.20; "mysql:8.0" -> mysql 8.0 (release line only); "redis:latest" -> a hint. */
function image(ref: string | undefined, rel: string, result: Detection): void {
  if (!ref || ref.includes('$')) return;
  const [path, tag = 'latest'] = ref.split('@')[0]!.split(':');
  const name = path!.split('/').pop()!;
  const product = IMAGES[name] ?? (path!.startsWith('library/') ? IMAGES[path!.slice(8)] : undefined);
  if (!product) return;
  const runtime = runtimeComponent(product, tag, rel);
  if (runtime) result.components.push(runtime);
  else result.hints.push(`${rel} uses ${ref}: the tag doesn't say which ${product} version runs; pin it or add it by hand`);
}

/** A runtime from a version file or an image tag; only the leading version is kept ("8.3.20-fpm" -> "8.3.20"). */
function runtimeComponent(product: string, raw: string, source: string): Component | null {
  const version = raw.match(/^v?(\d+(?:\.\d+){0,3})/)?.[1];
  if (!version) return null;
  const parts = version.split('.').length;
  // OS releases are two parts (almalinux 9.6); everything else needs a patch number to judge fixes.
  const exact = ['almalinux', 'rocky-linux', 'ubuntu', 'debian'].includes(product) ? parts >= 2 : parts >= 3;
  return { name: product, version, product, source, ...(exact ? {} : { exact: false as const }) };
}

interface ComposerPackage { name?: string; version?: string }

export function composerLock(lock: { packages?: ComposerPackage[]; 'packages-dev'?: ComposerPackage[] }, source: string): Component[] {
  const pick = (list: ComposerPackage[] | undefined, dev: boolean): Component[] =>
    (list ?? [])
      .filter((p) => p.name && p.version)
      .map((p) => ({ name: p.name!, version: p.version!, ecosystem: 'Packagist' as const, ...(dev ? { dev } : {}), source }));
  return [...pick(lock.packages, false), ...pick(lock['packages-dev'], true)];
}

interface NpmEntry { name?: string; version?: string; dev?: boolean; link?: boolean; dependencies?: Record<string, NpmEntry> }

export function npmLock(lock: { packages?: Record<string, NpmEntry>; dependencies?: Record<string, NpmEntry> }, source: string): Component[] {
  const out: Component[] = [];
  const add = (name: string, entry: NpmEntry) => {
    if (!entry.version || entry.link) return;
    out.push({ name, version: entry.version, ecosystem: 'npm', ...(entry.dev ? { dev: true } : {}), source });
  };
  if (lock.packages) {
    // lockfileVersion 2 and 3: keys are install paths ("node_modules/a/node_modules/b"); "" is the project itself.
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (!path.includes('node_modules/')) continue;
      add(entry.name ?? path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length), entry);
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, NpmEntry>) => {
      for (const [name, entry] of Object.entries(deps)) {
        add(name, entry);
        if (entry.dependencies) walk(entry.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return out;
}

function dedupe(components: Component[]): Component[] {
  // A release line ("node:20") says less than an exact version of it found elsewhere (.tool-versions 22.11.0).
  components = components.filter(
    (c) => c.exact !== false || !components.some((o) => o !== c && o.product === c.product && o.exact !== false && (o.version === c.version || o.version.startsWith(`${c.version}.`))),
  );
  const byKey = new Map<string, Component>();
  for (const c of components) {
    const key = `${c.ecosystem ?? c.product}:${c.name}@${c.version}`;
    const prev = byKey.get(key);
    // Deployed beats dev-only when the same version appears both ways.
    if (!prev || (prev.dev && !c.dev)) byKey.set(key, c);
  }
  return [...byKey.values()].sort((a, b) => `${a.ecosystem ?? ''}${a.name}`.localeCompare(`${b.ecosystem ?? ''}${b.name}`));
}
