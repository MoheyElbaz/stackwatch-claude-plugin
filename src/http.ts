// SPDX-License-Identifier: GPL-3.0-or-later
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { cacheDir } from './paths.ts';

const USER_AGENT = 'stackwatch/0.1.1 (+https://github.com/MoheyElbaz/stackwatch-claude-plugin)';

export interface Fetched {
  body: string;
  /** Answered from cache after the source failed. */
  stale: boolean;
}

interface Cached {
  url: string;
  fetchedAt: number;
  etag?: string;
  lastModified?: string;
  body: string;
}

export interface FetchOptions {
  /** Serve from cache without asking the source while younger than this. */
  ttlMs: number;
  timeoutMs?: number;
  method?: 'GET' | 'POST';
  body?: string;
  /** Overrides the cache file name (default: a hash of method, url and body). */
  cacheKey?: string;
  /** Never ask the source: answer from cache whatever its age, or fail. For slow sources in a hurry. */
  cacheOnly?: boolean;
  headers?: Record<string, string>;
}

/**
 * A GET or POST that keeps its answer on disk: fresh copies are served without a request,
 * older ones are revalidated with ETag / Last-Modified, and when the source is down the
 * last copy is served marked stale instead of failing the whole check.
 */
export async function fetchCached(url: string, options: FetchOptions): Promise<Fetched> {
  const method = options.method ?? 'GET';
  const key = options.cacheKey ?? createHash('sha256').update(`${method} ${url} ${options.body ?? ''}`).digest('hex').slice(0, 32);
  const file = join(cacheDir(), `${key.replace(/[^a-zA-Z0-9._-]/g, '_')}.json`);
  const cached = readCache(file);

  if (cached && Date.now() - cached.fetchedAt < options.ttlMs) return { body: cached.body, stale: false };
  if (options.cacheOnly) {
    if (cached) return { body: cached.body, stale: false };
    throw new Error(`${new URL(url).host}: not fetched yet`);
  }

  const headers: Record<string, string> = { 'user-agent': USER_AGENT, accept: 'application/json, application/atom+xml, application/xml;q=0.9, */*;q=0.5' };
  if (options.body) headers['content-type'] = 'application/json';
  Object.assign(headers, options.headers);
  if (cached?.etag) headers['if-none-match'] = cached.etag;
  if (cached?.lastModified) headers['if-modified-since'] = cached.lastModified;

  try {
    const res = await fetch(url, { method, headers, body: options.body, signal: AbortSignal.timeout(options.timeoutMs ?? 15000) });
    if (res.status === 304 && cached) {
      writeCache(file, { ...cached, fetchedAt: Date.now() });
      return { body: cached.body, stale: false };
    }
    if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
    const body = await res.text();
    writeCache(file, {
      url,
      fetchedAt: Date.now(),
      etag: res.headers.get('etag') ?? undefined,
      lastModified: res.headers.get('last-modified') ?? undefined,
      body,
    });
    return { body, stale: false };
  } catch (error) {
    if (cached) return { body: cached.body, stale: true };
    throw new Error(`${new URL(url).host}: ${(error as Error).message}`);
  }
}

function readCache(file: string): Cached | null {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Cached;
  } catch {
    return null;
  }
}

function writeCache(file: string, entry: Cached): void {
  mkdirSync(cacheDir(), { recursive: true, mode: 0o700 });
  writeFileSync(file, JSON.stringify(entry), { mode: 0o600 });
}

/** Runs fn over items with at most `limit` in flight. */
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}
