// SPDX-License-Identifier: GPL-3.0-or-later
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { localSourcesFile } from './paths.ts';
import type { Registry, Source } from './types.ts';

const TYPES = new Set(['feed', 'osv', 'kev', 'endoflife', 'nvd']);

/** sources.json ships beside the bundle (plugin/dist -> plugin/) and beside src (src -> plugin/). */
function shippedFile(): string {
  if (process.env.STACKWATCH_SOURCES) return process.env.STACKWATCH_SOURCES;
  for (const rel of ['../sources.json', '../plugin/sources.json']) {
    const path = fileURLToPath(new URL(rel, import.meta.url));
    if (existsSync(path)) return path;
  }
  throw new Error('sources.json was not found next to stackwatch');
}

function readRegistry(file: string): Partial<Registry> {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Partial<Registry>;
  } catch (error) {
    throw new Error(`${file}: ${(error as Error).message}`);
  }
}

/**
 * The shipped sources and products, with ~/.stackwatch/sources.json merged over them: an entry
 * with a known id changes that source (e.g. {"id": "thehackernews", "enabled": false}), a new id
 * adds one.
 */
export function loadRegistry(): Registry {
  const shipped = readRegistry(shippedFile());
  const local = existsSync(localSourcesFile()) ? readRegistry(localSourcesFile()) : {};

  const sources = new Map<string, Source>();
  for (const s of [...(shipped.sources ?? []), ...(local.sources ?? [])]) sources.set(s.id, { ...sources.get(s.id), ...s });

  const enabled = [...sources.values()].filter((s) => s.enabled !== false);
  for (const s of enabled) {
    if (!s.id || !TYPES.has(s.type) || !/^https:\/\//.test(s.url ?? '')) {
      throw new Error(`source ${JSON.stringify(s.id)} needs an id, a type (${[...TYPES].join(', ')}) and an https url`);
    }
    s.name ||= s.id;
  }
  return { sources: enabled, products: { ...(shipped.products ?? {}), ...(local.products ?? {}) } };
}
