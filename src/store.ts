// SPDX-License-Identifier: GPL-3.0-or-later
import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dataFile, home } from './paths.ts';
import type { Component, Data, Level, Stack } from './types.ts';

export function emptyData(): Data {
  return { version: 1, stacks: {}, items: [] };
}

export function loadData(): Data {
  let raw: string;
  try {
    raw = readFileSync(dataFile(), 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return emptyData();
    throw error;
  }
  try {
    const data = JSON.parse(raw) as Partial<Data>;
    return { version: 1, stacks: data.stacks ?? {}, items: data.items ?? [], lastRefresh: data.lastRefresh, problems: data.problems, settings: data.settings };
  } catch (error) {
    // Refuse rather than start empty: saving over it would lose every stack and read mark.
    throw new Error(`${dataFile()} is not valid JSON (${(error as Error).message}); fix or move it`);
  }
}

/** Written to a temporary file and renamed, so a hook and a tool writing at once never leave half a file. */
export function saveData(data: Data): void {
  mkdirSync(home(), { recursive: true, mode: 0o700 });
  const tmp = `${dataFile()}.${process.pid}.tmp`;
  writeFileSync(tmp, JSON.stringify(data, null, 1), { mode: 0o600 });
  renameSync(tmp, dataFile());
}

export function updateData<T>(change: (data: Data) => T): T {
  const data = loadData();
  const result = change(data);
  saveData(data);
  return result;
}

/** Project names are keys a person types, so only a plain slug is accepted. */
export function projectName(raw: string): string {
  const name = raw.trim().toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^[-.]+|-+$/g, '');
  if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(name)) throw new Error(`"${raw}" can't be used as a project name`);
  return name;
}

export function componentKey(c: Component): string {
  return `${c.ecosystem ?? c.product ?? 'other'}:${c.name}`;
}

/**
 * What a project runs on. For a runtime the most direct source wins: what was typed by hand, then
 * what the server reported, then what the project's files suggest (a Docker tag may be stale).
 */
export function componentsOf(stack: Stack): Component[] {
  const out: Component[] = [];
  const seen = new Set<string>();
  const productsFrom = new Map<string, string>();
  for (const [origin, list] of [['manual', stack.manual], ['probed', stack.probed ?? []], ['detected', stack.detected]] as const) {
    for (const c of list) {
      const owner = c.product ? productsFrom.get(c.product) : undefined;
      if (owner && owner !== origin) continue;
      if (c.product) productsFrom.set(c.product, origin);
      const key = `${componentKey(c)}@${c.version}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(c);
    }
  }
  return out;
}

export const LEVEL_DEFAULT: Level = 'high';

/** The lowest level that raises an alert for a project. */
export function alertLevelFor(data: Data, project: string): Level {
  return data.stacks[project]?.alertLevel ?? data.settings?.alertLevel ?? LEVEL_DEFAULT;
}
