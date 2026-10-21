// SPDX-License-Identifier: GPL-3.0-or-later
import { homedir } from 'node:os';
import { join } from 'node:path';

/** Everything stackwatch keeps lives here, outside any repository. */
export function home(): string {
  return process.env.STACKWATCH_HOME || join(homedir(), '.stackwatch');
}

/** Stacks, news, findings and read marks. */
export const dataFile = (): string => join(home(), 'data.json');
/** The user's own sources and products, merged over the shipped sources.json. */
export const localSourcesFile = (): string => join(home(), 'sources.json');
export const cacheDir = (): string => join(home(), 'cache');
export const logFile = (): string => join(home(), 'stackwatch.log');
