// SPDX-License-Identifier: GPL-3.0-or-later
import { appendFileSync, mkdirSync } from 'node:fs';
import { UNTRUSTED_NOTE, actionsOf, alertIssues, renderAlerts, type Issue } from './format.ts';
import { home, logFile } from './paths.ts';
import { loadRegistry } from './registry.ts';
import { refresh } from './refresh.ts';
import { alertLevelFor, loadData } from './store.ts';

const STALE_MS = 60 * 60_000;
/** A session waits at most this long for a refresh; past it, the last stored result is shown. */
const BUDGET_MS = 20_000;

export interface HookOutput {
  systemMessage?: string;
  hookSpecificOutput?: { hookEventName: 'SessionStart'; additionalContext: string };
}

/**
 * Runs when a Claude Code session starts. Refreshes when the last check is over an hour old, then
 * raises every unread alert at or above each project's level (high by default; they repeat each
 * session until marked read) and reminds in one line about alerts that were read but are still
 * open. Never fails the session.
 */
export async function sessionStartHook(now = Date.now(), doRefresh: () => Promise<unknown> = () => refresh({ timeoutMs: 6000, quick: true })): Promise<HookOutput | null> {
  try {
    const before = loadData();
    if (!Object.keys(before.stacks).length) return null;
    if (!before.lastRefresh || now - Date.parse(before.lastRefresh) > STALE_MS) {
      await Promise.race([doRefresh().catch((error: Error) => log(`refresh: ${error.message}`)), new Promise((r) => setTimeout(r, BUDGET_MS).unref())]);
    }

    const data = loadData();
    const issues = alertIssues(data.items, (project) => alertLevelFor(data, project));
    const unread = issues.filter((i) => !i.top.read);
    const open = issues.length - unread.length;
    if (!issues.length) return null;
    if (!unread.length) return { systemMessage: `stackwatch: ${open} security alert${open === 1 ? '' : 's'} read but still open. /stackwatch:check` };

    const names = new Map(loadRegistry().sources.map((s) => [s.id, s.name]));
    return {
      systemMessage: message(unread, open),
      hookSpecificOutput: {
        hookEventName: 'SessionStart',
        additionalContext: [
          '<stackwatch-alerts>',
          `stackwatch has ${unread.length} unread security alert(s) for the user's projects (at or above each project's alert level).`,
          'Mention them briefly at the start of your reply and offer the security-check skill for details and fixes. They stay unread until the user marks them read.',
          UNTRUSTED_NOTE,
          '',
          renderAlerts(unread, (id) => names.get(id) ?? id, 6),
          '</stackwatch-alerts>',
        ].join('\n'),
      },
    };
  } catch (error) {
    log(`hook: ${(error as Error).stack ?? error}`);
    return null;
  }
}

function message(unread: Issue[], open: number): string {
  const top = unread[0]!.top;
  const m = top.matches.find((x) => !x.dev) ?? top.matches[0]!;
  const what = `${top.level.toUpperCase()}${top.exploited ? ', exploited' : ''}: ${m.project} · ${m.component} ${m.version}${m.fixed ? ` → ${m.fixed}` : ''}`;
  const actions = actionsOf(unread);
  return `stackwatch: ${unread.length} unread security alert${unread.length === 1 ? '' : 's'} (${actions} thing${actions === 1 ? '' : 's'} to fix)${open ? `, +${open} read but open` : ''}. ${what}. /stackwatch:check`;
}

export function log(line: string): void {
  try {
    mkdirSync(home(), { recursive: true, mode: 0o700 });
    appendFileSync(logFile(), `[${new Date().toISOString()}] ${line}\n`, { mode: 0o600 });
  } catch {
    // Logging must never be the thing that breaks a session.
  }
}
