// SPDX-License-Identifier: GPL-3.0-or-later
import { existsSync, statSync } from 'node:fs';
import { basename, resolve } from 'node:path';
import { detect } from './detect.ts';
import { UNTRUSTED_NOTE, actionsOf, alertIssues, atLeast, countByLevel, countIssues, issuesOf, projectRisk, renderAlerts, renderItem, sortItems, type SourceName } from './format.ts';
import { productOf } from './match.ts';
import { parseProbe, runProbe } from './probe.ts';
import { loadRegistry } from './registry.ts';
import { refresh, rematch } from './refresh.ts';
import { LEVEL_DEFAULT, alertLevelFor, componentKey, componentsOf, loadData, projectName, updateData } from './store.ts';
import { LEVELS, type Component, type Data, type Item, type Level, type SshTarget, type Stack } from './types.ts';

/** The operations behind both the CLI and the MCP tools; each returns the text to show. */

const STALE_MS = 60 * 60_000;

// ---- projects ---------------------------------------------------------------------------------

export interface InitOptions {
  name?: string;
  exclude?: string[];
  /** The server the project runs on, to read its runtime versions over SSH. */
  ssh?: SshTarget;
  alertLevel?: Level;
}

/**
 * Registers a project in one go: reads its lockfiles and runtime files, reads the server's
 * runtime versions when an SSH target is given, checks everything against the sources, and
 * reports the project's risk with its alerts.
 */
export async function initProject(path: string, options: InitOptions = {}): Promise<string> {
  const root = resolve(path);
  if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`${root} is not a directory`);
  const project = projectName(options.name ?? basename(root));
  const existing = loadData().stacks[project];
  const ssh = options.ssh ?? existing?.ssh;
  const exclude = options.exclude?.length ? options.exclude : (existing?.exclude ?? []);

  const found = detect(root, exclude);
  const probe = ssh ? await probeServer(ssh) : null;

  const stack = changeStacks((data) => {
    const stack: Stack = {
      project,
      path: root,
      updated: new Date().toISOString(),
      exclude,
      detected: found.components,
      ...(probe?.components ? { probed: probe.components } : existing?.probed ? { probed: existing.probed } : {}),
      manual: existing?.manual ?? [],
      ...(ssh ? { ssh } : {}),
      ...((options.alertLevel ?? existing?.alertLevel) ? { alertLevel: options.alertLevel ?? existing?.alertLevel } : {}),
    };
    data.stacks[project] = stack;
    return stack;
  });

  const packages = stack.detected.filter((c) => c.ecosystem);
  const deployed = packages.filter((c) => !c.dev);
  const runtimes = componentsOf(stack).filter((c) => c.product);
  const lines = [
    `${existing ? 'Re-scanned' : 'Registered'} "${project}" from ${root}`,
    `Files read: ${found.files.join(', ') || 'no lockfiles'}`,
    `Packages: ${byEcosystem(deployed)} deployed, ${packages.length - deployed.length} dev-only`,
    `Runtimes and servers: ${runtimes.length ? runtimes.map(label).join(', ') : 'none found'}`,
  ];
  if (probe?.error) lines.push(`! Server check failed: ${probe.error}`);
  const hints = [...found.hints, ...(probe?.notes ?? [])];
  if (hints.length) lines.push('', 'Notes:', ...hints.map((h) => `- ${h}`));
  if (!ssh && !runtimes.some((c) => c.exact !== false)) {
    lines.push('', "No server versions yet. Give the server (--ssh user@host) to read them, or add each by hand:",
      `  stackwatch add ${project} php 8.3.20 --product php`);
  }

  lines.push('', await checkSummary(project));
  return lines.join('\n');
}

export async function updateProjects(project?: string): Promise<string> {
  const data = loadData();
  const stacks = project ? [requireStack(data, project)] : Object.values(data.stacks).filter((s) => s.path || s.ssh);
  if (!stacks.length) return 'No projects yet. Run init first.';
  const reports: string[] = [];
  for (const stack of stacks) reports.push(await rescan(stack));
  reports.push('', await checkSummary(project));
  return reports.join('\n\n');
}

async function rescan(stack: Stack): Promise<string> {
  const found = stack.path && existsSync(stack.path) ? detect(stack.path, stack.exclude ?? []) : null;
  const probe = stack.ssh ? await probeServer(stack.ssh) : null;

  return changeStacks((data) => {
    const current = data.stacks[stack.project] ?? stack;
    const next: Stack = {
      ...current,
      detected: found?.components ?? current.detected,
      ...(probe?.components ? { probed: probe.components } : {}),
      updated: new Date().toISOString(),
    };
    data.stacks[stack.project] = next;

    const changes = diff([...current.detected, ...(current.probed ?? [])], [...next.detected, ...(next.probed ?? [])]);
    const lines = [`${stack.project}: ${changes.length ? `${changes.length} change${changes.length === 1 ? '' : 's'}` : 'no changes'}`];
    if (!found && stack.path) lines.push(`! its folder ${stack.path} is gone; re-init it from its new place`);
    if (probe?.error) lines.push(`! server check failed: ${probe.error}`);
    lines.push(...changes.slice(0, 60), ...(changes.length > 60 ? [`… and ${changes.length - 60} more`] : []));
    return lines.join('\n');
  });
}

function diff(before: Component[], after: Component[]): string[] {
  const key = (c: Component) => `${componentKey(c)}|${c.source.startsWith('server') ? 'server' : 'files'}`;
  const was = new Map(before.map((c) => [key(c), c]));
  const now = new Map(after.map((c) => [key(c), c]));
  const changes: string[] = [];
  // OS packages change by the hundred: counted per OS, not listed.
  const os = new Map<string, { added: number; removed: number; changed: number }>();
  const tally = (c: Component, field: 'added' | 'removed' | 'changed') => {
    const t = os.get(c.ecosystem!) ?? { added: 0, removed: 0, changed: 0 };
    t[field]++;
    os.set(c.ecosystem!, t);
  };
  const isOs = (c: Component) => !!c.ecosystem?.includes(':');
  for (const [k, c] of now) {
    const old = was.get(k);
    if (!old) isOs(c) ? tally(c, 'added') : changes.push(`+ ${label(c)}`);
    else if (old.version !== c.version) isOs(c) ? tally(c, 'changed') : changes.push(`~ ${c.name} ${old.version} → ${c.version}`);
  }
  for (const [k, c] of was) if (!now.has(k)) isOs(c) ? tally(c, 'removed') : changes.push(`- ${label(c)}`);
  for (const [ecosystem, t] of os) {
    changes.push(`± ${ecosystem} packages: ${[t.added && `${t.added} new`, t.changed && `${t.changed} updated`, t.removed && `${t.removed} removed`].filter(Boolean).join(', ')}`);
  }
  return changes;
}

async function probeServer(ssh: SshTarget): Promise<{ components?: Component[]; notes: string[]; error?: string }> {
  try {
    const host = ssh.target.split('@').pop()!;
    return parseProbe(await runProbe(ssh), host);
  } catch (error) {
    return { notes: [], error: (error as Error).message };
  }
}

export function addComponent(project: string, component: Omit<Component, 'source'>): string {
  const registry = loadRegistry();
  if (component.product && !registry.products[component.product]) {
    throw new Error(`unknown product "${component.product}". Known: ${Object.keys(registry.products).join(', ')} (add others under "products" in ~/.stackwatch/sources.json)`);
  }
  return changeStacks((data) => {
    const stack = requireStack(data, project);
    const entry: Component = { ...component, source: 'manual' };
    const manual = stack.manual.filter((c) => !(c.name === entry.name && (c.product ?? c.ecosystem) === (entry.product ?? entry.ecosystem)));
    data.stacks[stack.project] = { ...stack, manual: [...manual, entry], updated: new Date().toISOString() };
    return `${manual.length !== stack.manual.length ? 'Updated' : 'Added'} ${label(entry)} in "${stack.project}"`;
  });
}

export function removeComponent(project: string, name: string): string {
  return changeStacks((data) => {
    const stack = requireStack(data, project);
    const manual = stack.manual.filter((c) => c.name !== name);
    if (manual.length === stack.manual.length) return `"${stack.project}" has nothing added by hand named ${name}`;
    data.stacks[stack.project] = { ...stack, manual, updated: new Date().toISOString() };
    return `Removed ${name} from "${stack.project}"`;
  });
}

/** The lowest level that raises an alert: for one project, or for every project without its own. */
export function setAlertLevel(level: Level, project?: string): string {
  if (!LEVELS.includes(level) || level === 'info') throw new Error(`level must be one of ${LEVELS.filter((l) => l !== 'info').join(', ')}`);
  return updateData((data) => {
    if (project) {
      const stack = requireStack(data, project);
      data.stacks[stack.project] = { ...stack, alertLevel: level };
      return `"${stack.project}" now alerts on ${level} and above.`;
    }
    data.settings = { ...data.settings, alertLevel: level };
    return `Projects without their own level now alert on ${level} and above.`;
  });
}

export function describeProjects(): string {
  const data = loadData();
  const stacks = Object.values(data.stacks);
  if (!stacks.length) return 'No projects yet. Run init on a project folder.';
  const registry = loadRegistry();
  return [
    `Alerts are raised at ${data.settings?.alertLevel ?? LEVEL_DEFAULT} and above unless a project sets its own.`,
    ...stacks.map((s) => {
      const packages = s.detected.filter((c) => c.ecosystem);
      const deployed = packages.filter((c) => !c.dev);
      const frameworks = [...new Set(deployed.map((c) => productOf(c, registry)).filter(Boolean))];
      const runtimes = componentsOf(s).filter((c) => c.product);
      return [
        '',
        `${s.project} · ${projectRisk(data.items, s.project)} · alerts at ${alertLevelFor(data, s.project)}+`,
        `  folder: ${s.path ?? 'none'}${s.ssh ? ` · server: ${s.ssh.target}${s.ssh.port ? `:${s.ssh.port}` : ''}` : ''} · updated ${s.updated.slice(0, 10)}`,
        `  packages: ${byEcosystem(deployed)} deployed, ${packages.length - deployed.length} dev-only${frameworks.length ? ` (incl. ${frameworks.join(', ')})` : ''}`,
        `  runtimes: ${runtimes.map(label).join(', ') || 'none'}`,
      ].join('\n');
    }),
  ].join('\n');
}

/** Saves a stack change and re-matches stored news against it, so the next view is already right. */
function changeStacks<T>(change: (data: Data) => T): T {
  return updateData((data) => {
    const result = change(data);
    data.items = rematch(data.items, Object.values(data.stacks));
    // Findings come from OSV / endoflife.date for exact versions: recompute them at the next view.
    data.lastRefresh = undefined;
    return result;
  });
}

// ---- news and alerts --------------------------------------------------------------------------

async function fresh(force = false): Promise<{ data: Data; problems: string[] }> {
  const data = loadData();
  if (force || !data.lastRefresh || Date.now() - Date.parse(data.lastRefresh) > STALE_MS) {
    const result = await refresh();
    return { data: loadData(), problems: result.problems };
  }
  return { data, problems: data.problems ?? [] };
}

function names(): SourceName {
  const map = new Map(loadRegistry().sources.map((s) => [s.id, s.name]));
  return (id) => map.get(id) ?? id;
}

const levelsOf = (data: Data) => (project: string) => alertLevelFor(data, project);
const inProject = (project?: string) => (i: Item) => !project || i.matches.some((m) => m.project === projectName(project));

/** Checks now and reports each project's risk and its unread alerts. */
async function checkSummary(project?: string): Promise<string> {
  const { data, problems } = await fresh(true);
  const projects = project ? [projectName(project)] : Object.keys(data.stacks);
  const alerts = alertIssues(data.items, levelsOf(data)).filter((i) => !i.top.read && inProject(project)(i.top));
  return [
    ...projects.map((p) => `${p} · ${projectRisk(data.items, p)} · ${alerts.filter((i) => inProject(p)(i.top)).length} unread alert(s) at ${alertLevelFor(data, p)}+`),
    ...problems.map((p) => `! ${p}`),
    ...(alerts.length ? [UNTRUSTED_NOTE, '', renderAlerts(alerts, names(), 6)] : []),
  ].join('\n');
}

export async function refreshNow(): Promise<string> {
  const { data, problems } = await fresh(true);
  const alerts = alertIssues(data.items, levelsOf(data)).filter((i) => !i.top.read);
  return [
    `Read ${loadRegistry().sources.length} sources. ${data.items.length} items stored; ${alerts.length} unread alert${alerts.length === 1 ? '' : 's'}.`,
    ...Object.keys(data.stacks).map((p) => `${p} · ${projectRisk(data.items, p)}`),
    ...problems.map((p) => `! ${p}`),
  ].join('\n');
}

export async function alertsReport(options: { project?: string; includeRead?: boolean } = {}): Promise<{ text: string; items: Item[] }> {
  const { data, problems } = await fresh();
  const alerts = alertIssues(data.items, levelsOf(data)).filter((i) => inProject(options.project)(i.top));
  const unreadIssues = alerts.filter((i) => !i.top.read);
  const shown = options.includeRead ? alerts : unreadIssues;
  const projects = options.project ? [projectName(options.project)] : Object.keys(data.stacks);
  const readOpen = alerts.length - unreadIssues.length;
  const lines = [
    `${unreadIssues.length ? `${unreadIssues.length} unread security alert${unreadIssues.length === 1 ? '' : 's'} (${countIssues(unreadIssues)}), ${actionsOf(unreadIssues)} thing${actionsOf(unreadIssues) === 1 ? '' : 's'} to fix` : 'No unread security alerts'}` +
      (readOpen > 0 ? `; ${readOpen} read but still open` : '') +
      ` · last check ${data.lastRefresh?.slice(0, 16).replace('T', ' ') ?? 'never'} UTC`,
    ...projects.map((p) => `${p} · ${projectRisk(data.items, p)} · alerts at ${alertLevelFor(data, p)}+`),
    ...problems.map((p) => `! ${p}`),
  ];
  if (shown.length) lines.push(UNTRUSTED_NOTE, '', renderAlerts(shown, names()));
  return { text: lines.join('\n'), items: shown.map((i) => i.top) };
}

export async function newsReport(options: { all?: boolean; source?: string; project?: string; product?: string; min?: Level; limit?: number } = {}): Promise<string> {
  const { data, problems } = await fresh();
  const registry = loadRegistry();
  // Components of that product in any project ("php" -> the php runtime; "laravel" -> laravel/framework).
  const ofProduct = new Set(
    Object.values(data.stacks).flatMap((s) => componentsOf(s).filter((c) => productOf(c, registry) === options.product).map((c) => c.name)),
  );
  const items = sortItems(
    data.items.filter(
      (i) =>
        (options.all || !i.read) &&
        (!options.source || i.source === options.source) &&
        atLeast(i.level, options.min ?? 'low') &&
        inProject(options.project)(i) &&
        (!options.product || i.matches.some((m) => ofProduct.has(m.component))),
    ),
  );
  const limit = options.limit ?? 20;
  const head = `${items.length} ${options.all ? '' : 'unread '}item${items.length === 1 ? '' : 's'} (${countByLevel(items)})${items.length > limit ? `, showing ${limit}` : ''}`;
  return [head, ...problems.map((p) => `! ${p}`), ...(items.length ? [UNTRUSTED_NOTE, '', items.slice(0, limit).map((i) => renderItem(i, names())).join('\n\n')] : [])].join('\n');
}

export function markRead(options: { ids?: string[]; all?: boolean; source?: string; alerts?: boolean; note?: string }): string {
  if (!options.ids?.length && !options.all && !options.source && !options.alerts) throw new Error('say which: ids, all, source or alerts');
  return updateData((data) => {
    // An id stands for its whole issue: reading the php.net advisory also reads the news about it.
    const wanted = new Set(options.ids ?? []);
    const levels = levelsOf(data);
    if (options.alerts) for (const issue of alertIssues(data.items, levels)) for (const i of issue.items) wanted.add(i.id);
    for (const issue of issuesOf(data.items)) if (issue.items.some((i) => wanted.has(i.id))) for (const i of issue.items) wanted.add(i.id);
    const at = new Date().toISOString();
    let count = 0;
    data.items = data.items.map((i) => {
      const hit = options.all || wanted.has(i.id) || (options.source && i.source === options.source);
      if (!hit || i.read) return i;
      count++;
      return { ...i, read: true, readAt: at, ...(options.note ? { note: options.note } : {}) };
    });
    const missing = (options.ids ?? []).filter((id) => !data.items.some((i) => i.id === id));
    return `Marked ${count} item${count === 1 ? '' : 's'} read.${missing.length ? ` Not found: ${missing.join(', ')}` : ''}`;
  });
}

export function markUnread(ids: string[]): string {
  return updateData((data) => {
    const wanted = new Set(ids);
    let count = 0;
    data.items = data.items.map((i) => {
      if (!wanted.has(i.id) || !i.read) return i;
      count++;
      const { readAt: _readAt, ...rest } = i;
      return { ...rest, read: false };
    });
    return `Marked ${count} item${count === 1 ? '' : 's'} unread.`;
  });
}

export function sourcesReport(): string {
  const registry = loadRegistry();
  const data = loadData();
  const counts = new Map<string, number>();
  for (const i of data.items) counts.set(i.source, (counts.get(i.source) ?? 0) + 1);
  const problems = data.problems ?? [];
  return [
    `${registry.sources.length} sources (add or disable them in ~/.stackwatch/sources.json):`,
    ...registry.sources.map((s) => {
      const failing = problems.find((p) => p.startsWith(`${s.name}:`) || p.startsWith(`${s.name} (`));
      return `- ${s.id} [${s.type}${s.official ? ', official' : ''}${s.products?.length ? `, ${s.products.join('/')}` : ''}] ${s.url} · ${counts.get(s.id) ?? 0} items${failing ? ` · ! ${failing}` : ''}`;
    }),
  ].join('\n');
}

// ---- helpers ----------------------------------------------------------------------------------

function requireStack(data: Data, project: string): Stack {
  const stack = data.stacks[projectName(project)];
  if (!stack) throw new Error(`No project "${project}". Run init first.`);
  return stack;
}

function label(c: Component): string {
  const from = c.source === 'manual' ? 'by hand' : c.source.startsWith('server') ? 'server' : c.source;
  return `${c.name} ${c.version}${c.exact === false ? ' (line only)' : ''} [${from}]`;
}

function byEcosystem(components: Component[]): string {
  const counts = new Map<string, number>();
  for (const c of components) counts.set(c.ecosystem ?? 'other', (counts.get(c.ecosystem ?? 'other') ?? 0) + 1);
  return [...counts].map(([e, n]) => `${n} ${e}`).join(' + ') || '0';
}
