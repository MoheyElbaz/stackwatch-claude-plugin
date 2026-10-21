// SPDX-License-Identifier: GPL-3.0-or-later
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, platform } from 'node:os';
import { join } from 'node:path';
import { alertIssues, clean, type Issue } from './format.ts';
import { home } from './paths.ts';
import { refresh } from './refresh.ts';
import { alertLevelFor, loadData, updateData } from './store.ts';

const LABEL = 'dev.stackwatch.check';

/**
 * For a scheduled run, with no Claude session open: refresh, then announce each new unread alert
 * once, on the desktop and through the user's own command (mail, a chat webhook, ...) if they set one.
 */
export async function notifyNew(): Promise<string> {
  if (!loadData().settings?.notifications) return 'Notifications are off. Turn them on with `stackwatch notifications on`.';
  const result = await refresh({ timeoutMs: 20000 });
  const data = loadData();
  const fresh = alertIssues(data.items, (p) => alertLevelFor(data, p)).filter((i) => !i.top.read && !i.items.some((x) => x.notifiedAt));
  if (!fresh.length) return `No new alerts.${result.problems.length ? ` (${result.problems.length} source problem(s))` : ''}`;

  const text = summary(fresh);
  desktop(fresh.length === 1 ? headline(fresh[0]!) : `${fresh.length} new security alerts. ${headline(fresh[0]!)}`);
  const command = data.settings?.notifyCommand;
  let sent = '';
  if (command) sent = await runCommand(command, text);

  const at = new Date().toISOString();
  const ids = new Set(fresh.flatMap((i) => i.items.map((x) => x.id)));
  updateData((d) => {
    d.items = d.items.map((i) => (ids.has(i.id) ? { ...i, notifiedAt: at } : i));
  });
  return `Announced ${fresh.length} new alert${fresh.length === 1 ? '' : 's'}${sent}.\n\n${text}`;
}

function headline(issue: Issue): string {
  const m = issue.top.matches.find((x) => !x.dev) ?? issue.top.matches[0];
  return `${issue.top.level.toUpperCase()}${issue.top.exploited ? ' (exploited)' : ''}: ${m ? `${m.project} · ${m.component} ${m.version}${m.fixed ? ` → ${m.fixed}` : ''}` : clean(issue.top.title, 80)}`;
}

function summary(issues: Issue[]): string {
  return issues
    .map((i) => `${headline(i)}\n  ${clean(i.top.title)}\n  ${[...i.top.cves.slice(0, 3), i.top.url].join(' · ')}`)
    .join('\n\n');
}

/** The text goes as an argument, never into the script, so a feed title can't become AppleScript. */
function desktop(message: string): void {
  if (platform() === 'darwin') {
    spawnSync('osascript', ['-e', 'on run argv', '-e', 'display notification (item 1 of argv) with title "stackwatch" sound name "Basso"', '-e', 'end run', clean(message, 200)]);
  } else if (platform() === 'linux') {
    spawnSync('notify-send', ['stackwatch', clean(message, 200)]);
  }
}

/** The user's own command, set by them in a terminal; the alert text arrives on its stdin. */
function runCommand(command: string, text: string): Promise<string> {
  return new Promise((resolve) => {
    const child = spawn('sh', ['-c', command], { stdio: ['pipe', 'ignore', 'pipe'] });
    let err = '';
    child.stderr.on('data', (d) => (err += d));
    child.on('error', (e) => resolve(` (notify command failed: ${e.message})`));
    child.on('close', (code) => resolve(code === 0 ? ' and sent it with your notify command' : ` (notify command exited ${code}: ${err.trim().slice(0, 200)})`));
    child.stdin.end(`stackwatch: new security alerts\n\n${text}\n`);
  });
}

export function setNotifyCommand(command: string | null): string {
  return updateData((data) => {
    data.settings = { ...data.settings };
    if (command) data.settings.notifyCommand = command;
    else delete data.settings.notifyCommand;
    return command ? `New alerts will also be piped to: ${command}` : 'Notify command removed; desktop notifications only.';
  });
}

// ---- the option -------------------------------------------------------------------------------

/** Alerts outside Claude are off by default: turning them on schedules the hourly check, off removes it. */
export function notifications(action: 'on' | 'off' | 'status', script: string): string {
  if (action === 'status') {
    const data = loadData();
    const on = !!data.settings?.notifications;
    return [
      `Notifications are ${on ? 'on' : 'off'}.`,
      on ? schedule('status', script) : 'Turn them on with `stackwatch notifications on` (hourly check, desktop notification).',
      data.settings?.notifyCommand ? `Notify command: ${data.settings.notifyCommand}` : 'No notify command (set one with `stackwatch notify-command "<cmd>"`).',
    ].join('\n');
  }
  updateData((data) => {
    data.settings = { ...data.settings, notifications: action === 'on' };
  });
  return action === 'on' ? `Notifications on. ${schedule('install', script)}` : `Notifications off. ${schedule('remove', script)}`;
}

// ---- schedule ---------------------------------------------------------------------------------

const plistPath = () => join(homedir(), 'Library', 'LaunchAgents', `${LABEL}.plist`);

function schedule(action: 'install' | 'remove' | 'status', script: string): string {
  const everyHour = `0 * * * * ${process.execPath} ${script} notify >> ${join(home(), 'schedule.log')} 2>&1`;
  if (platform() !== 'darwin') {
    if (action === 'status') return 'Scheduling is set up by you on this system. Add this line with `crontab -e`:\n' + everyHour;
    return `On this system, add (or remove) this line with \`crontab -e\`:\n${everyHour}`;
  }

  const domain = `gui/${process.getuid?.() ?? 501}`;
  if (action === 'status') {
    const loaded = spawnSync('launchctl', ['print', `${domain}/${LABEL}`], { encoding: 'utf8' }).status === 0;
    return loaded ? `Scheduled: checks every hour (${plistPath()}).` : 'Not scheduled. Run `stackwatch schedule install`.';
  }
  spawnSync('launchctl', ['bootout', `${domain}/${LABEL}`]);
  if (action === 'remove') {
    if (existsSync(plistPath())) rmSync(plistPath());
    return 'Hourly check removed.';
  }

  mkdirSync(join(homedir(), 'Library', 'LaunchAgents'), { recursive: true });
  mkdirSync(home(), { recursive: true, mode: 0o700 });
  const xml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  writeFileSync(plistPath(), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>${xml(process.execPath)}</string><string>${xml(script)}</string><string>notify</string></array>
  <key>StartInterval</key><integer>3600</integer>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>${xml(join(home(), 'schedule.log'))}</string>
  <key>StandardErrorPath</key><string>${xml(join(home(), 'schedule.log'))}</string>
</dict>
</plist>
`);
  const loaded = spawnSync('launchctl', ['bootstrap', domain, plistPath()], { encoding: 'utf8' });
  if (loaded.status !== 0) return `Wrote ${plistPath()} but launchctl refused it: ${loaded.stderr.trim()}`;
  return `Scheduled: every hour, new alerts become a desktop notification${loadData().settings?.notifyCommand ? ' and go to your notify command' : ''}. Log: ${join(home(), 'schedule.log')}`;
}
