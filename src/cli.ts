// SPDX-License-Identifier: GPL-3.0-or-later
import { parseArgs } from 'node:util';
import { sessionStartHook } from './hook.ts';
import { notifications, notifyNew, setNotifyCommand } from './notify.ts';
import { startMcpServer } from './mcp.ts';
import {
  addComponent, alertsReport, describeProjects, initProject, markRead, markUnread, newsReport, refreshNow, removeComponent, setAlertLevel, sourcesReport, updateProjects,
} from './ops.ts';
import { LEVELS, type Level } from './types.ts';

const VERSION = '0.1.0';

const HELP = `stackwatch ${VERSION}: security news and alerts for the tech your projects run on

  alerts [project] [--read]               unread critical/high alerts (--read: also read but still open)
  news [--all] [--source id] [--project p] [--product p] [--min level] [--limit n]
                                          everything the sources said, unread first
  read <id...> | --alerts | --source id | --all  [--note text]
                                          mark items read
  unread <id...>                          mark items unread
  refresh                                 read every source now
  sources                                 list the sources (sources.json + ~/.stackwatch/sources.json)

  init [path] [--name n] [--exclude a,b] [--ssh user@host] [--port n] [--identity key] [--level l]
                                          register a project: its files, its server's versions, a first check
  update [project]                        re-scan files and server, show what changed, check again
  add <project> <name> <version> --product p [--note t]
                                          add what neither can see, by hand
  remove <project> <name>                 remove one added by hand
  level <critical|high|medium|low> [project]
                                          lowest level that raises an alert (default high)
  list                                    projects with their risk

  notifications on|off|status             alerts outside Claude, off by default: on = hourly check + desktop notification
  notify-command "<cmd>" | --clear        with notifications on, also pipe new alerts to your command ("mail -s stackwatch you@example.com")
  notify                                  what the hourly check runs: refresh, announce each new alert once

  hook                                    Claude Code SessionStart hook
  mcp                                     run the MCP server on stdio

Levels: ${LEVELS.join(', ')}. Data: ~/.stackwatch/data.json (STACKWATCH_HOME to move it).`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      name: { type: 'string' }, exclude: { type: 'string' }, product: { type: 'string' }, note: { type: 'string' },
      ssh: { type: 'string' }, port: { type: 'string' }, identity: { type: 'string' }, level: { type: 'string' },
      source: { type: 'string' }, project: { type: 'string' }, min: { type: 'string' }, limit: { type: 'string' },
      all: { type: 'boolean' }, alerts: { type: 'boolean' }, read: { type: 'boolean' }, clear: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' }, version: { type: 'boolean', short: 'v' },
    },
  });
  const [command, ...args] = positionals;

  if (values.version) return print(VERSION);
  if (values.help || !command || command === 'help') return print(HELP);

  switch (command) {
    case 'alerts': {
      const report = await alertsReport({ project: args[0], includeRead: values.read });
      print(report.text);
      // Scripts and cron can act on it: 2 while anything critical or high is unread.
      return report.items.some((i) => !i.read) ? 2 : 0;
    }
    case 'news': {
      const min = values.min as Level | undefined;
      if (min && !LEVELS.includes(min)) throw new Error(`--min must be one of ${LEVELS.join(', ')}`);
      return print(await newsReport({ all: values.all, source: values.source, project: values.project, product: values.product, min, limit: values.limit ? Number(values.limit) : undefined }));
    }
    case 'read':
      return print(markRead({ ids: args, all: values.all, source: values.source, alerts: values.alerts, note: values.note }));
    case 'unread':
      if (!args.length) throw new Error('usage: stackwatch unread <id...>');
      return print(markUnread(args));
    case 'refresh':
      return print(await refreshNow());
    case 'sources':
      return print(sourcesReport());
    case 'init': {
      const level = values.level as Level | undefined;
      if (level && !LEVELS.includes(level)) throw new Error(`--level must be one of ${LEVELS.join(', ')}`);
      return print(await initProject(args[0] ?? process.cwd(), {
        name: values.name,
        exclude: values.exclude?.split(',').map((s) => s.trim()).filter(Boolean),
        ...(values.ssh ? { ssh: { target: values.ssh, ...(values.port ? { port: Number(values.port) } : {}), ...(values.identity ? { identity: values.identity } : {}) } } : {}),
        ...(level ? { alertLevel: level } : {}),
      }));
    }
    case 'update':
      return print(await updateProjects(args[0]));
    case 'level':
      if (!args[0]) throw new Error('usage: stackwatch level <critical|high|medium|low> [project]');
      return print(setAlertLevel(args[0] as Level, args[1]));
    case 'add': {
      const [project, name, version] = args;
      if (!project || !name || !version) throw new Error('usage: stackwatch add <project> <name> <version> --product p');
      return print(addComponent(project, { name, version, ...(values.product ? { product: values.product } : {}), ...(values.note ? { note: values.note } : {}) }));
    }
    case 'remove':
      if (!args[0] || !args[1]) throw new Error('usage: stackwatch remove <project> <name>');
      return print(removeComponent(args[0], args[1]));
    case 'list':
      return print(describeProjects());
    case 'notify':
      return print(await notifyNew());
    case 'notify-command':
      if (!values.clear && !args[0]) throw new Error('usage: stackwatch notify-command "<command>" | --clear');
      return print(setNotifyCommand(values.clear ? null : args.join(' ')));
    case 'notifications': {
      const action = (args[0] ?? 'status') as 'on' | 'off' | 'status';
      if (!['on', 'off', 'status'].includes(action)) throw new Error('usage: stackwatch notifications on|off|status');
      return print(notifications(action, process.argv[1]!));
    }
    case 'hook': {
      const output = await sessionStartHook();
      if (output) process.stdout.write(JSON.stringify(output));
      // A refresh that ran past the hook's budget must not hold the session open.
      process.exit(0);
    }
    case 'mcp':
      await startMcpServer(VERSION);
      return -1;
    default:
      throw new Error(`unknown command "${command}"\n\n${HELP}`);
  }
}

function print(text: string): number {
  process.stdout.write(text.endsWith('\n') ? text : `${text}\n`);
  return 0;
}

main(process.argv.slice(2)).then(
  (code) => {
    // The MCP server keeps running on stdio; everything else exits with its code.
    if (code >= 0) process.exitCode = code;
  },
  (error: Error) => {
    process.stderr.write(`stackwatch: ${error.message}\n`);
    process.exitCode = 1;
  },
);
