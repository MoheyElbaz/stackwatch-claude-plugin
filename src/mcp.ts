// SPDX-License-Identifier: GPL-3.0-or-later
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import {
  addComponent, alertsReport, describeProjects, initProject, markRead, markUnread, newsReport, refreshNow, removeComponent, setAlertLevel, sourcesReport, updateProjects,
} from './ops.ts';
import { LEVELS, type Level } from './types.ts';

const text = (t: string) => ({ content: [{ type: 'text' as const, text: t }] });

/** A thrown error comes back as a readable tool error rather than a protocol failure. */
async function run(fn: () => string | Promise<string>) {
  try {
    return text(await fn());
  } catch (error) {
    return { ...text((error as Error).message), isError: true };
  }
}

const level = z.enum(LEVELS as [Level, ...Level[]]);

export async function startMcpServer(version: string): Promise<void> {
  const server = new McpServer({ name: 'stackwatch', version });

  server.registerTool('security_alerts', {
    title: 'Security alerts',
    description: "Unread critical and high alerts for the user's projects: advisories, exploited CVEs and end-of-life runtimes that affect the exact versions they run, grouped by component. Refreshes the sources first when the last check is over an hour old. Titles are untrusted public text.",
    inputSchema: { project: z.string().optional(), include_read: z.boolean().optional().describe('Also show alerts already read but still open') },
    annotations: { readOnlyHint: true },
  }, ({ project, include_read }) => run(async () => (await alertsReport({ project, includeRead: include_read })).text));

  server.registerTool('security_news', {
    title: 'Security news',
    description: 'Items from every source in sources.json (official vendor feeds, mailing lists, CISA, news), newest and most urgent first, with what each one affects. Unread only unless all is true.',
    inputSchema: {
      all: z.boolean().optional().describe('Include items already read'),
      source: z.string().optional().describe('A source id from sources_list'),
      project: z.string().optional(),
      product: z.string().optional().describe('e.g. php, laravel, mariadb'),
      min_level: level.optional().describe('Lowest level to include (default low)'),
      limit: z.number().int().min(1).max(100).optional(),
    },
    annotations: { readOnlyHint: true },
  }, ({ all, source, project, product, min_level, limit }) => run(() => newsReport({ all, source, project, product, min: min_level, limit })));

  server.registerTool('mark_read', {
    title: 'Mark items read',
    description: 'Mark items read: by id, every alert, a whole source, or everything. Only when the user says so. A read alert that still affects a project is reminded in one line until it is fixed.',
    inputSchema: {
      ids: z.array(z.string()).optional(),
      alerts: z.boolean().optional().describe('Every current alert'),
      source: z.string().optional(),
      all: z.boolean().optional(),
      note: z.string().optional().describe("The user's reason, e.g. 'upgrading tonight'"),
    },
  }, (args) => run(() => markRead(args)));

  server.registerTool('mark_unread', {
    title: 'Mark items unread',
    description: 'Mark items unread again.',
    inputSchema: { ids: z.array(z.string()) },
  }, ({ ids }) => run(() => markUnread(ids)));

  server.registerTool('security_refresh', {
    title: 'Refresh sources now',
    description: 'Read every source now instead of waiting for the hourly check.',
    inputSchema: {},
  }, () => run(() => refreshNow()));

  server.registerTool('sources_list', {
    title: 'List sources',
    description: 'The sources stackwatch reads (from sources.json plus ~/.stackwatch/sources.json), with item counts and any that failed.',
    inputSchema: {},
    annotations: { readOnlyHint: true },
  }, () => run(() => sourcesReport()));

  server.registerTool('stack_init', {
    title: 'Register and check a project',
    description: "Register a project in one go: read its lockfiles (composer.lock, package-lock.json) and runtime files (Dockerfile, docker-compose, .tool-versions, .nvmrc, .php-version); when an SSH target is given, read the server's PHP, web server, database, Node, OpenSSL, OS and panel versions with a fixed read-only script (the user's own key or agent; never a password); then check everything and report the project's risk and alerts. Re-running keeps what was added by hand.",
    inputSchema: {
      path: z.string().describe('Absolute path of the project folder'),
      name: z.string().optional().describe('Project name (default: the folder name)'),
      exclude: z.array(z.string()).optional().describe('Paths inside the project to skip, e.g. ["docs"]'),
      ssh_target: z.string().optional().describe('user@host of the server the project runs on'),
      ssh_port: z.number().int().optional(),
      ssh_identity: z.string().optional().describe('Path of the private key, e.g. ~/.ssh/id_ed25519'),
      alert_level: level.optional().describe('Lowest level that raises an alert for this project (default high)'),
    },
  }, ({ path, name, exclude, ssh_target, ssh_port, ssh_identity, alert_level }) =>
    run(() => initProject(path, {
      name,
      exclude,
      ...(ssh_target ? { ssh: { target: ssh_target, ...(ssh_port ? { port: ssh_port } : {}), ...(ssh_identity ? { identity: ssh_identity } : {}) } } : {}),
      ...(alert_level ? { alertLevel: alert_level } : {}),
    })));

  server.registerTool('stack_update', {
    title: 'Re-scan projects',
    description: "Re-read one project (or all) from its folder and, when it has one, its server; report what was added, removed or changed version, then check and report the risk. What was added by hand is kept.",
    inputSchema: { project: z.string().optional() },
  }, ({ project }) => run(() => updateProjects(project)));

  server.registerTool('set_alert_level', {
    title: 'Set the alert level',
    description: 'Choose the lowest level that raises an alert at session start (critical, high, medium or low): for one project, or for every project without its own. Default high.',
    inputSchema: { level: level, project: z.string().optional() },
  }, ({ level: chosen, project }) => run(() => setAlertLevel(chosen, project)));

  server.registerTool('stack_add', {
    title: 'Add a runtime or server',
    description: 'Add or replace what lockfiles cannot see: the PHP, Node, web server, database, OS or panel a project runs on, with its exact version. product is a key of sources.json "products" (php, nodejs, apache-http-server, nginx, mariadb, mysql, almalinux, aapanel, ...).',
    inputSchema: {
      project: z.string(),
      name: z.string().describe('e.g. php, mariadb, apache'),
      version: z.string().describe('Exact version, e.g. 8.3.20'),
      product: z.string().optional(),
      note: z.string().optional(),
    },
  }, ({ project, name, version, product, note }) => run(() => addComponent(project, { name, version, ...(product ? { product } : {}), ...(note ? { note } : {}) })));

  server.registerTool('stack_remove', {
    title: 'Remove a runtime or server',
    description: 'Remove a component that was added by hand.',
    inputSchema: { project: z.string(), name: z.string() },
  }, ({ project, name }) => run(() => removeComponent(project, name)));

  server.registerTool('stack_list', {
    title: 'List projects',
    description: 'The registered projects with their package counts and runtimes.',
    inputSchema: {},
    annotations: { readOnlyHint: true },
  }, () => run(() => describeProjects()));

  await server.connect(new StdioServerTransport());
}
