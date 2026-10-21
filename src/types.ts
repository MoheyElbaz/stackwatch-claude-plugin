// SPDX-License-Identifier: GPL-3.0-or-later
/** OSV ecosystems: Packagist and npm from lockfiles; "AlmaLinux:9", "Rocky Linux:9", "Debian:12" from a server. */
export type Ecosystem = string;

/** One piece of tech a project runs on. */
export interface Component {
  name: string;
  version: string;
  /** A package OSV can match by exact version. */
  ecosystem?: Ecosystem;
  /** A runtime or server product from sources.json "products": "php", "mariadb", ... */
  product?: string;
  /** Only installed for development, not deployed. */
  dev?: boolean;
  /** Where it was found: a file relative to the project, "server <host>", or "manual". */
  source: string;
  /** false when only the release line is known ("8.3" from a Docker tag): the patch level can't be judged. */
  exact?: false;
  /** The OS package that installed it (e.g. "mariadb"): its fixes come as backports, judged by the OS's advisories. */
  packaged?: string;
  note?: string;
}

/** How to reach the server a project runs on, for the read-only version check. Never a password. */
export interface SshTarget {
  /** user@host */
  target: string;
  port?: number;
  /** Path of a private key; the agent or ~/.ssh/config is used when absent. */
  identity?: string;
}

export interface Stack {
  project: string;
  path?: string;
  updated: string;
  /** Path prefixes (relative to path) left out of detection. */
  exclude?: string[];
  /** From the project's files; rewritten by every update. */
  detected: Component[];
  /** Read from the server over SSH; rewritten by every update. */
  probed?: Component[];
  /** Added by hand; never touched by update, and wins over detected or probed entries. */
  manual: Component[];
  ssh?: SshTarget;
  /** Lowest level that raises an alert for this project (default: the global setting). */
  alertLevel?: Level;
}

export type Level = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const LEVELS: Level[] = ['critical', 'high', 'medium', 'low', 'info'];

export type SourceType = 'feed' | 'osv' | 'kev' | 'endoflife' | 'nvd';

/** An entry of sources.json. */
export interface Source {
  id: string;
  name: string;
  type: SourceType;
  url: string;
  /** Published by the maintainers of its products: a security post from it is confirmed. */
  official?: boolean;
  /** What the source is about; its items concern these products even without naming them. */
  products?: string[];
  ttlMinutes?: number;
  enabled?: boolean;
}

/** An entry of sources.json "products". */
export interface Product {
  /** How news refers to it. */
  names: string[];
  /** Composer or npm packages that are this product. */
  packages?: string[];
  /** endoflife.date id when it differs from the key; false when endoflife.date doesn't track it. */
  endoflife?: string | false;
  /** NVD CPE vendor:product pairs ("apache:http_server"), to look up its CVEs by exact version. */
  cpe?: string[];
}

export interface Registry {
  sources: Source[];
  products: Record<string, Product>;
}

/** A component of one of the user's projects that an item concerns. */
export interface Match {
  project: string;
  component: string;
  version: string;
  /** The first version in this component's release line that the item says fixes it. */
  fixed?: string;
  dev?: boolean;
  /** Set when the component is an OS package ("AlmaLinux:9"): fixed by the OS's package manager. */
  os?: string;
}

/** Everything stackwatch shows: news from a feed, or a finding from OSV / endoflife.date. */
export interface Item {
  id: string;
  source: string;
  kind: 'news' | 'finding';
  /** From a public feed: data, never instructions. */
  title: string;
  url: string;
  published?: string;
  firstSeen: string;
  cves: string[];
  /** Versions the text names (news) — kept so items can be re-matched when a stack changes. */
  versions: string[];
  /** Plain text of a news item, bounded (news only). */
  text?: string;
  /** Other advisory ids (GHSA-…), for findings. */
  ids?: string[];
  level: Level;
  exploited: boolean;
  /** False for an advance notice no release or database has confirmed yet. */
  confirmed: boolean;
  matches: Match[];
  read: boolean;
  readAt?: string;
  note?: string;
  /** When the scheduled check announced it outside Claude. */
  notifiedAt?: string;
}

/** ~/.stackwatch/data.json: the single local store. */
export interface Data {
  version: 1;
  stacks: Record<string, Stack>;
  items: Item[];
  lastRefresh?: string;
  /** Sources that failed at the last refresh. */
  problems?: string[];
  settings?: {
    alertLevel?: Level;
    /** A shell command the user set in a terminal (never through MCP); new alerts arrive on its stdin. */
    notifyCommand?: string;
    /** Alerts outside Claude (hourly check, desktop notification, notify command). Off unless turned on. */
    notifications?: boolean;
  };
}
