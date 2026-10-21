# stackwatch

Security news and alerts for the tech your projects actually run on, inside Claude Code.

stackwatch learns what a project runs: the packages in its lockfiles, the runtimes in its Docker
and version files, and, over SSH, the runtimes, OS packages and kernel on its server. It reads
official vendor feeds, mailing lists, CISA, OSV and NVD, matches every item to your exact versions,
and at the start of each Claude Code session tells you what needs fixing:

```text
stackwatch: 12 unread security alerts (3 things to fix). CRITICAL: shop · php 8.2.20 → 8.2.35. /stackwatch:check
```

- **One list of sources:** [`plugin/sources.json`](plugin/sources.json). Adding a feed means adding
  an entry, with no code; private additions go in `~/.stackwatch/sources.json`.
- **One local store:** `~/.stackwatch/data.json` holds your projects' tech, every item and finding,
  and what you have read.
- **Things to fix, not raw advisories:**
  - Reports of the same CVE are merged: php.net, three news sites and a mailing list about one flaw
    count as one alert.
  - All of a server's OS package advisories are one alert, fixed by one `dnf upgrade --security`.

## Install

You need [Claude Code](https://claude.com/claude-code) and Node.js 20 or newer (`node -v`). The
server check also needs an `ssh` client and a key that can log in to the server.

**1. Add the plugin**, in Claude Code:

```text
/plugin marketplace add MoheyElbaz/stackwatch-claude-plugin
/plugin install stackwatch@stackwatch
```

Or from a terminal:

```sh
claude plugin marketplace add MoheyElbaz/stackwatch-claude-plugin
claude plugin install stackwatch@stackwatch
```

**2. Start a new Claude Code session**, so the plugin loads. `/plugin` lists it as enabled.

**3. Register a project**, from inside it:

```text
/stackwatch:init
```

Claude reads the project's lockfiles and runtime files, then asks whether it runs on a server you
can reach over SSH. Give `user@host` (plus a port or key if needed) to read the server's runtimes,
OS packages and kernel. Then it checks everything and shows the project's risk and what to fix.

**4. That's it.** Every new session starts with your unread alerts. Use them like this:

| Command | Does |
|---|---|
| `/stackwatch:check` | the alerts, most urgent first, with the fix for each |
| `/stackwatch:news` | everything the sources said that concerns you |
| `/stackwatch:update` | after upgrading: re-scan and confirm the alerts are gone |
| `/stackwatch:level medium` | alert from medium up (default high) |

Mark alerts read when you've seen them ("mark them read") and they stop interrupting.

**Update or remove:**

```sh
claude plugin marketplace update stackwatch && claude plugin update stackwatch@stackwatch
claude plugin uninstall stackwatch@stackwatch      # your data stays in ~/.stackwatch until you delete it
```

## What init finds

| from | what |
|---|---|
| `composer.lock`, `package-lock.json` | every Composer and npm package and its exact version (dev-only ones flagged) |
| `Dockerfile`, `docker-compose.yml`, `.tool-versions`, `.nvmrc`, `.php-version` | runtimes: PHP, Node, MariaDB, MySQL, PostgreSQL, Redis, nginx, Apache, the OS image |
| the server, over SSH (`--ssh user@host`) | the runtimes actually running and whether the OS installed them; every OS package (rpm or dpkg); the running kernel |

The server check is a fixed script ([`src/probe.ts`](src/probe.ts)) that only prints versions and
package lists. It runs with your own key or agent and never uses a password.

For each runtime, a version typed by hand beats the server, and the server beats the project files.
A Docker tag like `php:8.3` is kept as "line only": it can show end of life, but not whether a fix
is installed.

## Sources

| type | what | shipped |
|---|---|---|
| `feed` | any RSS or Atom feed | **vendors:** php.net, Node.js, Laravel, Symfony, Drupal, WordPress, Django, Python, Go, Ruby on Rails, nginx, PostgreSQL, MariaDB, Redis, GitLab, Ubuntu, Debian, AlmaLinux · **research and news:** oss-security, Full Disclosure, CISA advisories, SANS ISC, Exploit-DB, BleepingComputer, The Hacker News |
| `kev` | CISA Known Exploited Vulnerabilities | marks what is exploited in the wild |
| `osv` | OSV.dev | Composer and npm packages, and OS packages (AlmaLinux, Rocky Linux, Debian) by exact version |
| `nvd` | NVD | CVEs of runtimes the OS did not install (PHP or Apache compiled by a panel, say) |
| `endoflife` | endoflife.date | release lines past end of life; a newer patch out |

How each kind of source is trusted:
- **Official feeds:** a feed marked `official` for a product (php.net for `php`) speaks for that
  product. An advance notice ("security release tomorrow") raises an **unconfirmed** alert until
  the release is out.
- **General news:** counts only when the headline is about one of your products, or names one of
  your packages next to "npm" or "package".
- **OS packages:** judged by the OS's own advisories, which include backported fixes, never by
  upstream version numbers. News about a kernel CVE your server's advisories no longer list stays
  quiet.

## Levels

| Level | Means |
|---|---|
| **critical** | On CISA's exploited list, or a fix you don't have that is rated critical or described as remote code execution. |
| **high** | A security fix you don't have, a runtime past end of life, or an official advance notice from the last two weeks. |
| **medium** | Concerns your stack and is about security, or a newer runtime patch with no advisory attached. |
| **low / info** | Other news, kept for 30 days to browse. |

Each project has a **risk**: its worst open issue.

Alerts are the issues at or above the project's alert level: `high` by default, changed with
`/stackwatch:level`. They are raised at every session start until you mark them read. A read alert
that still applies is reminded in one line until you upgrade.

## Notifications outside Claude (off by default)

```sh
stackwatch notifications on       # hourly check; each new alert once, as a desktop notification
stackwatch notify-command "mail -s stackwatch you@example.com"   # optional: also pipe new alerts to a command
stackwatch notifications off      # remove the hourly check
```

On macOS this installs a LaunchAgent. On Linux it prints the crontab line to add. The notify command
can only be set from a terminal, never by Claude.

## CLI

```sh
sw() { node plugin/dist/stackwatch.mjs "$@"; }

sw init ~/code/shop --name shop --ssh deploy@shop.example --identity ~/.ssh/shop   # files + server + first check
sw add shop php 8.3.20 --product php        # only what neither the files nor the server show
sw level medium shop                        # alert from medium up for this project
sw alerts                                   # exit code 2 while anything is unread
sw news --product php                       # everything the sources said about it
sw read --alerts --note "upgrading tonight"
sw update                                   # after upgrades: re-scan files and server, check again
sw sources                                  # what is read, item counts, failures
```

NVD allows a handful of requests without a key. For a faster first check, give the plugin a free
[NVD API key](https://nvd.nist.gov/developers/request-an-api-key) when Claude Code asks on install,
or later with `/plugin configure stackwatch`. Claude Code keeps it in secure storage and the plugin
sends it only to NVD. The CLI outside Claude Code reads it from `CLAUDE_PLUGIN_OPTION_NVD_API_KEY`.

## Privacy

`~/.stackwatch/` is readable only by you, and it lists the exact versions your servers run: never
commit it.

What leaves your machine:
- package names and versions, sent to OSV;
- runtime names and versions, sent to NVD (with your NVD API key, if you gave one);
- runtime names, sent to endoflife.date.

Feeds are only downloaded. The server check runs over your own SSH connection to your own server.

Feed text is treated as untrusted. It is flattened and bounded, and the skill tells Claude never to
act on instructions inside it.

## Develop

```sh
npm install
npm run verify     # typecheck, tests, bundle into plugin/dist (committed, so installs need no build)
```

`plugin/dist/THIRD_PARTY_NOTICES.txt` lists the bundled packages and their licenses.

**Reviewing the bundle.** `plugin/dist` is built only from `src/` and `scripts/` by `npm run build`
(esbuild, minified, split into files under 240 KiB). To check that the committed bundle matches the
source, run `npm ci && npm run build && git diff --stat plugin/dist`: it should print nothing. The
only network calls are in `src/http.ts` (fetching the sources listed in `plugin/sources.json`), and
the only command run on a server is the read-only script in `src/probe.ts`.

## License

Copyright (C) 2026 Mohey Elbaz

This program is free software: you can redistribute it and/or modify it under the terms of the GNU
General Public License as published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version. See [LICENSE](LICENSE).

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
