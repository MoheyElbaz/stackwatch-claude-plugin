---
description: Register a project with stackwatch - scan its tech, read its server's versions, check it and show its risk
argument-hint: [path] [ssh user@host] [alert level]
---

Use the **security-check** skill to register a project with stackwatch.

User input (an optional path, default the current working directory; an optional server as user@host,
with a port and key if given; an optional alert level): $ARGUMENTS

1. If no server was given, ask once whether the project runs on a server they can reach over SSH
   (user@host, port, key path). Never ask for or accept a password.
2. Call `stack_init` with the absolute path, the SSH target if any, `exclude` for folders that are
   not deployed, and `alert_level` if given (default high).
3. Report what it found (files, packages, runtimes and where each came from), the project's risk,
   and its alerts, most urgent first, with the fix for each.
4. If a runtime is still missing (no server given, or the server check failed), ask for its exact
   version and add it with `stack_add`.
