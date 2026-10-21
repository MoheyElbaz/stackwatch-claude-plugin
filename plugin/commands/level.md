---
description: Choose from which risk level stackwatch raises alerts (critical, high, medium, low)
argument-hint: <critical|high|medium|low> [project]
---

Call the stackwatch `set_alert_level` tool with the level and optional project in $ARGUMENTS
(without a project it applies to every project that has no level of its own). If no level was
given, explain the levels in one line each and ask which one:
- critical: exploited in the wild, or a critical / remote-code-execution fix you don't have yet
- high (default): any security fix you don't have yet, a runtime past end of life, an official advance notice
- medium: also security news about your stack and newer runtime patches without an advisory
- low: also general security news that mentions nothing you run
