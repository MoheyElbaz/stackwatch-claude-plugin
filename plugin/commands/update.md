---
description: Re-scan your projects' tech after upgrades and confirm the alerts are gone
argument-hint: "[project]"
---

Use the **security-check** skill. Call `stack_update` for the project in $ARGUMENTS (or all), show
what changed, ask whether any runtime versions changed too (update those with `stack_add`), then
call `security_alerts`.
