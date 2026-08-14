---
description: List all available RAPTOR commands
dispatch: skill
exclude_from_listing: true
---

# RAPTOR Command Reference

Output "RAPTOR commands:" then list all available RAPTOR slash commands grouped by workflow stage. Use the groups below as `**bold headers**`, each followed by a bullet list of commands in alphabetical order. Format: `- /command <args> — Description`. Derive the command list from the available skills — do not use a hardcoded list.

**Discover**
Find vulnerabilities: agentic, codeql, fuzz, scan, sca, web.

**Analyse**
Go deeper: binary, crash-analysis, describe, frida, threat-model, understand, validate.

**Exploit & fix**
Act on findings: cve-diff, exploit, patch.

**Report**
Present results: annotate, diagram, scorecard.

**Project**
Manage work: project, sage, version.

After the groups, on a separate line: `- /create-skill — Save approaches as reusable skills (alpha)`

Omit commands flagged as "unavailable" in the most recent startup warnings. Commands flagged as "limited" should still be shown with a note (e.g., `(limited — rr not found)`).

Exclude non-RAPTOR commands (e.g., /commands itself, /help) and internal/duplicate commands (e.g., raptor-scan, raptor-fuzz, raptor-web).

End with: "Commands with missing dependencies are omitted. Check the startup warnings for details."
