---
description: List all available RAPTOR commands
---

# RAPTOR Command Reference

Output "Full list of RAPTOR commands:" then list all available RAPTOR slash commands as a bullet list. Format: `- /command <args> — Description`. Derive the list from the available skills — do not use a hardcoded list.

Omit commands flagged as "unavailable" in the most recent startup warnings. Commands flagged as "limited" should still be shown with a note (e.g., `(limited — rr not found)`).

Exclude non-RAPTOR commands (e.g., /commands itself, /help) and internal/duplicate commands (e.g., raptor-scan, raptor-fuzz, raptor-web).

End with: "Commands with missing dependencies are omitted. Check the startup warnings for details."
