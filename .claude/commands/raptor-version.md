---
description: Show the running RAPTOR framework version
dispatch: python3 raptor.py --version
---

# /raptor-version - RAPTOR Version

Reports the version of RAPTOR the current session is running without
colliding with GitHub Copilot CLI's built-in `/version` command.

Execute: `python3 raptor.py --version`

Output the command's single-line result plainly, for example:
`RAPTOR version: 3.0.0-1786-g7fcf38ea`.

The value comes from `RaptorConfig.effective_version()`: in a git checkout it
is the true position past the last release tag (`<tag>-<commits>-g<sha>`, with
`-local` when the tree has uncommitted changes); installed or archived copies
use the baked release number.
