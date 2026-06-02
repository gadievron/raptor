---
description: Show the running RAPTOR framework version
---

# /version - RAPTOR Version

Reports the version of RAPTOR the current session is running.

Execute: `python3 raptor.py --version`

Output the command's single-line result as the version, plainly (e.g. "RAPTOR version: 3.0.0-1786-g7fcf38ea"). Do not embellish.

The value comes from `RaptorConfig.effective_version()`: in a git checkout it is the true position past the last release tag (`<tag>-<commits>-g<sha>`, with `-local` when the tree has uncommitted changes), so a clone never claims to be a clean release it has moved past; in an installed or archived copy with no git metadata it is the baked release number stamped at release time.
