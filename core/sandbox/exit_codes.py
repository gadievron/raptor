"""Documented exit codes for sandbox fail-CLOSED sites.

Each constant names a specific reason the sandboxed child terminated
itself post-fork rather than continuing with a degraded isolation
posture. Operators forking the RAPTOR sandbox can use these to
distinguish the failure mode without parsing stderr.

Numeric values are fixed by the original W31 / W35.C / W36.E.1
design — do not renumber without coordinating with operator-side
scripts that may already key off them.

Convention:
- 0-125: app-defined exit codes (we use these).
- 126: "permission/exec failure" — used here for sandbox setup
  failures that leave the child without its expected isolation.
- 127: "command not found" — reserved, not used here.
- 128+N: signal N — reserved by POSIX, not used here.

The stderr message remains the authoritative disambiguator (it
names the specific syscall/site that failed). These codes give
parent processes a structured way to react without parsing text.
"""

# Filesystem / mount isolation could not be installed. Parent
# expected an enforced sandbox; silent downgrade would be a
# contract violation, so the child exits before any user code runs.
SANDBOX_EXIT_LANDLOCK_DOWNGRADE = 126
SANDBOX_EXIT_MOUNT_NS_BIND_FAIL = 126

# RLIMIT_CORE could not be set to (0, 0). Without it, a crashing
# sandboxed process can dump a core file containing the full address
# space — including any secrets read under Landlock's permissive
# default read policy (~/.ssh, ~/.aws, etc.). The crash itself
# becomes a credential-exfiltration primitive. Distinct from the
# 126 codes above so post-mortem can tell which guarantee was lost.
SANDBOX_EXIT_RLIMIT_CORE_FAIL = 99
