"""CLI-driven command injection: sys.argv → subprocess.call(shell=True).

Tests RAPTOR's LocalFlowSource coverage. The stdlib
`RemoteFlowSource`-based CodeQL query (CommandInjection.ql) does NOT
flag this — its source model is scoped to network inputs (HTTP, RPC,
etc.) and excludes process-local sources like sys.argv.

The RAPTOR-shipped CommandInjectionLocal.ql query (using
`LocalFlowSource`) DOES flag this, providing IRIS Tier 1 confirmation
for CLI-driven command-injection findings that would otherwise have
to fall through to Tier 2's LLM-customised predicates.
"""

import subprocess
import sys


def main() -> int:
    # sys.argv[1] is attacker-controlled when this script runs setuid /
    # is called from a wrapper that takes user input.
    target = sys.argv[1]
    return subprocess.call(f"ping -c1 {target}", shell=True)


if __name__ == "__main__":
    sys.exit(main())
