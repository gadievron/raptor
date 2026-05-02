"""Named sandbox profile definitions.

Profiles are the ONLY legitimate way for a user to downgrade isolation.
They map a human-memorable name onto a coherent set of layer settings.
Kept in a tiny standalone module so both `cli.py` (for argparse choices)
and `context.py` (for profile resolution in sandbox()) can import them
without a circular dependency.

Wrapped in MappingProxyType because `PROFILES` is exposed via __all__ —
a plain dict would let an external caller mutate `PROFILES["full"]
["block_network"] = False` and corrupt the module for every subsequent
sandbox() invocation in the process.
"""

import types

# Profile definitions
# -------------------
# full:         network blocked + Landlock + seccomp (incl. ptrace) + rlimits.
#               The default. Appropriate for scan/exploit/PoC work.
# debug:        full, but seccomp permits ptrace so gdb/rr can trace the
#               target. Use for /crash-analysis. Target AND debugger run
#               in the same sandbox — debugger forks target as a descendant
#               so ptrace_scope=1 naturally authorises the trace.
# network-only: network blocked + rlimits only (no Landlock, no seccomp).
#               For tools whose correctness requires unrestricted fs or
#               syscalls within a build — user's last-resort-short-of-none.
# none:         rlimits only. Emergency escape hatch.
#
# `seccomp` is the profile name passed into _make_seccomp_preexec(); an
# empty string disables seccomp for that profile.
PROFILES = types.MappingProxyType({
    "full":         types.MappingProxyType({"block_network": True,  "use_landlock": True,  "seccomp": "full"}),
    "debug":        types.MappingProxyType({"block_network": True,  "use_landlock": True,  "seccomp": "debug"}),
    "network-only": types.MappingProxyType({"block_network": True,  "use_landlock": False, "seccomp": ""}),
    "none":         types.MappingProxyType({"block_network": False, "use_landlock": False, "seccomp": ""}),
})
DEFAULT_PROFILE = "full"


# Kwargs that configure isolation. Callers must not pass these to
# sandbox().run() or run_trusted() — isolation is set on context creation,
# not per-call. Defined here so sandbox-context's inner run() and the
# top-level run_trusted() can both reference it.
_SANDBOX_KWARGS = frozenset({
    "block_network", "target", "output", "allowed_tcp_ports",
    "profile", "disabled", "limits", "map_root",
    "use_egress_proxy", "proxy_hosts",
    "restrict_reads", "readable_paths",
    "caller_label",
    "fake_home",
    # tool_paths is sandbox()-level (extra dirs to bind-mount in
    # mount-ns mode so operator-installed tools at non-standard
    # paths — pip --user, pyenv, homebrew — are visible inside
    # the sandbox). Passing to inner run() would silently no-op.
    "tool_paths",
})
