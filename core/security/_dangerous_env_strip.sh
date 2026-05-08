#!/usr/bin/env bash
# Shared dangerous-env-var strip list for `bin/raptor` and `bin/cve-diff`.
#
# Lives in `core/security/` next to its Python siblings:
#   * core/config.RaptorConfig.DANGEROUS_ENV_VARS — canonical Python list
#   * core/security/env_sanitisation.strip_env_vars() — Python helper
#     that strips them when spawning subprocesses
#
# This `.sh` is the launcher-side equivalent: it strips the same
# variables BEFORE the Python interpreter even starts, so a hostile
# parent env can't inject code via LD_PRELOAD / PYTHONSTARTUP / etc.
# during Python's own boot. Putting all three artefacts under
# `core/security/` means a `git grep DANGEROUS_ENV_VARS` over that
# directory surfaces the canonical list regardless of which language
# layer is enforcing.
#
# This file is SOURCED, not executed. It declares the canonical set of
# environment variables that execute attacker code INSIDE the
# launcher → Python → Claude Code chain (or, for cve-diff, inside the
# launcher → Python → cve-diff agent chain).
#
# Pre-fix the two launchers maintained their own near-identical strip
# lists:
#   * bin/raptor stripped 30+ vars (the canonical set + a handful of
#     newer additions: LD_DEBUG, LD_PROFILE, NODE_*, MALLOC_*)
#   * bin/cve-diff stripped 13 vars (a strict subset, missing the
#     newer additions)
#
# The drift was real: when batch 581 added LD_DEBUG/LD_PROFILE/
# LD_PROFILE_OUTPUT to bin/raptor, bin/cve-diff was NOT updated —
# operators running cve-diff had a wider attack surface than
# operators running raptor. The shared fragment closes that gap and
# guarantees future additions land in both launchers atomically.
#
# Do NOT add variables here that only affect SUBPROCESSES (git config,
# JAVA_TOOL_OPTIONS, shell rc vars, editor/pager, Kerberos). Those
# are handled by `core.config.get_safe_env()` when we spawn children;
# stripping them in the launcher would needlessly break the operator's
# legitimate environment.

for _raptor_strip_var in \
    LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT \
    LD_DEBUG LD_PROFILE LD_PROFILE_OUTPUT \
    GCONV_PATH \
    PYTHONSTARTUP PYTHONPATH PYTHONHOME PYTHONUSERBASE \
    PYTHONBREAKPOINT PYTHONINSPECT \
    OPENSSL_CONF SSLKEYLOGFILE \
    NODE_OPTIONS NODE_PATH NODE_EXTRA_CA_CERTS \
    MALLOC_CONF JE_MALLOC_CONF MALLOC_CHECK_ MALLOC_PERTURB_ \
    BASH_ENV ENV ; do
    unset "$_raptor_strip_var"
done
unset _raptor_strip_var
