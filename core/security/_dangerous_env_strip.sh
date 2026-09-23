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
# The drift was real: when LD_DEBUG/LD_PROFILE/LD_PROFILE_OUTPUT
# were added to bin/raptor, bin/cve-diff was NOT updated —
# operators running cve-diff had a wider attack surface than
# operators running raptor. The shared fragment closes that gap and
# guarantees future additions land in both launchers atomically.
#
# Do NOT add variables here that only affect SUBPROCESSES (git config,
# JAVA_TOOL_OPTIONS, shell rc vars, editor/pager, Kerberos). Those
# are handled by `core.config.get_safe_env()` when we spawn children;
# stripping them in the launcher would needlessly break the operator's
# legitimate environment.
#
# Exported-function hardening. bash imports `BASH_FUNC_<name>%%` env
# entries as shell functions at startup, and (outside POSIX mode)
# function lookup precedes EVERY builtin — a hostile parent env
# exporting a function named `unset` therefore both executed attacker
# code from this very loop and silently neutralised the strip. No
# builtin name is safe to call until precedence is restored, so the
# fragment leans only on primitives an exported function cannot
# shadow: reserved words, variable assignment/expansion (SYNTAX, not
# command lookup), and — once `POSIXLY_CORRECT=1` is assigned —
# special builtins, which POSIX command search finds BEFORE functions
# (`unset` is one). From there: clear any shadow on the two regular
# builtins used below (`declare`, `read` — regular builtins rank
# below functions even in POSIX mode), then drop every EXPORTED
# function outright. In a launcher chain an exported function can
# only have arrived via env import (the launchers export none); each
# one is a PATH-grade command shadow, and `unset -f` removes both the
# function and its export so children do not re-import it.
#
# Boundary (documented, not defended): a fully hostile parent env
# also owns PATH itself — redirecting `python3` to an attacker binary
# is a different primitive this fragment never claimed to close. The
# claim here is narrower and now holds: the strip loop executes no
# attacker code, the listed variables are truly gone, and no imported
# function survives into the launcher or its children.
_raptor_had_posix=${POSIXLY_CORRECT+set}
POSIXLY_CORRECT=1
unset -f unset declare read 2>/dev/null || :
while read -r _raptor_decl _raptor_flags _raptor_fname; do
    case $_raptor_decl:$_raptor_flags in
        declare:*x*) unset -f "$_raptor_fname" 2>/dev/null || : ;;
    esac
done <<RAPTOR_FUNC_SWEEP
$(declare -F)
RAPTOR_FUNC_SWEEP
unset _raptor_decl _raptor_flags _raptor_fname

for _raptor_strip_var in \
    LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT \
    LD_DEBUG LD_PROFILE LD_PROFILE_OUTPUT \
    DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH \
    DYLD_FALLBACK_LIBRARY_PATH DYLD_FRAMEWORK_PATH \
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

# Leave POSIX mode only if this fragment enabled it.
if [ "$_raptor_had_posix" != set ]; then
    unset POSIXLY_CORRECT
fi
unset _raptor_had_posix
