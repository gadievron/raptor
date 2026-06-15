"""Central configuration for the sanitizer-cut value-bound gate.

Review #4 on PR #794. The gate's three knobs used to be read straight
from process-global env vars (``RAPTOR_SANITIZER_CUT``,
``RAPTOR_SANITIZER_CUT_NO_LEXICAL``, ``RAPTOR_SANITIZER_CUT_PARITY_LOG``)
deep inside :mod:`core.dataflow.smt_barrier`. That had two footguns:

1. ``NO_LEXICAL`` set while ``SANITIZER_CUT`` was unset silently
   disabled *all* suppression — the value-bound gate was off AND the
   lexical fallback was off, so every finding passed through with no
   warning.
2. ``PARITY_LOG=1`` (a boolean-style value) wrote telemetry to a file
   literally named ``1`` in the current working directory.

This module replaces the three booleans with a single 4-state *mode*
that the consuming commands (``/agentic``, ``/validate``, ``/codeql``)
set from a ``--sanitizer-cut`` CLI flag. The mode collapses the knob
space so the dangerous combination is unrepresentable:

* ``off``    — value-bound gate disabled; lexical fallback on. Default.
* ``on``     — value-bound gate enabled; lexical fallback on.
* ``strict`` — value-bound gate enabled; lexical fallback OFF
               (the Phase 16 end-state: a verdict the gate can't make
               becomes "don't suppress", never deferring to lexical).
* ``shadow`` — suppression behaves like ``off``, but the value-bound
               verdict is computed alongside the lexical decision and
               written to the parity log (Phase 15 telemetry).

Note there is **no** mode with both the value-bound gate and the
lexical fallback off, so footgun 1 cannot be expressed.

Resolution precedence: an explicit :func:`configure` call (driven by a
CLI flag) wins; otherwise the legacy env vars are read as a
back-compat fallback — with the two footguns fixed at the resolution
point (see :func:`_resolve_from_env`). Existing env-driven tests keep
working because :func:`current` re-reads the env each call when no
explicit configuration is active.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Optional

VALID_MODES = ("off", "on", "strict", "shadow")

# Default parity-log filename, placed under the run directory when a
# bare/boolean log value or shadow mode asks for telemetry without an
# explicit path.
DEFAULT_PARITY_LOG_NAME = "sanitizer_cut_parity.jsonl"

_TRUTHY = ("1", "true", "on", "yes")

# Legacy env vars — read only as a back-compat fallback when no
# explicit configure() has run.
_ENV_MODE = "RAPTOR_SANITIZER_CUT"
_ENV_NO_LEXICAL = "RAPTOR_SANITIZER_CUT_NO_LEXICAL"
_ENV_PARITY_LOG = "RAPTOR_SANITIZER_CUT_PARITY_LOG"


@dataclass(frozen=True)
class SanitizerCutConfig:
    """Resolved gate configuration.

    ``value_bound_enabled`` — consult the value-bound vertex-cut gate.
    ``lexical_fallback_enabled`` — fall back to the lexical heuristic
    when the gate can't decide. False only in ``strict``.
    ``parity_log_path`` — where to append shadow telemetry, or None.
    ``mode`` — the originating mode name, for introspection / audit.
    """

    mode: str
    value_bound_enabled: bool
    lexical_fallback_enabled: bool
    parity_log_path: Optional[str]


# Module-level explicit configuration. None means "fall back to env".
_active: Optional[SanitizerCutConfig] = None


def _truthy(value: str) -> bool:
    return value.strip().lower() in _TRUTHY


def _resolve_parity_log(
    raw: Optional[str], run_dir: Optional[str], *, want_default: bool,
) -> Optional[str]:
    """Resolve a parity-log path.

    A boolean-style value (``1`` / ``true`` / ``on`` / ``yes``) or
    ``want_default`` means "enable telemetry at the default path"
    rather than a literal filename — fixing footgun 2. The default
    lands under ``run_dir`` when known, else the CWD.
    """
    if raw is not None:
        raw = raw.strip()
    if raw:
        if _truthy(raw):
            want_default = True
        else:
            return raw
    if not want_default:
        return None
    base = run_dir if run_dir else "."
    return os.path.join(base, DEFAULT_PARITY_LOG_NAME)


def config_for_mode(
    mode: str,
    *,
    parity_log: Optional[str] = None,
    run_dir: Optional[str] = None,
) -> SanitizerCutConfig:
    """Build a :class:`SanitizerCutConfig` for ``mode``.

    ``parity_log`` is an explicit path (or a boolean-style string that
    means "default path"). ``run_dir`` is the active run's output
    directory, used to place the default parity log.
    """
    mode = (mode or "off").strip().lower()
    if mode not in VALID_MODES:
        raise ValueError(
            f"invalid sanitizer-cut mode {mode!r}; "
            f"expected one of {', '.join(VALID_MODES)}"
        )
    value_bound = mode in ("on", "strict")
    lexical = mode != "strict"
    parity_path = _resolve_parity_log(
        parity_log, run_dir, want_default=(mode == "shadow"),
    )
    return SanitizerCutConfig(
        mode=mode,
        value_bound_enabled=value_bound,
        lexical_fallback_enabled=lexical,
        parity_log_path=parity_path,
    )


def _resolve_from_env() -> SanitizerCutConfig:
    """Back-compat resolution from the legacy env vars, with both
    footguns fixed.

    ``NO_LEXICAL`` is honoured only when the value-bound gate is also
    on (footgun 1) — set without ``SANITIZER_CUT`` it emits a one-line
    warning and is ignored, so suppression never silently turns off.
    ``PARITY_LOG`` is resolved through :func:`_resolve_parity_log`
    (footgun 2)."""
    cut_on = _truthy(os.environ.get(_ENV_MODE, ""))
    no_lexical = _truthy(os.environ.get(_ENV_NO_LEXICAL, ""))
    parity_raw = os.environ.get(_ENV_PARITY_LOG)

    if no_lexical and not cut_on:
        sys.stderr.write(
            f"warning: {_ENV_NO_LEXICAL} is set but {_ENV_MODE} is not "
            "— ignoring it (disabling the lexical fallback without the "
            "value-bound gate would disable all sanitizer suppression). "
            f"Set {_ENV_MODE}=1 too, or use --sanitizer-cut=strict.\n"
        )
        no_lexical = False

    if cut_on and no_lexical:
        mode = "strict"
    elif cut_on:
        mode = "on"
    else:
        mode = "off"

    parity_path = _resolve_parity_log(parity_raw, None, want_default=False)
    # An env parity log with the gate off is telemetry-only — the env
    # equivalent of shadow mode. Keep the resolved suppression mode but
    # carry the log path.
    base = config_for_mode(mode)
    return SanitizerCutConfig(
        mode=base.mode,
        value_bound_enabled=base.value_bound_enabled,
        lexical_fallback_enabled=base.lexical_fallback_enabled,
        parity_log_path=parity_path,
    )


def _export_to_env(c: SanitizerCutConfig) -> None:
    """Write the resolved config back to the canonical env vars so
    subprocesses spawned by a consuming command (``/agentic`` spawns
    LLM-analysis / codeql workers) inherit it and reconstruct the same
    config through :func:`_resolve_from_env`. Only footgun-safe
    combinations are ever written, so the inherited resolution can't
    trip footgun 1. The flag stays the operator interface; the env vars
    are an internal transport."""
    os.environ["RAPTOR_SANITIZER_CUT"] = (
        "1" if c.value_bound_enabled else "0"
    )
    if not c.lexical_fallback_enabled:
        os.environ["RAPTOR_SANITIZER_CUT_NO_LEXICAL"] = "1"
    else:
        os.environ.pop("RAPTOR_SANITIZER_CUT_NO_LEXICAL", None)
    if c.parity_log_path:
        os.environ["RAPTOR_SANITIZER_CUT_PARITY_LOG"] = c.parity_log_path
    else:
        os.environ.pop("RAPTOR_SANITIZER_CUT_PARITY_LOG", None)


def configure(
    mode: str,
    *,
    parity_log: Optional[str] = None,
    run_dir: Optional[str] = None,
    export_env: bool = False,
) -> SanitizerCutConfig:
    """Install an explicit configuration (from a CLI flag). Returns the
    resolved config. Overrides the env-var fallback for the process.

    ``export_env=True`` also writes the resolved state to the canonical
    env vars so spawned subprocesses inherit it — consuming commands
    pass this; tests do not."""
    global _active
    _active = config_for_mode(mode, parity_log=parity_log, run_dir=run_dir)
    if export_env:
        _export_to_env(_active)
    return _active


def reset() -> None:
    """Clear the explicit configuration — :func:`current` falls back to
    the env vars again. Primarily for tests."""
    global _active
    _active = None


def current() -> SanitizerCutConfig:
    """The active configuration. Explicit :func:`configure` wins;
    otherwise resolve live from the env each call (so env-driven tests
    and ad-hoc runs keep working)."""
    if _active is not None:
        return _active
    return _resolve_from_env()


def value_bound_enabled() -> bool:
    return current().value_bound_enabled


def lexical_fallback_enabled() -> bool:
    return current().lexical_fallback_enabled


def parity_log_path() -> Optional[str]:
    return current().parity_log_path


_PERSIST_NAME = "sanitizer-cut-config.json"


def persist(run_dir: str) -> Optional[str]:
    """Write the active config to ``<run_dir>/sanitizer-cut-config.json``
    so a multi-process pipeline (``/validate`` runs each stage as its
    own process) can reload it. Returns the path written, or None if
    there is no explicit config to persist."""
    if _active is None:
        return None
    import json
    path = os.path.join(run_dir, _PERSIST_NAME)
    payload = {
        "mode": _active.mode,
        "parity_log_path": _active.parity_log_path,
    }
    # Per-run internal artifact — no other UID needs to read it. Create
    # 0o600 rather than the umask default (0o644) so it isn't
    # world-readable (review #4 on PR #794). O_TRUNC mirrors the
    # overwrite semantics of "w".
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path


def load_persisted(
    run_dir: str, *, export_env: bool = True,
) -> Optional[SanitizerCutConfig]:
    """Reload a config persisted by :func:`persist` and install it
    (with env export by default). No-op returning None when the file is
    absent or unreadable — the env fallback stays active."""
    import json
    path = os.path.join(run_dir, _PERSIST_NAME)
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except (OSError, ValueError):
        return None
    return configure(
        payload.get("mode", "off"),
        parity_log=payload.get("parity_log_path"),
        run_dir=run_dir,
        export_env=export_env,
    )


def add_cli_arguments(parser) -> None:
    """Register ``--sanitizer-cut`` / ``--sanitizer-cut-parity-log`` on
    an :mod:`argparse` parser. Consuming commands call this, then pass
    the parsed values (plus the run dir) to :func:`configure`."""
    parser.add_argument(
        "--sanitizer-cut",
        choices=VALID_MODES,
        default=None,
        metavar="off|on|strict|shadow",
        help=(
            "Value-bound sanitizer-cut suppression mode (default: off). "
            "on=gate+lexical fallback; strict=gate only, no lexical; "
            "shadow=off behaviour + parity telemetry."
        ),
    )
    parser.add_argument(
        "--sanitizer-cut-parity-log",
        default=None,
        metavar="PATH",
        help=(
            "Append sanitizer-cut parity telemetry to PATH "
            "(default: <run_dir>/" + DEFAULT_PARITY_LOG_NAME + " in "
            "shadow mode)."
        ),
    )


def configure_from_args(
    args, *, run_dir: Optional[str] = None, export_env: bool = False,
) -> Optional[SanitizerCutConfig]:
    """Apply parsed argparse values. No-op (returns None, leaving the
    env fallback active) when ``--sanitizer-cut`` was not passed.

    ``export_env=True`` propagates the resolved state to the env so
    subprocess workers inherit it — consuming commands pass this."""
    mode = getattr(args, "sanitizer_cut", None)
    parity_log = getattr(args, "sanitizer_cut_parity_log", None)
    if mode is None and parity_log is None:
        return None
    return configure(
        mode or "off", parity_log=parity_log, run_dir=run_dir,
        export_env=export_env,
    )


__all__ = [
    "VALID_MODES",
    "SanitizerCutConfig",
    "config_for_mode",
    "configure",
    "configure_from_args",
    "persist",
    "load_persisted",
    "add_cli_arguments",
    "current",
    "reset",
    "value_bound_enabled",
    "lexical_fallback_enabled",
    "parity_log_path",
]
