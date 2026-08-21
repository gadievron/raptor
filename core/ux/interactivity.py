"""Interactivity gate: may this session ask the operator a question?

RAPTOR's slash commands and skills are markdown instructions executed
by a Claude Code session, and some of them define decision points
where an *interactive* session should present a structured
multiple-choice prompt (the AskUserQuestion tool) instead of prose.
The same skill text, however, also runs in contexts where nobody will
ever answer:

  * dispatched ``claude -p`` sub-agents (agentic passes, gap-audit,
    cc_dispatch) — a pending question would stall the pipeline;
  * CI — the run must stay deterministic and unattended.

This module is the single yes/no authority those instructions consult
(via the ``libexec/raptor-may-ask`` shim) before asking. The answer is
doctrine, not enforcement: a session that cannot run the shim must
treat itself as non-interactive, and every AskUserQuestion instruction
in a command/skill file names a non-interactive fallback — always the
pre-existing default behaviour.

Nothing here is invented detection. The gate composes RAPTOR's two
existing operator-presence precedents:

  * the annotation provenance predicate
    (``core.annotations.provenance``): any std fd is a TTY →
    interactive. Covers direct operator invocations from a terminal.
  * the rule-of-two human-attendance probe
    (``core.security.rule_of_two``): CI-marker hardening (a CI runner
    with an allocated pseudo-TTY must not count), plus the Linux
    ``/proc`` ancestor walk for a recently-active controlling
    terminal. That walk is what sees the human inside a Claude Code
    session — the Bash tool runs its subprocesses with the
    controlling terminal detached (``/dev/tty`` is ENXIO, std fds are
    pipes), but the interactive ``claude`` ancestor keeps its
    terminal. Headless dispatch children are new session leaders with
    no terminal anywhere in their chain.

Decision order (first hit wins):

  1. ``RAPTOR_NONINTERACTIVE`` truthy → non-interactive. RAPTOR
     stamps this into every ``claude`` CLI child it spawns
     (``core.llm.cc_adapter.cc_subprocess_env``), so dispatched
     sub-agents carry an explicit marker no probe can override.
     Operators may also export it to force the documented defaults
     everywhere.
  2. CI (``rule_of_two.is_ci()``: ``RAPTOR_CI``, ``CI``,
     ``GITHUB_ACTIONS``, vendor markers) → non-interactive.
  3. Any std fd is a TTY → interactive.
  4. Human-attendance probe finds a recently-active controlling
     terminal in the process ancestry → interactive.
  5. Otherwise → non-interactive (fail closed).
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping

# Human-readable verdicts, printed by ``libexec/raptor-may-ask``.
INTERACTIVE = "interactive"
NON_INTERACTIVE = "non-interactive"

# Explicit override: any truthy value forces the non-interactive
# verdict. Stamped into claude CLI children by cc_subprocess_env.
NONINTERACTIVE_ENV = "RAPTOR_NONINTERACTIVE"

# Values treated as "not set" for the override, so
# ``RAPTOR_NONINTERACTIVE=0`` is benign (matches rule_of_two's CI
# falsy handling).
_FALSEY = frozenset({"", "0", "false", "no", "off"})


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() not in _FALSEY


def session_may_ask(
    environ: Mapping[str, str] | None = None,
    *,
    ci: Callable[[], bool] | None = None,
    std_fd_interactive: bool | None = None,
    human_probe: Callable[[], bool] | None = None,
) -> bool:
    """Whether this session may present an operator prompt.

    The keyword hooks exist for hermetic tests; production callers
    pass nothing and get the live process environment,
    ``rule_of_two.is_ci``, the annotation-provenance std-fd predicate,
    and the rule-of-two human-attendance probe.
    """
    env = os.environ if environ is None else environ
    if _truthy(env.get(NONINTERACTIVE_ENV)):
        return False
    if ci is None:
        from core.security.rule_of_two import is_ci as ci
    if ci():
        return False
    if std_fd_interactive is None:
        from core.annotations.provenance import (
            INTERACTIVE_TTY,
            PROVENANCE_KEY,
            detect_invocation_context,
        )
        std_fd_interactive = (
            detect_invocation_context()[PROVENANCE_KEY] == INTERACTIVE_TTY
        )
    if std_fd_interactive:
        return True
    if human_probe is None:
        # Deliberate cross-module private import, resolved at call
        # time so test patches on the rule_of_two attribute keep
        # working. The probe already fails closed on any error.
        from core.security.rule_of_two import (
            _session_has_human_terminal as human_probe,
        )
    try:
        return bool(human_probe())
    except Exception:  # noqa: BLE001 — fail closed: no proof of an operator
        return False


def session_interactivity(
    environ: Mapping[str, str] | None = None,
    *,
    ci: Callable[[], bool] | None = None,
    std_fd_interactive: bool | None = None,
    human_probe: Callable[[], bool] | None = None,
) -> str:
    """String verdict for CLI display: ``interactive`` / ``non-interactive``."""
    may = session_may_ask(
        environ,
        ci=ci,
        std_fd_interactive=std_fd_interactive,
        human_probe=human_probe,
    )
    return INTERACTIVE if may else NON_INTERACTIVE
