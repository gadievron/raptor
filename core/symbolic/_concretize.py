"""Adversarial size concretization for symbolic-length libc calls.

A copy/read whose LENGTH is attacker data (``memcpy(dst, src,
hdr[1])`` — the classic declared-length overflow) makes angr build a
per-byte conditional expression over every possible length. The
resulting AST wedges z3 at ASSERT time, which the solver ``timeout``
parameter does not bound (it only caps check-sat) — the isolate's
hard kill is the only thing that stops it, and the solve is lost.

The escape is to never build that expression: at the SimProcedure
boundary, a symbolic size argument is constrained to its MAXIMUM
satisfiable value (capped). For overflow verification the maximum is
exactly the adversarial choice — the attacker supplying the length
picks the largest the path admits. The cost is completeness, not
soundness: a witness found under the max-length constraint is a real
witness (the constraint only narrows the state); a hijack reachable
only at some mid-range length is missed, which the honest
"no witness" result already covers.

Hooks are installed on the angr project INSIDE the isolated solve
child (each solve runs in its own spawned process), so the shared
per-process project cache never leaks hooked state to other
consumers.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

#: Ceiling for the concretized size — generous for stack smashes,
#: small enough that the concrete copy stays cheap.
MAX_CONCRETE_SIZE = 0x1000

#: libc/POSIX calls whose size-class arguments explode when symbolic,
#: with the 0-based run() argument indices to concretize. fread/fwrite
#: multiply two arguments; both get pinned.
_SIZE_ARG_HOOKS = {
    ("libc", "memcpy"): (2,),
    ("libc", "memmove"): (2,),
    ("libc", "memset"): (2,),
    ("libc", "strncpy"): (2,),
    ("libc", "fread"): (1, 2),
    ("libc", "fwrite"): (1, 2),
    ("posix", "read"): (2,),
    ("posix", "recv"): (2,),
}


def _pin_size(state, val, cap: int):
    """Constrain a symbolic size to its max satisfiable value ≤ cap."""
    try:
        if not getattr(val, "symbolic", False):
            return
        mx = state.solver.max(val)
        if mx > cap:
            if not state.solver.satisfiable(
                    extra_constraints=[val <= cap]):
                return  # size is forced above the cap — leave it
            state.solver.add(val <= cap)
            mx = state.solver.max(val)
        state.solver.add(val == mx)
        logger.debug("adversarial size concretization: pinned to %#x", mx)
    except Exception:  # noqa: BLE001 — a failed pin degrades to stock behaviour
        logger.debug("size concretization failed", exc_info=True)


def install_adversarial_size_hooks(
    project, cap: int = MAX_CONCRETE_SIZE,
) -> int:
    """Hook symbolic-size libc calls with a max-concretizing preamble.

    Returns the number of symbols hooked. Idempotent per project.
    """
    try:
        from angr.procedures import SIM_PROCEDURES
    except ImportError:
        return 0
    if getattr(project, "_raptor_size_hooks", False):
        return 0
    import inspect
    hooked = 0
    for (lib, name), size_indices in _SIZE_ARG_HOOKS.items():
        base = SIM_PROCEDURES.get(lib, {}).get(name)
        if base is None:
            continue
        # angr derives a procedure's arity from run()'s signature; a
        # *args wrapper would zero it — pass the base arity through.
        base_arity = len(inspect.getfullargspec(base.run).args) - 1

        class _Pinned(base):  # type: ignore[misc,valid-type]  # noqa: B903
            _pin_indices = size_indices

            def run(self, *args, **kwargs):
                for i in self._pin_indices:
                    if i < len(args):
                        _pin_size(self.state, args[i], cap)
                return super().run(*args, **kwargs)

        try:
            project.hook_symbol(
                name, _Pinned(num_args=base_arity), replace=True,
            )
            hooked += 1
        except Exception:  # noqa: BLE001 — symbol absent from this binary
            continue
    project._raptor_size_hooks = True
    return hooked
