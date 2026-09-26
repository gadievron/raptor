"""Per-run Joern resource controls.

Mirrors ``packages/codeql/tunables.py``: centralises the JVM heap,
CPG build timeout, and query timeout that every Joern invocation
across RAPTOR needs.  Previously these were scattered as module-level
constants in ``core/audit/orchestrator.py`` (600s) and
``core/audit/sweep.py`` (600s / 300s), with no operator override path.

Defaults come from RAPTOR's central tuning config (``core.tuning``,
backed by ``tuning.json``) via ``from_tuning()``.  Operator CLI flags
override per-run.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class JoernTunables:
    """Joern resource knobs.

      * ``heap_mb``          — JVM ``-Xmx`` in MB.  ``None`` = JVM default.
      * ``cpg_timeout_s``    — wall-clock cap on ``joern-parse`` (CPG build).
      * ``import_timeout_s`` — wall-clock cap on loading a built CPG into the
        server.  Separate from ``cpg_timeout_s`` because the import runs in
        a background thread and large CPGs (>50 MB) routinely need several
        minutes to deserialise inside the JVM.
      * ``query_timeout_s``  — wall-clock cap on each ``joern --script`` query.
    """
    heap_mb: int | None = None
    cpg_timeout_s: int = 300
    import_timeout_s: int = 900
    query_timeout_s: int = 300
    # True when the central tuning resolved ``joern_cpg_timeout_s``
    # to the derived-at-build-time sentinel: ``cpg_timeout_s`` then
    # holds the unknown-scope fallback, and build sites that know the
    # target refine it from the scope's SLOC estimate (see
    # ``resolve_cpg_timeout_s``).
    cpg_timeout_auto: bool = False
    # True when the central tuning resolved ``joern_import_timeout_s``
    # to the derived-at-import-time sentinel: ``import_timeout_s``
    # then holds the unknown-size fallback, and import sites that
    # have the built cpg.bin refine it from the file's size (see
    # ``resolve_import_timeout_s``).
    import_timeout_auto: bool = False
    # True when ``heap_mb`` was DERIVED (tuning "auto"), not an
    # explicit operator number. Limit-raising consumers (the
    # retry-at-derived-max path) honor explicit values both
    # directions: an explicit heap is never capped and never raised.
    heap_is_derived: bool = False

    @classmethod
    def from_tuning(cls, *, overrides: dict | None = None) -> JoernTunables:
        """Build from RAPTOR's central tuning config.

        ``overrides`` is an operator-CLI-arg-shaped dict; any non-None
        value overrides the tuning-resolved default for that field.
        Recognised keys: ``heap_mb``, ``cpg_timeout_s``,
        ``import_timeout_s``, ``query_timeout_s``.
        """
        from core.tuning import (
            JOERN_CPG_TIMEOUT_DERIVED,
            JOERN_IMPORT_TIMEOUT_DERIVED,
            derive_joern_cpg_timeout_s,
            derive_joern_import_timeout_s,
            get_tuning,
        )
        t = get_tuning()
        overrides = overrides or {}

        heap_mb = overrides.get("heap_mb")
        heap_is_derived = False
        if heap_mb is None:
            heap_mb = t.joern_heap_mb if t.joern_heap_mb > 0 else None
            heap_is_derived = heap_mb is not None and bool(
                getattr(t, "joern_heap_mb_derived", False),
            )

        cpg_timeout_auto = False
        cpg_timeout_s = overrides.get("cpg_timeout_s")
        if cpg_timeout_s is None:
            cpg_timeout_s = t.joern_cpg_timeout_s
            if cpg_timeout_s == JOERN_CPG_TIMEOUT_DERIVED:
                # Derived-at-build-time: hold the unknown-scope
                # fallback so every consumer still sees a usable
                # number; sites that know the target refine it.
                cpg_timeout_auto = True
                cpg_timeout_s = derive_joern_cpg_timeout_s(None)

        import_timeout_auto = False
        import_timeout_s = overrides.get("import_timeout_s")
        if import_timeout_s is None:
            # getattr with the sentinel default: a stale Tuning
            # instance without the key behaves like "auto" (derive at
            # the import site) rather than pinning a literal here.
            import_timeout_s = getattr(
                t, "joern_import_timeout_s", JOERN_IMPORT_TIMEOUT_DERIVED,
            )
            if import_timeout_s == JOERN_IMPORT_TIMEOUT_DERIVED:
                # Derived-at-import-time: hold the unknown-size
                # fallback so every consumer still sees a usable
                # number; sites that have the built CPG refine it.
                import_timeout_auto = True
                import_timeout_s = derive_joern_import_timeout_s(None)

        query_timeout_s = overrides.get("query_timeout_s")
        if query_timeout_s is None:
            query_timeout_s = t.joern_query_timeout_s

        return cls(
            heap_mb=heap_mb,
            cpg_timeout_s=cpg_timeout_s,
            import_timeout_s=import_timeout_s,
            query_timeout_s=query_timeout_s,
            cpg_timeout_auto=cpg_timeout_auto,
            import_timeout_auto=import_timeout_auto,
            heap_is_derived=heap_is_derived,
        )


def resolve_cpg_timeout_s(
    tunables: JoernTunables | None,
    target: Path | str,
    *,
    exclude_dirs: tuple[str, ...] = (),
) -> int:
    """Build-site resolution of a derived CPG timeout.

    Non-auto tunables (an explicit config value or an operator
    override) return their number unchanged. Auto tunables derive the
    timeout from the in-scope source-size estimate of *target* under
    the same exclusion set the build will use — key/analysis/timeout
    parity. Estimation failure degrades to the unknown-scope fallback
    already held in ``cpg_timeout_s``, never to an error (a timeout
    derivation must not cost the channel).
    """
    base = int(
        getattr(tunables, "cpg_timeout_s", JoernTunables.cpg_timeout_s)
        if tunables is not None else JoernTunables.cpg_timeout_s
    )
    if tunables is None or not getattr(tunables, "cpg_timeout_auto", False):
        return base
    try:
        from pathlib import Path as _Path

        from core.tuning import derive_joern_cpg_timeout_s

        from .runner import estimate_in_scope_sloc
        sloc = estimate_in_scope_sloc(
            _Path(target), exclude_dirs=exclude_dirs,
        )
        derived = derive_joern_cpg_timeout_s(sloc if sloc > 0 else None)
    except Exception:  # noqa: BLE001 — derivation must not cost the channel
        logger.debug("CPG timeout derivation failed", exc_info=True)
        return base
    logger.info(
        "joern CPG timeout derived: %ds (~%d estimated in-scope SLOC)",
        derived, sloc,
    )
    return derived


def resolve_import_timeout_s(
    tunables: JoernTunables | None,
    cpg_bytes: int | None,
) -> int:
    """Import-site resolution of a derived CPG-import timeout.

    Non-auto tunables (an explicit config value or an operator
    override) return their number unchanged. Auto tunables derive the
    timeout from *cpg_bytes* — the serialized size of the built
    cpg.bin the import site is about to load (the import wall is
    client-side deserialise work, so the file size is the honest
    scale signal). Unknown size or derivation failure degrades to the
    fallback already held in ``import_timeout_s``, never to an error
    (a timeout derivation must not cost the channel).
    """
    base = int(
        getattr(tunables, "import_timeout_s", JoernTunables.import_timeout_s)
        if tunables is not None else JoernTunables.import_timeout_s
    )
    if tunables is None or not getattr(tunables, "import_timeout_auto", False):
        return base
    try:
        from core.tuning import derive_joern_import_timeout_s
        derived = derive_joern_import_timeout_s(cpg_bytes)
    except Exception:  # noqa: BLE001 — derivation must not cost the channel
        logger.debug("CPG import timeout derivation failed", exc_info=True)
        return base
    if derived != base:
        logger.info(
            "joern CPG import timeout derived: %ds (CPG %.0f MiB)",
            derived, (cpg_bytes or 0) / (1024 * 1024),
        )
    return derived


# Clamp on the wall-timeout INPUT to the CPU-budget derivation, not on
# the walls RAPTOR derives (those carry their own caps upstream): a
# corrupted or hostile timeout value reaching a spawn site must not
# mint an effectively unlimited RLIMIT_CPU. 24 h comfortably clears
# every derivable Joern wall (build cap 4 h, import cap 3 h, pre-sweep
# cap 2 h) and any plausible explicit override; smaller would silently
# re-tighten a deliberate very-large operator wall back into the
# SIGXCPU-before-wall failure this helper exists to remove.
_SANDBOX_WALL_INPUT_CAP_S = 86400
# Headroom above wall x CPUs for JVM boot/teardown accounting slop.
_SANDBOX_CPU_HEADROOM_S = 300


def sandbox_cpu_limits(wall_timeout_s: int) -> dict[str, int]:
    """Sandbox ``limits`` override sizing RLIMIT_CPU to a wall timeout.

    The JVM is multi-threaded and RLIMIT_CPU counts CPU time summed
    across every thread, so a spawn whose wall budget exceeds
    ``standing_cpu / n_cpus`` can be SIGXCPU-killed long before its
    wall expires (observed: a kernel-scale joern-parse rebuild died on
    the sandbox's standing ~1 h CPU budget while its derived wall
    allowed 4 h). The wall timeout is the run's actual compute bound —
    the subprocess layer kills at wall regardless — so RLIMIT_CPU here
    is a backstop for wall-enforcement failure (an orphaned JVM), and
    it must sit ABOVE wall x available CPUs to never fire first.

    Floor: the standing sandbox budget
    (:func:`core.sandbox.preexec.standing_cpu_seconds`) — a derived
    override only ever RAISES the standing posture. A standing 0
    (operator-configured "no CPU rlimit") returns ``{}``: nothing to
    raise, and the override must not resurrect a disabled limit.
    """
    wall = max(0, min(int(wall_timeout_s), _SANDBOX_WALL_INPUT_CAP_S))
    try:
        from core.sandbox.preexec import standing_cpu_seconds
        standing = standing_cpu_seconds()
    except Exception:  # noqa: BLE001 — the sandbox layer may be absent
        # (unsandboxed opt-out path); mirror its documented default.
        standing = 3600
    if standing == 0:
        return {}
    try:
        cpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        cpus = os.cpu_count() or 1
    cpus = max(1, cpus)
    return {
        "cpu_seconds": max(
            standing, wall * cpus + _SANDBOX_CPU_HEADROOM_S,
        ),
    }
