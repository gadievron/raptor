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

from dataclasses import dataclass


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
            derive_joern_cpg_timeout_s,
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

        import_timeout_s = overrides.get("import_timeout_s")
        if import_timeout_s is None:
            import_timeout_s = getattr(t, "joern_import_timeout_s", 900)

        query_timeout_s = overrides.get("query_timeout_s")
        if query_timeout_s is None:
            query_timeout_s = t.joern_query_timeout_s

        return cls(
            heap_mb=heap_mb,
            cpg_timeout_s=cpg_timeout_s,
            import_timeout_s=import_timeout_s,
            query_timeout_s=query_timeout_s,
            cpg_timeout_auto=cpg_timeout_auto,
            heap_is_derived=heap_is_derived,
        )
