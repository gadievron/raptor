"""Per-run CodeQL resource controls.

Centralises the ``-j`` / ``-M`` / ``--max-disk-cache`` flag set that every
CodeQL invocation across RAPTOR needs to plumb through.  Previously
each call site constructed these strings inline (3 sites in
``query_runner.py`` alone, plus the dataflow corpus walker), with the
subtle bug that the trust-witness walker had been omitting them
entirely — meaning ``codeql database create`` ran with the upstream
default ``-j 1`` and serialised the secondary HTML/JS extractor phase
on Go web repos.  That timed out the per-pair build budget on the
overnight v3 walk (12/16 build_fails stuck in this phase).

The defaults are sourced from RAPTOR's central tuning config
(:mod:`core.tuning`, backed by ``tuning.json``) via :meth:`from_tuning`,
so changing ``codeql_threads`` / ``codeql_ram_mb`` in one place
propagates everywhere.  Operator CLI flags override per-run.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class CodeQLTunables:
    """CodeQL resource flags appended to ``database create`` /
    ``database analyze`` commands.

      * ``threads``           — codeql ``-j``.  ``0`` = all cores.
      * ``ram_mb``            — codeql ``-M`` (MB).  ``None`` skips the
                                 flag and lets codeql autodetect.
      * ``max_disk_cache_mb`` — codeql ``--max-disk-cache`` (MB).
                                 ``None`` = codeql's unbounded default.
                                 Only valid on ``database create``; the
                                 analyze path rejects it as unknown.
    """
    threads: int = 0
    ram_mb: Optional[int] = None
    max_disk_cache_mb: Optional[int] = None

    @classmethod
    def from_tuning(cls, *, overrides: Optional[dict] = None) -> "CodeQLTunables":
        """Build from RAPTOR's central tuning config.

        ``overrides`` is an operator-CLI-arg-shaped dict; any non-None
        value overrides the tuning-resolved default for that field.
        Recognised keys: ``threads``, ``ram_mb``, ``max_disk_cache_mb``.
        """
        # Lazy import: callers that build CodeQLTunables() directly with
        # explicit values (tests, small one-offs) shouldn't pay the
        # tuning module's import cost (json + hardware detect).
        from core.tuning import get_tuning
        t = get_tuning()
        overrides = overrides or {}
        threads = overrides.get("threads")
        if threads is None:
            threads = t.codeql_threads
        ram_mb = overrides.get("ram_mb")
        if ram_mb is None:
            # 0 in tuning means "unset" — codeql autodetect.
            ram_mb = t.codeql_ram_mb if t.codeql_ram_mb > 0 else None
        max_disk_cache_mb = overrides.get("max_disk_cache_mb")
        if max_disk_cache_mb is None:
            # 0 in tuning means "leave codeql's unbounded default".
            v = t.codeql_max_disk_cache_mb
            max_disk_cache_mb = v if v > 0 else None
        return cls(threads=threads, ram_mb=ram_mb,
                   max_disk_cache_mb=max_disk_cache_mb)

    def append_to(self, cmd: list, *, include_disk_cache: bool = True) -> None:
        """Append the relevant CodeQL flags onto ``cmd`` in place.

        ``include_disk_cache`` controls whether ``--max-disk-cache`` is
        appended; only ``database create`` accepts that flag.  The
        analyze path passes ``False`` so it doesn't error on an unknown
        option.
        """
        cmd.extend(["-j", str(self.threads)])
        if self.ram_mb is not None:
            cmd.extend(["-M", str(self.ram_mb)])
        if include_disk_cache and self.max_disk_cache_mb is not None:
            cmd.append(f"--max-disk-cache={self.max_disk_cache_mb}")
