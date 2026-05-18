"""``raptor doctor`` — on-demand status report.

Runs the same checks the SessionStart banner runs (``check_tools``,
``check_llm``, ``check_env``, ``check_lang``, ``check_active_project``
in :mod:`core.startup.init`), but renders them for an operator who
explicitly typed ``raptor doctor`` because something feels off.

Differences from the banner:

  * No logo, no quote, no banner-layout — failures first, then
    warnings, then a one-line summary of what passed.
  * Does NOT write ``.startup-output`` — the SessionStart hook owns
    that file. Doctor only prints to stdout.
  * Non-zero exit on real failure (``--strict`` also fails on
    warnings) so CI / shell scripts can gate on a clean state.

Deliberately NOT in scope:

  * Install advice for missing binaries. RAPTOR's audience is
    technical operators — saying ``apt install rr`` is patronising
    and often wrong (rr is Linux-only, the operator may build from
    source for newer kernels, etc.). Doctor reports what's missing
    and which features degrade; the operator picks how to install.
  * Performance benchmarks, network reachability beyond what
    ``check_llm`` already does, test runs.

The doctor-command concept was signposted earlier by:
  * gadievron/raptor#57 (splinters-io) — first surfaced the
    operator-facing self-check shape in an aborted Frida-
    integration PR.
  * gadievron/raptor#486 (hinotori-agent) — second proposal,
    revisited the same idea.

This implementation wraps the existing ``core.startup.init``
checks rather than duplicate them, so a new check or tool added
to ``RaptorConfig.TOOL_DEPS`` lights up in both banner and
doctor without per-site updates.
"""

from __future__ import annotations

import logging
import sys
from typing import Iterable, List, Optional, Tuple

from core.security.log_sanitisation import escape_nonprintable


_USAGE = (
    "usage: raptor doctor [--strict] [--verbose]\n"
    "  --strict     non-zero exit on warnings too (CI gate)\n"
    "  --verbose    include passing checks in the output\n"
)


def _gather() -> Tuple[
    List[Tuple[str, bool]],  # tool_results
    List[str],               # tool_warnings
    List[str],               # llm_lines
    List[str],               # llm_warnings
    List[str],               # env_parts
    List[str],               # env_warnings
    Optional[str],           # lang_line
    Optional[str],           # project_line
]:
    """Run every check and return the same shape ``init.main`` builds.

    Silences logging like ``init.main`` does — these checks are
    noisy at WARNING level (LLM key validation, sandbox probes).
    """
    from .init import (
        check_active_project, check_env, check_lang, check_llm,
        check_tools,
    )

    logging.disable(logging.WARNING)
    try:
        tool_results, tool_warnings, unavailable = check_tools()
        llm_lines, llm_warnings = check_llm()
        env_parts, env_warnings = check_env(unavailable)
        lang_line = check_lang()
        project_line = check_active_project()
    finally:
        logging.disable(logging.NOTSET)

    return (
        tool_results, tool_warnings,
        llm_lines, llm_warnings,
        env_parts, env_warnings,
        lang_line, project_line,
    )


def _render(
    tool_results: Iterable[Tuple[str, bool]],
    tool_warnings: Iterable[str],
    llm_lines: Iterable[str],
    llm_warnings: Iterable[str],
    env_parts: Iterable[str],
    env_warnings: Iterable[str],
    lang_line: Optional[str],
    project_line: Optional[str],
    *,
    verbose: bool,
) -> Tuple[str, int, int]:
    """Render the doctor output. Returns (text, n_failures, n_warnings).

    Failure classification:
      * ``check_env`` mixes pass/fail signals — entries containing
        the ``✗`` glyph are failures. The rest are facts (``disk 16
        GB free``) or passes (``out/ ✓``).
      * Missing tools become warnings unless the tool is in a
        required group (``check_tools`` already classifies
        severity in ``tool_warnings``; we surface those as-is).
      * Anything in a ``*_warnings`` list is a warning.
    """
    failures: List[str] = []
    warnings: List[str] = []
    passes: List[str] = []

    # Tools — single line summary of present/missing, then individual
    # warnings (which already carry severity).
    missing = [name for name, ok in tool_results if not ok]
    present = [name for name, ok in tool_results if ok]
    if present:
        passes.append(f"tools present: {', '.join(sorted(present))}")
    if missing:
        # The warnings list carries the feature-impact phrasing
        # (``rr not found — /crash-analysis limited``) so we don't
        # need to re-format from tool_results here. tool_warnings
        # also carries group-level entries (e.g. "no scanner").
        pass
    for w in tool_warnings:
        warnings.append(w)

    # LLM — banner's ``check_llm`` is informational; entries describe
    # which provider is configured. Warnings stand alone.
    for line in llm_lines:
        clean = line.strip()
        if clean:
            passes.append(clean)
    for w in llm_warnings:
        warnings.append(w)

    # Env — mixed: ``out/ ✗`` is a failure, ``disk 16 GB free`` is a
    # pass, ``RAPTOR_DIR not set …`` from the new check appears in
    # env_warnings.
    for part in env_parts:
        clean = part.strip()
        if not clean:
            continue
        if "✗" in clean:
            failures.append(clean)
        else:
            passes.append(clean)
    for w in env_warnings:
        warnings.append(w)

    # Language support — single informational line.
    if lang_line:
        passes.append(lang_line.strip())

    # Active project — informational.
    if project_line:
        passes.append(project_line.strip())

    out: List[str] = ["RAPTOR doctor", "============="]

    # Defence in depth: although every current producer of these
    # strings is RAPTOR-internal (check_tools, check_llm, check_env),
    # a future producer could surface attacker-influenced text — a
    # tool warning derived from subprocess stderr, an LLM-provider
    # error string, a project name read from disk. Run every
    # operator-visible line through ``escape_nonprintable`` so raw
    # ESC bytes / C1 controls never reach the terminal.
    if failures:
        out.append("")
        out.append("FAILURES:")
        for f in failures:
            out.append(f"  ✗ {escape_nonprintable(f)}")

    if warnings:
        out.append("")
        out.append("WARNINGS:")
        for w in warnings:
            out.append(f"  ! {escape_nonprintable(w)}")

    if verbose and passes:
        out.append("")
        out.append("PASSED:")
        for p in passes:
            out.append(f"  ✓ {escape_nonprintable(p)}")
    elif passes and not failures and not warnings:
        # Compact "all good" when there's nothing to act on.
        out.append("")
        out.append(f"All {len(passes)} check(s) passed. "
                   "(--verbose for detail.)")

    out.append("")
    out.append(
        f"Summary: {len(failures)} failure(s), "
        f"{len(warnings)} warning(s), {len(passes)} passed."
    )

    return "\n".join(out), len(failures), len(warnings)


def main(argv: Optional[List[str]] = None) -> int:
    """Run the doctor.

    Exit codes:
      * 0 — no failures (and no warnings under ``--strict``)
      * 1 — at least one failure (or, under ``--strict``, any warning)
      * 2 — usage error
    """
    argv = list(argv or [])
    strict = False
    verbose = False
    while argv:
        a = argv.pop(0)
        if a == "--strict":
            strict = True
        elif a in ("--verbose", "-v"):
            verbose = True
        else:
            print(_USAGE, file=sys.stderr)
            return 2

    try:
        gathered = _gather()
    except Exception as e:  # noqa: BLE001 — never crash a doctor
        # Exception messages can be tainted (e.g. subprocess stderr
        # rolled into a RuntimeError); escape before emitting.
        safe_msg = escape_nonprintable(f"{type(e).__name__}: {e}")
        print(
            f"RAPTOR doctor\n=============\n\n"
            f"FAILURES:\n  ✗ doctor internal error: {safe_msg}\n\n"
            f"Summary: 1 failure(s), 0 warning(s), 0 passed.",
        )
        return 1

    text, n_fail, n_warn = _render(*gathered, verbose=verbose)
    print(text)
    if n_fail:
        return 1
    if strict and n_warn:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
