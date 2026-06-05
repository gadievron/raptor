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

Install advice (PM-aware): each missing-tool warning is enriched
with an install-hint continuation line via
``packages.describe.package_manager.format_install_advice``. The
historic "no hints" stance was driven by the wrong-by-construction
``apt install`` everywhere — install_advice fixes that: per-tool
policy dispatches to the right shape for each install kind
(distro PM with PM-correct package name, pipx for CLI tools,
static URL for codeql, "Linux-only" for rr off Linux). The hints
are correct or honestly absent — they're never patronising.

Deliberately NOT in scope:

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


def _build_install_hints(missing_tool_names: List[str]) -> dict:
    """For each missing TOOL_DEPS name, look up its binary and
    format install advice via packages.describe.package_manager.

    Returns ``{binary_name: hint_line}``. Lookup keys are the
    ``binary`` field from RaptorConfig.TOOL_DEPS, not the
    user-facing tool name — warnings include the binary name
    (e.g. ``spatch not found`` for coccinelle).
    """
    try:
        from core.config import RaptorConfig
        from packages.describe.package_manager import format_install_advice
    except Exception:  # noqa: BLE001
        return {}
    out: dict = {}
    for name in missing_tool_names:
        dep = RaptorConfig.TOOL_DEPS.get(name)
        if not dep:
            continue
        binary = dep.get("binary")
        if not binary:
            continue
        try:
            out[binary] = format_install_advice(binary)
        except Exception:  # noqa: BLE001
            continue
    return out


def _hint_for_warning(warning: str, install_hints: dict) -> Optional[str]:
    """Match a warning string to one of the install hints. The
    warnings produced by check_tools look like ``"… <binary>
    not found"`` (single-tool case) or ``"… (afl-fuzz or
    semgrep)"`` (group case). Match against the binary names
    in ``install_hints``; first match wins.
    """
    for binary, hint in install_hints.items():
        # Bounded by spaces / parentheses so a binary like "go"
        # doesn't accidentally match inside "/agentic".
        for needle in (f" {binary} ", f"({binary} ", f" {binary})", f" {binary}.", f"{binary} not found"):
            if needle in warning:
                return hint
    return None


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
    # Build a lookup of "binary name → install advice" for every
    # tool that's missing so we can enrich the upstream warnings.
    # Pre-fix /doctor printed "rr not found" with no hint — the
    # historic concern was hints being patronising/wrong; with PM-
    # aware advice they're correct-by-construction (or honest
    # about Linux-only when off Linux).
    install_hints = _build_install_hints(missing)
    for w in tool_warnings:
        # Enrich the warning with an install hint when the
        # missing tool's binary name appears in the warning. The
        # warning strings look like "/crash-analysis limited — rr
        # not found"; match by " <name> not found" so a future
        # warning shape can extend without re-coding the
        # detection.
        warnings.append(w)
        hint = _hint_for_warning(w, install_hints)
        if hint:
            # Tuple-marker: the renderer below routes (hint, str)
            # tuples to a continuation prefix instead of the
            # warning bullet. Parallel structure rather than an
            # in-band sentinel — eliminates the collision surface
            # if a future warning string starts with an attacker-
            # influenced LLM error message.
            warnings.append(("hint", hint))

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

    from core.config import RaptorConfig

    out: List[str] = [
        "RAPTOR doctor",
        "=============",
        f"version: {RaptorConfig.effective_version()}",
    ]

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
            # Tuple-marked continuation lines (currently just
            # install hints) get a continuation prefix instead of
            # the warning bullet, so the operator reads them as a
            # follow-up to the prior warning.
            if isinstance(w, tuple) and len(w) == 2 and w[0] == "hint":
                out.append(
                    f"      hint: {escape_nonprintable(w[1])}"
                )
            else:
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
    # Continuation entries (install-hint tuples) don't count as
    # warnings — only the real warning bullets do.
    real_warnings = sum(
        1 for w in warnings
        if not (isinstance(w, tuple) and w and w[0] == "hint")
    )
    out.append(
        f"Summary: {len(failures)} failure(s), "
        f"{real_warnings} warning(s), {len(passes)} passed."
    )

    return "\n".join(out), len(failures), real_warnings


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
        elif a in ("--help", "-h"):
            # `--help` is a help request, not a usage error: print usage to
            # stdout and exit 0, matching every other raptor.py mode. Pre-fix
            # it fell into the else branch (usage to stderr, exit 2), making
            # `doctor --help` the one mode where the documented help flag
            # looked like a failure.
            print(_USAGE)
            return 0
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
