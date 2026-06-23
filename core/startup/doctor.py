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
from collections.abc import Iterable

from core.security.log_sanitisation import escape_nonprintable

_USAGE = (
    "usage: raptor doctor [--strict] [--verbose]\n"
    "       raptor doctor --codex-login\n"
    "       raptor doctor --codex-device-login\n"
    "  --strict              non-zero exit on warnings too (CI gate)\n"
    "  --verbose             include passing checks in the output\n"
    "  --codex-login         delegate browser login to `codex login`\n"
    "  --codex-device-login  delegate headless login to `codex login --device-auth`\n"
)


def _build_install_hints(missing_tool_names: list[str]) -> dict:
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
            # Python-module dependency — a library, not a CLI, so the
            # advice is a plain pip install of the dep's declared PyPI
            # name (module and distribution names differ, e.g.
            # z3 vs z3-solver), not the pipx/PM registry.
            if dep.get("module") and dep.get("pip"):
                out[name] = f"pip install {dep['pip']}"
            continue
        try:
            out[binary] = format_install_advice(binary)
        except Exception:
            logging.getLogger(__name__).debug(
                "install-advice lookup failed for %s", binary,
                exc_info=True,
            )
            continue
    return out


def _hint_for_warning(warning: str, install_hints: dict) -> str | None:
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


def _module_dep_warnings() -> list[str]:
    """Import-verify the Python-module TOOL_DEPS in a subprocess.

    ``check_tools`` uses ``find_spec`` (locate without importing), so
    a wheel whose native extension is broken — Python upgraded under
    the venv, half-completed install — passes the presence check and
    then crashes the first /audit or /codeql run that imports it.
    Import in a THROWAWAY subprocess: a segfaulting extension module
    must not take doctor down with it. Never raises.

    Probe isolation: ``python -c`` puts the CURRENT DIRECTORY at
    ``sys.path[0]``, so a planted ``z3.py`` / ``z3/`` in whatever
    directory doctor happened to be invoked from would execute
    attacker code in this (unsandboxed) process's child. The probe
    therefore runs with ``-I`` (isolated mode: no cwd/script dir on
    sys.path, PYTHON* env ignored, no user site), from a fresh empty
    temp directory, with the sanitised env.
    """
    import subprocess
    import tempfile

    out: list[str] = []
    try:
        import importlib.util

        from core.config import RaptorConfig
    except Exception:  # noqa: BLE001
        return out
    try:
        safe_env = RaptorConfig.get_safe_env()
    except Exception:  # noqa: BLE001
        return out
    for name in sorted(RaptorConfig.TOOL_DEPS):
        dep = RaptorConfig.TOOL_DEPS[name]
        module = dep.get("module")
        if not module:
            continue
        try:
            if importlib.util.find_spec(module) is None:
                continue  # absent — check_tools already covers it
        except Exception:
            logging.getLogger(__name__).debug(
                "find_spec(%s) failed", module, exc_info=True,
            )
            continue
        try:
            with tempfile.TemporaryDirectory(
                prefix="raptor-doctor-probe-",
            ) as neutral_cwd:
                proc = subprocess.run(
                    [sys.executable, "-I", "-c",
                     f"import importlib; importlib.import_module({module!r})"],
                    capture_output=True, text=True, check=False, timeout=60,
                    cwd=neutral_cwd, env=safe_env,
                )
        except (OSError, subprocess.SubprocessError):
            continue  # probe failure ≠ broken module; stay quiet
        if proc.returncode != 0:
            pip_name = dep.get("pip", module)
            out.append(
                f"{name} is installed but failed to import — "
                f"{dep['affects']} will fail at use time "
                f"(pip install --force-reinstall {pip_name})"
            )
    return out


# Bounded-scan caps for the imported-annotation advisory sweep. Doctor
# is on-demand, but a project output dir can hold arbitrarily many runs
# and notes — the sweep reads at most this much before reporting what
# it has.
_ADVISORY_MAX_PROJECTS = 50
_ADVISORY_MAX_RUN_DIRS = 100
_ADVISORY_MAX_NOTES = 500

# The registry ``target`` value ``import_project`` records when the
# archive's embedded metadata omitted a target — the only import
# breadcrumb the registry carried before the persisted import marker
# existed. Presence is a strong import-origin hint; absence proves
# nothing (the archive controls its own embedded target).
_IMPORTED_TARGET_SENTINEL = "(imported)"


def _human_grade_note_count(output_dir) -> int:
    """Count human-grade annotations under *output_dir*'s canonical
    annotation locations (``<out>/annotations`` plus each top-level
    run dir's ``annotations/``), skipping any run dir that carries the
    persisted import marker (those trees were demoted at import time).

    Bounded by ``_ADVISORY_MAX_RUN_DIRS`` / ``_ADVISORY_MAX_NOTES`` —
    an under-count on a pathological layout is acceptable for an
    advisory.
    """
    from pathlib import Path

    from core.annotations.provenance import is_human_grade
    from core.annotations.storage import (
        annotation_file_mtime,
        iter_all_annotations,
    )
    from core.project.findings_utils import IMPORTED_RUN_MARKER_FILE

    output_dir = Path(output_dir)
    bases = []
    root_base = output_dir / "annotations"
    if root_base.is_dir() and not root_base.is_symlink():
        bases.append(root_base)
    from core.project.project import GENERATED_PROJECT_DIRS
    scanned_dirs = 0
    for child in sorted(output_dir.iterdir()):
        if scanned_dirs >= _ADVISORY_MAX_RUN_DIRS:
            break
        if child.is_symlink() or not child.is_dir():
            continue
        if (child.name.startswith((".", "_"))
                or child.name == "annotations"
                or child.name in GENERATED_PROJECT_DIRS):
            continue
        scanned_dirs += 1
        if (child / IMPORTED_RUN_MARKER_FILE).is_file():
            # Post-hardening imported run: every restored note was
            # demoted to provenance=imported at import time.
            continue
        ann_base = child / "annotations"
        if ann_base.is_dir() and not ann_base.is_symlink():
            bases.append(ann_base)

    count = 0
    seen = 0
    for base in bases:
        for ann in iter_all_annotations(base):
            seen += 1
            if seen > _ADVISORY_MAX_NOTES:
                return count
            mtime = annotation_file_mtime(base, ann.file)
            if is_human_grade(ann.metadata, note_mtime=mtime):
                count += 1
    return count


def _imported_annotation_advisories(projects_dir=None) -> list[str]:
    """INFO-grade advisory sweep: human-grade annotations that may
    predate the import-demotion hardening.

    Projects imported BEFORE the hardening landed had their archive's
    annotations restored byte-faithfully — a forged human-grade stamp
    (``source=human`` + interactive-TTY provenance) in such an import
    reads as operator authority forever, and those imports carry no
    persisted ``.raptor-imported.json`` marker, so they cannot be
    retro-identified from the artifacts alone. A blanket migration
    would wrongly demote legitimate local operator notes, so this is
    an advisory, never a fix:

      * Projects whose registry ``target`` is the import sentinel
        (see ``_IMPORTED_TARGET_SENTINEL`` — the one pre-marker
        registry breadcrumb import ever recorded) AND that contain
        human-grade notes in unmarked trees get a targeted advisory.
      * Every other project containing such notes is listed
        generically: the notes cannot be machine-attributed to a
        local vs imported origin; operators who ever imported
        archives from untrusted sources should review them.

    Cheap (bounded scan), skippable (empty list when no projects are
    registered), and advisory-only — the caller renders these outside
    the failure/warning counts so they never affect the exit code.
    """
    try:
        from pathlib import Path

        from core.project.findings_utils import IMPORTED_RUN_MARKER_FILE
        from core.project.project import ProjectManager
    except Exception:  # noqa: BLE001 — advisory sweep, never fatal
        return []
    try:
        mgr = ProjectManager(projects_dir=projects_dir)
        projects = mgr.list_projects()
    except Exception:  # noqa: BLE001
        return []
    if not projects:
        return []

    targeted: list[tuple[str, int]] = []
    generic: list[str] = []
    for project in projects[:_ADVISORY_MAX_PROJECTS]:
        try:
            out_dir = Path(project.output_dir)
            if not out_dir.is_dir():
                continue
            if (out_dir / IMPORTED_RUN_MARKER_FILE).is_file():
                # Post-hardening import: restored notes were demoted
                # at import; human-grade notes here are local writes.
                continue
            count = _human_grade_note_count(out_dir)
        except Exception:  # noqa: BLE001 — one bad project stays quiet
            logging.getLogger(__name__).debug(
                "imported-annotation sweep failed for project %s",
                project.name, exc_info=True,
            )
            continue
        if not count:
            continue
        if project.target == _IMPORTED_TARGET_SENTINEL:
            targeted.append((project.name, count))
        else:
            generic.append(project.name)

    lines: list[str] = []
    for name, count in targeted:
        lines.append(
            f"project '{name}' was imported (registry target "
            f"'(imported)') and carries {count} human-grade "
            f"annotation(s) with no import marker — notes restored "
            f"before the import-demotion hardening read with operator "
            f"authority; review with /annotate ls, then re-stamp "
            f"(/annotate edit) or remove any you don't recognise"
        )
    if generic:
        names = ", ".join(f"'{n}'" for n in generic)
        lines.append(
            f"human-grade annotations found in project(s) {names} — "
            f"notes predating the import-demotion hardening cannot be "
            f"machine-attributed to a local vs imported origin; if "
            f"you ever imported project archives from untrusted "
            f"sources, review them with /annotate ls, then re-stamp "
            f"(/annotate edit) or remove any you don't recognise"
        )
    return lines


def _gather() -> tuple[
    list[tuple[str, bool]],  # tool_results
    list[str],               # tool_warnings
    list[str],               # llm_lines
    list[str],               # llm_warnings
    list[str],               # env_parts
    list[str],               # env_warnings
    str | None,           # lang_line
    str | None,           # project_line
    list[str],               # advisories
]:
    """Run every check and return the same shape ``init.main`` builds.

    Silences logging like ``init.main`` does — these checks are
    noisy at WARNING level (LLM key validation, sandbox probes).
    """
    from .init import (
        check_active_project,
        check_env,
        check_lang,
        check_llm,
        check_tools,
    )

    logging.disable(logging.WARNING)
    try:
        tool_results, tool_warnings, unavailable = check_tools()
        # Doctor-only depth: verify Python-module deps actually
        # import. The banner's find_spec probe deliberately does not
        # import (startup speed; a broken wheel can't crash the
        # banner) — the cost is that a present-but-broken wheel shows
        # ✓ and crashes at first use. Doctor is on-demand and allowed
        # to spend a subprocess to catch exactly that.
        tool_warnings = list(tool_warnings) + _module_dep_warnings()
        llm_lines, llm_warnings = check_llm()
        env_parts, env_warnings = check_env(unavailable)
        lang_line, lang_warnings = check_lang()
        env_warnings = list(env_warnings) + list(lang_warnings)
        # Doctor-only depth (same rationale shape as the module-import
        # verification above): the AWS IMDS / proxy / credential-chain
        # interaction matrix. Advisory environment-shape lines, gated
        # on AWS use being plausible. Deliberately not in the banner —
        # session start should not editorialise about credential
        # topology on every launch, but an operator who typed
        # ``raptor doctor`` is asking exactly that question.
        from .aws_imds import aws_imds_advisories
        env_warnings += aws_imds_advisories()
        project_line = check_active_project()
        # Doctor-only depth: imported-annotation provenance sweep.
        # Advisory severity — rendered outside the failure/warning
        # counts, never affects the exit code (even under --strict).
        advisories = _imported_annotation_advisories()
    finally:
        logging.disable(logging.NOTSET)

    return (
        tool_results, tool_warnings,
        llm_lines, llm_warnings,
        env_parts, env_warnings,
        lang_line, project_line,
        advisories,
    )


def _render(
    tool_results: Iterable[tuple[str, bool]],
    tool_warnings: Iterable[str],
    llm_lines: Iterable[str],
    llm_warnings: Iterable[str],
    env_parts: Iterable[str],
    env_warnings: Iterable[str],
    lang_line: str | None,
    project_line: str | None,
    advisories: Iterable[str] = (),
    *,
    verbose: bool,
) -> tuple[str, int, int]:
    """Render the doctor output. Returns (text, n_failures, n_warnings).

    ``advisories`` are INFO-grade lines rendered under an ADVISORIES
    heading — counted in neither failures nor warnings, so they never
    change the exit code (not even under ``--strict``).

    Failure classification:
      * ``check_env`` mixes pass/fail signals — entries containing
        the ``✗`` glyph are failures. The rest are facts (``disk 16
        GB free``) or passes (``out/ ✓``).
      * Missing tools become warnings unless the tool is in a
        required group (``check_tools`` already classifies
        severity in ``tool_warnings``; we surface those as-is).
      * Anything in a ``*_warnings`` list is a warning.
    """
    failures: list[str] = []
    warnings: list[str] = []
    passes: list[str] = []

    # Tools — single line summary of present/missing, then individual
    # warnings (which already carry severity).
    missing = [name for name, ok in tool_results if not ok]
    present = [name for name, ok in tool_results if ok]
    if present:
        passes.append(f"tools present: {', '.join(sorted(present))}")
    # Missing tools need no re-formatting here: the warnings list
    # carries the feature-impact phrasing (``/crash-analysis limited
    # — rr not found``) and the group-level entries ("no scanner").
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
    warnings.extend(llm_warnings)

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
    warnings.extend(env_warnings)

    # Language support — single informational line. A ✗ lang line
    # (no grammars) must NOT be listed under PASSED; the degradation
    # warning check_lang emits alongside it covers the signal.
    if lang_line and "✗" not in lang_line:
        passes.append(lang_line.strip())

    # Active project — informational.
    if project_line:
        passes.append(project_line.strip())

    from core.config import RaptorConfig

    out: list[str] = [
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
        out.extend(f"  ✗ {escape_nonprintable(f)}" for f in failures)

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

    advisory_lines = [a for a in advisories if a]
    if advisory_lines:
        out.append("")
        out.append("ADVISORIES:")
        for a in advisory_lines:
            out.append(f"  i {escape_nonprintable(a)}")

    if verbose and passes:
        out.append("")
        out.append("PASSED:")
        out.extend(f"  ✓ {escape_nonprintable(p)}" for p in passes)
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


def main(argv: list[str] | None = None) -> int:
    """Run the doctor.

    Exit codes:
      * 0 — no failures (and no warnings under ``--strict``)
      * 1 — at least one failure (or, under ``--strict``, any warning)
      * 2 — usage error
    """
    argv = list(argv or [])
    strict = False
    verbose = False
    codex_login = False
    codex_device_login = False
    while argv:
        a = argv.pop(0)
        if a == "--strict":
            strict = True
        elif a in ("--verbose", "-v"):
            verbose = True
        elif a == "--codex-login":
            codex_login = True
        elif a == "--codex-device-login":
            codex_device_login = True
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

    if codex_login and codex_device_login:
        print(_USAGE, file=sys.stderr)
        return 2
    if strict and (codex_login or codex_device_login):
        print(_USAGE, file=sys.stderr)
        return 2
    if codex_login or codex_device_login:
        from .codex import run_codex_login
        return run_codex_login(device_auth=codex_device_login)

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
