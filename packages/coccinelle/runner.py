"""Coccinelle (spatch) runner — invoke rules and parse structured output.

spatch 1.3 has no --json flag. We use Python scripting blocks injected into
rules to emit structured COCCIRESULT lines on stdout that we parse here.

For rules that already contain their own Python scripting (human-authored
static rules), we parse their output directly. For rules without scripting,
we wrap them with a reporting harness.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional

from core.config import RaptorConfig

from .models import SpatchMatch, SpatchResult

RESULT_PREFIX = "COCCIRESULT:"
_SPATCH_BIN = "spatch"
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")

# Resolve `spatch` ONCE per process via shutil.which and cache the
# absolute path. Pre-fix every subprocess call passed the bare
# `"spatch"` and the kernel did a fresh PATH lookup at exec time.
# Two pain points the cache closes:
#   * Performance: a multi-rule scan run can fire dozens of
#     subprocess.run / Popen invocations; each one re-scans every
#     PATH entry to find spatch.
#   * Race: between `is_available()` (which probes PATH via
#     `shutil.which`) and the subsequent subprocess.run that
#     re-resolves PATH internally, an attacker who can rewrite PATH
#     (a long-running RAPTOR session that picks up a new env var
#     mid-run, an upstream tool that mutates os.environ) could
#     swap out spatch. Cache locks in the resolved path discovered
#     at first probe.
_resolved_spatch: Optional[str] = None
_spatch_resolved: bool = False  # True once we've cached (None or path).
def _spatch_path() -> Optional[str]:
    global _resolved_spatch, _spatch_resolved
    if not _spatch_resolved:
        _resolved_spatch = shutil.which(_SPATCH_BIN)
        _spatch_resolved = True
    return _resolved_spatch


def reset_spatch_path_cache() -> None:
    """Clear the cached spatch path. Call between tests that patch
    `shutil.which` so the next probe re-resolves PATH.
    """
    global _resolved_spatch, _spatch_resolved
    _resolved_spatch = None
    _spatch_resolved = False


def is_available() -> bool:
    """Check whether spatch is on PATH."""
    # Always re-probe in is_available so test mocks of shutil.which
    # work as expected. The cache only locks in for command builds
    # (where the race-protection matters); is_available is a
    # cheap probe.
    return shutil.which(_SPATCH_BIN) is not None


def version() -> Optional[str]:
    """Return the spatch version string, or None if unavailable."""
    if not is_available():
        return None
    try:
        proc = subprocess.run(
            [_spatch_path() or _SPATCH_BIN, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        for line in proc.stdout.splitlines():
            if line.startswith("spatch version"):
                return line.split("spatch version", 1)[1].strip()
        return proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else None
    except (subprocess.TimeoutExpired, OSError):
        return None


def run_rule(
    target: Path,
    rule: Path,
    *,
    include_dirs: Optional[List[Path]] = None,
    no_includes: bool = False,
    timeout: int = 300,
    env: Optional[Dict[str, str]] = None,
    defines: Optional[Dict[str, str]] = None,
    subprocess_runner=None,
) -> SpatchResult:
    """Run a single Coccinelle rule against a target.

    Args:
        target: File or directory to scan.
        rule: Path to .cocci rule file.
        include_dirs: Extra -I directories for header resolution.
        no_includes: Pass --no-includes (recommended for untrusted targets).
        timeout: Per-rule timeout in seconds.
        env: Subprocess environment (use get_safe_env() for untrusted targets).
        defines: Virtual identifier bindings passed as -D key=value.
        subprocess_runner: Optional callable replacing subprocess.run. Must
            accept the same kwargs (capture_output, text, timeout, env,
            input) and return an object with returncode/stdout/stderr.
            Defaults to subprocess.run. Used by callers that need to
            engage a sandbox (e.g. core.sandbox.run) without reimplementing
            the spatch invocation logic.

    Returns:
        SpatchResult with matches parsed from COCCIRESULT lines.
    """
    rule = Path(rule)
    target = Path(target)
    rule_name = rule.stem

    if not is_available():
        return SpatchResult(
            rule=rule_name, rule_path=str(rule),
            errors=["spatch is not installed (coccinelle package not found on PATH)"],
            returncode=-1,
        )

    if not rule.exists():
        return SpatchResult(
            rule=rule_name, rule_path=str(rule),
            errors=[f"Rule file not found: {rule}"],
            returncode=-1,
        )

    rule_text = rule.read_text()
    needs_harness = RESULT_PREFIX not in rule_text and "script:python" not in rule_text

    # If the rule needs harness injection, the modified text has to
    # reach spatch via a real file path. Pre-fix this routed via
    # ``--sp-file -`` (stdin), but spatch 1.3 (the build on every
    # host we ship to) doesn't accept ``-`` / ``--sp-file=-`` /
    # ``--sp-file /dev/stdin`` — each errors with either
    # ``Sys_error("-: No such file or directory")`` or "unexpected
    # code before the first rule". The only reliable invocation is
    # a real path. Write the harnessed text to a tempfile and pass
    # its path; cleanup in ``finally`` covers timeout / error paths.
    harnessed_rule_path: Optional[Path] = None
    if needs_harness:
        injected = _inject_harness(rule_text, rule_name)
        if injected != rule_text:
            # Tempfile in the system tempdir — works under the
            # default sandbox allowlist (``/tmp`` is reachable).
            # delete=False so we control cleanup; without it the
            # NamedTemporaryFile context manager would unlink on
            # exit before spatch could read it through the
            # subprocess_runner.
            fd, tmp_name = tempfile.mkstemp(suffix=".cocci", prefix="raptor-cocci-")
            try:
                with os.fdopen(fd, "w") as fh:
                    fh.write(injected)
                harnessed_rule_path = Path(tmp_name)
            except OSError:
                # If we can't write, fall back to the un-harnessed
                # rule path. The caller still gets spatch results,
                # just without our structured COCCIRESULT lines —
                # which is the same UX as a multi-rule file
                # (handled below in _inject_harness's existing
                # "return rule_text unchanged" path).
                try:
                    Path(tmp_name).unlink()
                except OSError:
                    pass
                harnessed_rule_path = None

    sp_file_path = harnessed_rule_path if harnessed_rule_path else rule
    cmd = [_spatch_path() or _SPATCH_BIN, "--sp-file", str(sp_file_path)]

    if target.is_dir():
        cmd.extend(["--dir", str(target)])
    else:
        cmd.append(str(target))

    if no_includes:
        cmd.append("--no-includes")
    if include_dirs:
        for d in include_dirs:
            cmd.extend(["-I", str(d)])

    cmd.append("--very-quiet")

    if defines:
        for k, v in defines.items():
            cmd.extend(["-D", f"{k}={v}"])

    run_env = dict(env) if env is not None else RaptorConfig.get_safe_env()
    runner = subprocess_runner or subprocess.run

    start = time.monotonic()
    # `cwd=target.parent if file else target if dir`. spatch
    # resolves #include paths relative to its CWD when paths
    # are not absolute. Pre-fix the runner inherited the
    # parent process's CWD (typically the RAPTOR repo root,
    # not the target's directory), so:
    #   * Headers in the target's own tree found via relative
    #     #include were missed (spatch couldn't resolve
    #     `#include "foo.h"` because it looked in
    #     RAPTOR-root not target-root).
    #   * SmPL `<+...+>` patterns spanning multiple translation
    #     units silently failed to match across includes.
    # Setting cwd= to the target's directory fixes both — the
    # path semantics now match what spatch expects when invoked
    # by hand from the target repo.
    if target.is_file():
        spatch_cwd = target.parent
    elif target.is_dir():
        spatch_cwd = target
    else:
        spatch_cwd = None
    try:
        try:
            proc = runner(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=run_env,
                cwd=str(spatch_cwd) if spatch_cwd is not None else None,
            )
        except subprocess.TimeoutExpired as exc:
            # Capture partial output before giving up. spatch on
            # large repos sometimes runs past the timeout AFTER
            # producing partial results — pre-fix we threw away
            # everything (returned only "Timeout" error). Now we
            # parse whatever it managed to emit before the timeout
            # so operators see those matches in the report
            # alongside the timeout warning.
            partial_stdout = exc.stdout if isinstance(exc.stdout, str) else (
                exc.stdout.decode("utf-8", errors="replace") if exc.stdout else ""
            )
            partial_stderr = exc.stderr if isinstance(exc.stderr, str) else (
                exc.stderr.decode("utf-8", errors="replace") if exc.stderr else ""
            )
            partial_matches = _dedup_matches(
                _parse_results(partial_stdout, rule_name)
                + _parse_results(partial_stderr, rule_name)
            )
            return SpatchResult(
                rule=rule_name, rule_path=str(rule),
                matches=partial_matches,
                errors=[f"Timeout after {timeout}s (partial output captured)"],
                returncode=-1,
            )
        except OSError as e:
            return SpatchResult(
                rule=rule_name, rule_path=str(rule),
                errors=[str(e)],
                returncode=-1,
            )
        elapsed = int((time.monotonic() - start) * 1000)

        matches = _dedup_matches(
            _parse_results(proc.stdout, rule_name) + _parse_results(proc.stderr, rule_name)
        )
        errors = _parse_errors(proc.stderr)

        files_examined = _collect_files_examined(target, {m.file for m in matches})

        return SpatchResult(
            rule=rule_name,
            rule_path=str(rule),
            matches=matches,
            files_examined=files_examined,
            errors=errors,
            elapsed_ms=elapsed,
            returncode=proc.returncode,
        )
    finally:
        # Clean up the harnessed-rule tempfile. Covers timeout
        # (early return), OSError (early return), and normal-exit
        # paths uniformly. Best-effort; an already-unlinked file
        # or permission flake doesn't affect the result.
        if harnessed_rule_path is not None:
            try:
                harnessed_rule_path.unlink()
            except OSError:
                pass


def run_rules(
    target: Path,
    rules_dir: Path,
    *,
    include_dirs: Optional[List[Path]] = None,
    no_includes: bool = False,
    timeout_per_rule: int = 300,
    env: Optional[Dict[str, str]] = None,
    defines: Optional[Dict[str, str]] = None,
    subprocess_runner=None,
) -> List[SpatchResult]:
    """Run all .cocci rules in a directory against a target.

    Returns one SpatchResult per rule, in filename order.
    """
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        return []

    rule_paths = sorted(rules_dir.glob("*.cocci"))
    if not rule_paths:
        return []

    if not is_available():
        return [
            SpatchResult(
                rule="coccinelle",
                errors=["spatch is not installed (coccinelle package not found on PATH)"],
                returncode=-1,
            )
        ]

    results = []
    for rule_path in rule_paths:
        result = run_rule(
            target, rule_path,
            include_dirs=include_dirs,
            no_includes=no_includes,
            timeout=timeout_per_rule,
            env=env,
            defines=defines,
            subprocess_runner=subprocess_runner,
        )
        results.append(result)

    return results


def _dedup_matches(matches: List[SpatchMatch]) -> List[SpatchMatch]:
    """Remove duplicate matches (same file+line+col+rule), preserving order."""
    seen: set = set()
    result = []
    for m in matches:
        key = (m.file, m.line, m.column, m.rule)
        if key not in seen:
            seen.add(key)
            result.append(m)
    return result


def _collect_files_examined(target: Path, match_files: set) -> List[str]:
    """Build files_examined from the target path plus any match files.

    spatch has no machine-readable log of which files it processed, so we
    approximate: for a single file target we know exactly; for a directory
    we enumerate *.c AND *.h (spatch examines headers too — pre-fix
    only `.c` was counted, so the files_examined report under-
    counted by ~50% on typical C projects, and any rule that
    matched in a header silently failed to surface in
    files_examined even though it WAS examined).
    """
    if target.is_file():
        examined = {str(target)} | match_files
    elif target.is_dir():
        # Both .c and .h — spatch examines preprocessed
        # translation units which include headers via #include
        # expansion. Operators tracking "did the rule examine
        # this header?" need .h in the list.
        examined = (
            {str(f) for f in target.rglob("*.c")}
            | {str(f) for f in target.rglob("*.h")}
            | match_files
        )
    else:
        examined = set(match_files)
    return sorted(examined)


def _inject_harness(rule_text: str, rule_name: str) -> str:
    """Wrap a plain SmPL rule with a Python reporting harness.

    Adds an @script:python block that emits COCCIRESULT JSON lines for
    each match. Binds the first position metavariable from the first
    named rule — only correct for single-rule SmPL files. Multi-rule
    files where the position variable is declared in a later rule will
    produce an "unbound metavariable" error from spatch.

    If no position metavariable is found, returns the rule unchanged
    (matches won't produce structured output, but spatch still runs).
    """
    # `re.ASCII` so `\w` matches only ASCII identifiers. Pre-fix the
    # bare pattern admitted Unicode word chars (Cyrillic, Greek,
    # CJK, fullwidth letters) — and the captured pos_var is then
    # f-string-interpolated into the synthesised @script:python
    # harness AND used as a Python identifier in the harness's for-
    # loop. Python 3 accepts Unicode identifiers, but a hostile
    # rule file with a homoglyph pos_var could produce a harness
    # whose runtime identifier collides with a different rule
    # variable visually but not structurally. Stick to ASCII for
    # the harness-injected identifier; legitimate Coccinelle rules
    # use ASCII metavariable names per convention.
    if not re.search(r"position\s+\w+", rule_text, re.ASCII):
        return rule_text

    pos_match = re.search(r"position\s+(\w+)", rule_text, re.ASCII)
    pos_var = pos_match.group(1)

    # Detect multi-rule .cocci files. Pre-fix the harness only
    # bound to the FIRST `@rule_name@` block, so:
    #   * If the position variable was declared in a LATER
    #     rule, spatch raised "unbound metavariable" for the
    #     harness reference.
    #   * If multiple rules each declared their own position
    #     vars, only the first one's matches were captured;
    #     the rest silently produced no COCCIRESULT output.
    # `re.findall(r"@(\w+)@", rule_text)` finds all named rule
    # headers. Multi-rule (>1 distinct name) returns the rule
    # text unchanged — spatch still runs (just without our
    # JSON harness), and the caller logs that structured
    # output was unavailable for this rule file. Better than
    # silently emitting partial / wrong data.
    # `re.ASCII` for the same identifier-scope reason as above —
    # rule names are Python identifiers in the harness.
    rule_names = re.findall(r"@(\w+)@", rule_text, re.ASCII)
    if len(set(rule_names)) > 1:
        # Multi-rule file — harness injection isn't safe.
        # Caller handles the no-output case via spatch's
        # raw stdout.
        return rule_text
    if not rule_names:
        return rule_text
    rule_id = rule_names[0]

    safe_name = _SAFE_NAME_RE.sub("_", rule_name)

    harness = f"""

@script:python@
{pos_var} << {rule_id}.{pos_var};
@@

import json, sys
for _p in {pos_var}:
    _m = {{"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": "{safe_name}"}}
    sys.stderr.write("{RESULT_PREFIX}" + json.dumps(_m) + "\\n")
"""
    return rule_text + harness


def _parse_results(output: str, rule_name: str) -> List[SpatchMatch]:
    """Parse COCCIRESULT lines from spatch stdout or stderr."""
    matches = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(RESULT_PREFIX):
            json_str = line[len(RESULT_PREFIX):]
            try:
                d = json.loads(json_str)
            except (json.JSONDecodeError, ValueError):
                continue
            # Type-guard: spatch's @script:python harness always emits
            # an object, but a malformed rule (operator-supplied SmPL
            # that built the JSON literal incorrectly) could emit a
            # bare array, string, or null. `.setdefault` then crashed
            # with AttributeError, taking out the WHOLE result-parsing
            # loop for that invocation. Skip non-object payloads.
            if not isinstance(d, dict):
                continue
            d.setdefault("rule", rule_name)
            try:
                matches.append(SpatchMatch.from_dict(d))
            except (TypeError, ValueError, KeyError):
                continue
    return matches


_ERROR_PATTERNS = (
    "parse error", "semantic error", "fatal error", "syntax error",
    "unbound metavariable", "already tagged token", "metavariable not used",
)


def _parse_errors(stderr: str) -> List[str]:
    """Extract error messages from spatch stderr, ignoring info lines."""
    errors = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(RESULT_PREFIX):
            continue
        if line.startswith("init_defs_builtins:"):
            continue
        if line.startswith("HANDLING:"):
            continue
        low = line.lower()
        if any(p in low for p in _ERROR_PATTERNS):
            errors.append(line)
    return errors
