"""Coccinelle (spatch) runner — invoke rules and parse structured output.

spatch 1.3 has no --json flag. We use Python scripting blocks injected into
rules to emit structured COCCIRESULT lines on stdout that we parse here.

For rules that already contain their own Python scripting (human-authored
static rules), we parse their output directly. For rules without scripting,
we wrap them with a reporting harness.

Trust posture: rules with their own scripting blocks execute code inside
spatch, so they only run when the caller passes ``allow_scripting=True``
(reserved for in-repo, code-trust rules). Untrusted / LLM-synthesised
rules keep the default False and are refused with a structured error;
they rely on the injected harness instead. The default subprocess runner
routes spatch through core.sandbox with network blocked.
"""

import json
import logging
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from core.config import RaptorConfig
from core.run.scratch import scratch_dir
from core.run.toolprobe import probe

from .models import SpatchMatch, SpatchResult

logger = logging.getLogger(__name__)

RESULT_PREFIX = "COCCIRESULT:"
_SPATCH_BIN = "spatch"
_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_-]")


def _make_nonce() -> str:
    """Per-invocation evidence nonce for the COCCIRESULT marker.

    spatch's transform/context diff output re-emits UNMODIFIED source
    lines from the scanned file, and hostile source can therefore plant
    a literal ``COCCIRESULT:{...}`` line that reaches our stdout parse
    (U14-F2: attacker-chosen file/line/rule minted as a verified
    SpatchMatch, PoC'd through an ``#if 0`` block). Every invocation
    now rewrites the rule's emit sites to ``COCCIRESULT-<nonce>:`` and
    the parser accepts ONLY that marker. The nonce is generated after
    the scanned repo was authored, so no repo content can carry it;
    a bare or wrong-nonce marker line is rejected and logged as an
    attack signal.
    """
    return secrets.token_hex(16)


def _nonced_prefix(nonce: str) -> str:
    return f"COCCIRESULT-{nonce}:"

# Position-metavariable names that we refuse to inject into the
# @script:python@ harness — they'd shadow Python builtins / keywords
# or our own scratch identifiers (``_p``, ``_m``), confusing the
# embedded interpreter or enabling unexpected behaviour from a
# hostile .cocci rule. The dunder-prefix check above this set
# catches ``__import__`` / ``__builtins__`` etc. without enumeration.
_COCCI_POS_VAR_DENY = frozenset({
    # Python keywords
    "True", "False", "None", "if", "else", "elif", "for", "while",
    "import", "from", "as", "def", "class", "return", "yield",
    "lambda", "try", "except", "finally", "raise", "with", "pass",
    "break", "continue", "global", "nonlocal", "assert", "in", "is",
    "not", "and", "or",
    # Harness-scope locals
    "json", "sys", "_p", "_m",
    # Common shadow-the-builtin foot-guns
    "int", "str", "bytes", "open", "type", "list", "dict", "set",
    "tuple", "object", "print", "id", "input", "exec", "eval",
    "compile", "globals", "locals", "vars", "getattr", "setattr",
    "hasattr", "delattr",
})

# SmPL scripting-block headers. `@script:python@`, `@script:ocaml@`,
# `@initialize:python@`, and `@finalize:python@` blocks execute code
# inside the spatch process — an LLM-synthesised or otherwise untrusted
# rule carrying one is a code-execution vector, not a pattern. The
# matcher anchors on the rule-header syntax (line-start `@`, optional
# whitespace, keyword, `:`), so a comment merely *mentioning*
# "@script:python" does not trip it. RAPTOR's own reporting harness is
# appended by _inject_harness AFTER the gate and is exempt by
# construction.
_SCRIPT_BLOCK_RE = re.compile(
    r"^[ \t]*@[ \t]*(?:script|initialize|finalize)[ \t]*:",
    re.MULTILINE | re.IGNORECASE,
)

# Structured-refusal message shared by run_rule / run_rules_batched.
_SCRIPT_BLOCK_REFUSAL = (
    "Rule contains a scripting block (@script:/@initialize:/@finalize:) "
    "and allow_scripting=False — refused before spatch invocation. "
    "Scripting blocks execute code inside spatch; pass "
    "allow_scripting=True only for in-repo, code-trust rules."
)


def contains_script_block(rule_text: str) -> bool:
    """True when ``rule_text`` declares an SmPL scripting block
    (``@script:``, ``@initialize:``, or ``@finalize:`` rule header).

    Shared gate: the runner refuses such rules unless the caller
    passes ``allow_scripting=True``, and checker synthesis uses the
    same predicate to reject LLM-emitted rules before they are
    persisted to disk.
    """
    return bool(_SCRIPT_BLOCK_RE.search(rule_text))


def _sandboxed_run(cmd, **kwargs):
    """Default subprocess runner: spatch inside core.sandbox with
    network blocked.

    Mirrors packages/codeql/query_runner.py: the rule text may carry
    embedded scripting (trusted in-repo rules, or the harness we
    inject), so the process gets no network and the standard sandbox
    filesystem posture. ``tool_paths`` exposes the spatch install dir
    so mount-ns mode keeps the binary visible when it is not under
    /usr/bin. Sandbox layers degrade internally when unavailable;
    a SandboxSetupError propagates — fail loud, never mask as a
    benign result. Callers that pass an explicit ``subprocess_runner``
    bypass this entirely (tests use stubs; adapters bring their own
    sandbox wrapper).
    """
    from core.sandbox import run as sandbox_run

    sp = _spatch_path()
    tool_paths = [str(Path(sp).resolve().parent)] if sp else None
    # env_caller_filtered: every caller in this module derives its env
    # from get_safe_env() (plus the private scratch TMPDIR), so the
    # sandbox's "unfiltered caller env" warning does not apply — and
    # would otherwise fire once per spatch invocation.
    kwargs.setdefault("env_caller_filtered", True)
    return sandbox_run(
        cmd,
        block_network=True,
        tool_paths=tool_paths,
        caller_label="coccinelle-runner",
        **kwargs,
    )


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
# The cached path is the REAL path (os.path.realpath of the which()
# result): package managers and opam installs commonly place a symlink
# on PATH while the actual binary (and its sibling data files) live in
# the install prefix. The mount-ns visibility check realpaths cmd[0]
# and the bind tree carries the RESOLVED tool dir, so exec'ing the
# un-realpath'd symlink either fails ENOENT inside the namespace or
# silently drops the run to the Landlock-only fallback tier
# (selftest-05 scanner precedent: exec tools via their real path).
_resolved_spatch: str | None = None
_spatch_resolved: bool = False  # True once we've cached (None or path).
def _spatch_path() -> str | None:
    global _resolved_spatch, _spatch_resolved
    if not _spatch_resolved:
        _found = shutil.which(_SPATCH_BIN)
        _resolved_spatch = os.path.realpath(_found) if _found else None
        _spatch_resolved = True
    return _resolved_spatch


def is_available() -> bool:
    """Check whether spatch is on PATH."""
    # Always re-probe in is_available so test mocks of shutil.which
    # work as expected. The cache only locks in for command builds
    # (where the race-protection matters); is_available is a
    # cheap probe.
    return shutil.which(_SPATCH_BIN) is not None


# Minimum spatch version RAPTOR's shipped rule-set is authored against.
# Several attribute rules (engine/coccinelle/source_intel/attrs/*) match a
# *prefix* GCC attribute on a function declaration —
# ``__attribute__((deprecated)) T f(...);`` — which spatch only learned to
# parse at 1.3. On 1.1.1 (the apt build on Ubuntu 22.04/24.04 and Debian
# bookworm) those rules raise a SmPL parse error and emit nothing; the
# runner degrades per-rule (the run continues) but the rule is dead. The
# rule-integrity parse test gates on this so it skips — rather than
# false-fails — on a host whose spatch predates the floor.
MIN_SPATCH_VERSION = (1, 3)


def version() -> str | None:
    """Return the spatch version string, or None if unavailable.

    Probe execution delegates to core.run.toolprobe (safe env,
    resolved-path exec, uncached so per-test ``subprocess.run``
    patches stay hermetic); the ``spatch version X`` line parse is
    spatch-specific and stays here.
    """
    info = probe(_SPATCH_BIN)
    if info is None:
        return None
    for line in info.stdout.splitlines():
        if line.startswith("spatch version"):
            return line.split("spatch version", 1)[1].strip()
    return info.stdout.strip().splitlines()[0] if info.stdout.strip() else None


def version_tuple() -> tuple | None:
    """Parse the leading ``major.minor`` of the spatch version into an
    int tuple (e.g. ``"1.3 compiled with ..."`` → ``(1, 3)``), or None if
    spatch is unavailable / the version string can't be parsed."""
    v = version()
    if not v:
        return None
    m = re.match(r"\s*(\d+)\.(\d+)", v)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def meets_min_version() -> bool:
    """True iff an installed spatch is at least ``MIN_SPATCH_VERSION``.
    False when spatch is absent or its version can't be determined."""
    vt = version_tuple()
    return vt is not None and vt >= MIN_SPATCH_VERSION


def run_rule(
    target: Path,
    rule: Path,
    *,
    include_dirs: list[Path] | None = None,
    no_includes: bool = False,
    timeout: int = 300,
    env: dict[str, str] | None = None,
    defines: dict[str, str] | None = None,
    subprocess_runner=None,
    allow_scripting: bool = False,
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
        subprocess_runner: Optional callable replacing the default sandboxed
            runner. Must accept the same kwargs (capture_output, text,
            timeout, env, input) and return an object with
            returncode/stdout/stderr. Defaults to ``_sandboxed_run``
            (core.sandbox with network blocked). Callers that need a
            different isolation posture pass their own wrapper; tests
            pass stubs.
        allow_scripting: When False (default), a rule declaring an SmPL
            scripting block (``@script:`` / ``@initialize:`` /
            ``@finalize:``) is refused with a structured error before any
            tempfile write or spatch invocation — those blocks execute
            code inside spatch. Pass True only for in-repo, code-trust
            rules (engine/coccinelle shipped rules, cocci_flow templates).
            RAPTOR's own injected reporting harness is added after this
            gate and is exempt by construction.

    Returns:
        SpatchResult with matches parsed from COCCIRESULT lines.
    """
    rule = Path(rule).resolve()
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

    # Size cap on the .cocci rule body. Operator-supplied today, but
    # the cocci_utilization arc proposes deriving rules from
    # scanned-repo content — this prevents a hostile rule from
    # OOMing the runner via a multi-GiB file. Real coccinelle rules
    # are <100 KiB; 1 MiB is generous.
    _RULE_MAX_BYTES = 1 * 1024 * 1024
    try:
        if rule.stat().st_size > _RULE_MAX_BYTES:
            return SpatchResult(
                rule=rule_name, rule_path=str(rule),
                errors=[f"Rule file exceeds {_RULE_MAX_BYTES}-byte cap"],
                returncode=-1,
            )
    except OSError as e:
        return SpatchResult(
            rule=rule_name, rule_path=str(rule),
            errors=[f"Rule file stat failed: {e}"],
            returncode=-1,
        )

    rule_text = rule.read_text(encoding="utf-8")

    # Scripting gate — refuse before any tempfile write or spatch
    # invocation. See contains_script_block / allow_scripting docs.
    if not allow_scripting and contains_script_block(rule_text):
        return SpatchResult(
            rule=rule_name, rule_path=str(rule),
            errors=[_SCRIPT_BLOCK_REFUSAL],
            returncode=-1,
        )

    needs_harness = RESULT_PREFIX not in rule_text and "script:python" not in rule_text

    # Per-invocation evidence nonce (see _make_nonce): every emit site
    # — the rule's own scripting blocks and our injected harness — is
    # rewritten from ``COCCIRESULT:`` to ``COCCIRESULT-<nonce>:``; the
    # parser accepts only the nonced marker.
    nonce = _make_nonce()
    exec_text = rule_text
    if needs_harness:
        exec_text = _inject_harness(rule_text, rule_name)
    exec_text = exec_text.replace(RESULT_PREFIX, _nonced_prefix(nonce))

    # Any modified text (harness injection and/or nonce substitution)
    # has to reach spatch via a real file path. ``--sp-file -``
    # (stdin) does not work on spatch 1.3 (the build on every host we
    # ship to) — each spelling errors with either
    # ``Sys_error("-: No such file or directory")`` or "unexpected
    # code before the first rule". The only reliable invocation is
    # a real path. Write the modified text to a tempfile and pass
    # its path; cleanup in ``finally`` covers timeout / error paths.
    harnessed_rule_path: Path | None = None
    if exec_text != rule_text:
        # Tempfile in the system tempdir — works under the
        # default sandbox allowlist (``/tmp`` is reachable).
        # delete=False so we control cleanup; without it the
        # NamedTemporaryFile context manager would unlink on
        # exit before spatch could read it through the
        # subprocess_runner.
        fd, tmp_name = tempfile.mkstemp(suffix=".cocci", prefix="raptor-cocci-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(exec_text)
            harnessed_rule_path = Path(tmp_name)
        except OSError as e:
            # Fail closed: running the ORIGINAL file would emit
            # plain (un-nonced) markers that the parser must reject,
            # so the run could only ever report false silence.
            # Pre-nonce this fell back to the un-harnessed rule; now
            # an unwritable tempdir is a structured error instead.
            try:
                Path(tmp_name).unlink()
            except OSError:
                pass
            return SpatchResult(
                rule=rule_name, rule_path=str(rule),
                errors=[
                    "failed to materialise nonce-marked rule file: "
                    f"{e}",
                ],
                returncode=-1,
            )

    sp_file_path = harnessed_rule_path or rule
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
    # Private scratch for spatch's own temp files. spatch materialises
    # per-file working copies (cocci-output-*, cocci_small_output-*)
    # in the temp dir and only removes them on clean exit — a timeout
    # kill or spatch crash strands them (observed: ~200 files from one
    # interrupted sweep). It honours TMPDIR, so scratch_dir points each
    # invocation at its own dir (TMPDIR exported into run_env) and
    # removes it on exit — including whatever a killed spatch left.
    with scratch_dir("raptor-cocci-tmp-", env=run_env):
        runner = subprocess_runner or _sandboxed_run

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
                    _parse_results(partial_stdout, rule_name, nonce=nonce)
                    + _parse_results(partial_stderr, rule_name, nonce=nonce)
                )
                return SpatchResult(
                    rule=rule_name, rule_path=str(rule),
                    matches=partial_matches,
                    errors=[f"Timeout after {timeout}s (partial output captured)"],
                    returncode=-1,
                    forged_markers=_warn_forged_markers(
                        partial_stdout, partial_stderr,
                        nonce=nonce, rule_name=rule_name, target=target,
                    ),
                )
            except OSError as e:
                return SpatchResult(
                    rule=rule_name, rule_path=str(rule),
                    errors=[str(e)],
                    returncode=-1,
                )
            elapsed = int((time.monotonic() - start) * 1000)

            matches = _dedup_matches(
                _parse_results(proc.stdout, rule_name, nonce=nonce)
                + _parse_results(proc.stderr, rule_name, nonce=nonce)
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
                forged_markers=_warn_forged_markers(
                    proc.stdout, proc.stderr,
                    nonce=nonce, rule_name=rule_name, target=target,
                ),
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
    include_dirs: list[Path] | None = None,
    no_includes: bool = False,
    timeout_per_rule: int = 300,
    env: dict[str, str] | None = None,
    defines: dict[str, str] | None = None,
    subprocess_runner=None,
    allow_scripting: bool = False,
    on_rule=None,
) -> list[SpatchResult]:
    """Run all .cocci rules in a directory against a target.

    ``allow_scripting`` is forwarded to run_rule — pass True only for
    in-repo, code-trust rule directories.

    ``on_rule`` is an optional progress callback invoked BEFORE each
    rule runs as ``on_rule(index, total, rule_stem)`` (0-based index,
    total rules in this directory). A single spatch invocation can run
    for minutes on large C targets; the callback lets callers emit
    operator-facing progress instead of going silent for the whole
    directory. Callback failures are swallowed — progress must never
    cost a scan.

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
    for idx, rule_path in enumerate(rule_paths):
        if on_rule is not None:
            try:
                on_rule(idx, len(rule_paths), rule_path.stem)
            except Exception:  # noqa: BLE001 — progress must never cost a scan
                logger.debug(
                    "on_rule progress callback failed", exc_info=True,
                )
        result = run_rule(
            target, rule_path,
            include_dirs=include_dirs,
            no_includes=no_includes,
            timeout=timeout_per_rule,
            env=env,
            defines=defines,
            subprocess_runner=subprocess_runner,
            allow_scripting=allow_scripting,
        )
        results.append(result)

    return results


def run_rules_batched(
    target: Path,
    rules: list[Path],
    *,
    timeout: int = 300,
    env: dict[str, str] | None = None,
    subprocess_runner=None,
    allow_scripting: bool = False,
) -> dict[str, SpatchResult]:
    """Run multiple .cocci rules in a single spatch invocation.

    Concatenates rule files into one temp file so spatch parses the C
    AST once.  Results are demultiplexed by the ``rule`` field in each
    COCCIRESULT line.  Rules that already contain @script:python@ blocks
    emitting COCCIRESULT are required (all engine/coccinelle/rules/ do),
    so batch callers running the shipped rule set must pass
    ``allow_scripting=True``. With the default False, any rule declaring
    a scripting block gets a structured refusal result (no execution);
    the remaining rules still run.

    Returns a dict keyed by rule stem name → SpatchResult.
    Falls back to per-rule run_rule when only one rule is given.
    """
    rules = [Path(r).resolve() for r in rules if Path(r).exists()]
    if not rules:
        return {}
    if len(rules) == 1:
        result = run_rule(
            target, rules[0], timeout=timeout,
            env=env, subprocess_runner=subprocess_runner,
            allow_scripting=allow_scripting,
        )
        return {rules[0].stem: result}

    if not is_available():
        return {
            r.stem: SpatchResult(
                rule=r.stem, rule_path=str(r),
                errors=["spatch is not installed"],
                returncode=-1,
            )
            for r in rules
        }

    parts = []
    rule_stems = []
    batched_rules = []
    refused: dict[str, SpatchResult] = {}
    alias_of: dict[str, str] = {}
    for r in rules:
        text = r.read_text(encoding="utf-8")
        # Scripting gate — same policy as run_rule, applied before the
        # batch tempfile is written. Refused rules never reach spatch.
        if not allow_scripting and contains_script_block(text):
            refused[r.stem] = SpatchResult(
                rule=r.stem, rule_path=str(r),
                errors=[_SCRIPT_BLOCK_REFUSAL],
                returncode=-1,
            )
            continue
        parts.append(f"// --- begin {r.stem} ---\n{text}\n")
        rule_stems.append(r.stem)
        batched_rules.append(r)
        # Alias map for the demux: several shipped rule files emit
        # 'rule' ids that differ from their file stem (e.g.
        # va_arg_mismatch.cocci emits only va_arg_promoted_type*,
        # double_close.cocci's second leg emits double_fclose).
        # Pre-fix the demux keyed on stems only and silently dropped
        # every alias emission — 100% of some rules' output.
        for emitted in _emitted_rule_ids(text):
            prior = alias_of.setdefault(emitted, r.stem)
            if prior != r.stem:
                logger.warning(
                    "batched rules %s and %s both emit rule id %r — "
                    "matches will be attributed to %s",
                    prior, r.stem, emitted, prior,
                )
        alias_of.setdefault(r.stem, r.stem)

    if not rule_stems:
        return refused

    # Same per-invocation evidence nonce as run_rule (see _make_nonce):
    # one nonce covers the whole batch invocation.
    nonce = _make_nonce()
    combined = "\n".join(parts).replace(RESULT_PREFIX, _nonced_prefix(nonce))

    fd, tmp_name = tempfile.mkstemp(
        suffix=".cocci", prefix="raptor-cocci-batch-",
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(combined)
        tmp_path = Path(tmp_name)
    except OSError:
        try:
            Path(tmp_name).unlink()
        except OSError:
            pass
        out = {
            s: SpatchResult(
                rule=s, errors=["failed to write batch file"],
                returncode=-1,
            )
            for s in rule_stems
        }
        out.update(refused)
        return out

    target = Path(target)
    cmd = [_spatch_path() or _SPATCH_BIN, "--sp-file", str(tmp_path)]
    if target.is_dir():
        cmd.extend(["--dir", str(target)])
    else:
        cmd.append(str(target))
    cmd.append("--very-quiet")

    run_env = dict(env) if env is not None else RaptorConfig.get_safe_env()
    # Same private-TMPDIR scratch as run_rule — see the comment there.
    with scratch_dir("raptor-cocci-tmp-", env=run_env):
        runner = subprocess_runner or _sandboxed_run

        if target.is_file():
            spatch_cwd = target.parent
        elif target.is_dir():
            spatch_cwd = target
        else:
            spatch_cwd = None

        start = time.monotonic()
        try:
            try:
                proc = runner(
                    cmd, capture_output=True, text=True,
                    timeout=timeout, env=run_env,
                    cwd=str(spatch_cwd) if spatch_cwd else None,
                )
            except subprocess.TimeoutExpired as exc:
                partial_stdout = exc.stdout if isinstance(
                    exc.stdout, str,
                ) else (
                    exc.stdout.decode("utf-8", errors="replace")
                    if exc.stdout else ""
                )
                partial_stderr = exc.stderr if isinstance(
                    exc.stderr, str,
                ) else (
                    exc.stderr.decode("utf-8", errors="replace")
                    if exc.stderr else ""
                )
                all_matches = _dedup_matches(
                    _parse_results(partial_stdout, "batch", nonce=nonce)
                    + _parse_results(partial_stderr, "batch", nonce=nonce),
                )
                forged = _warn_forged_markers(
                    partial_stdout, partial_stderr,
                    nonce=nonce, rule_name="batch", target=target,
                )
                by_rule = _demux_batch_matches(
                    all_matches, rule_stems, alias_of,
                )
                out = {
                    s: SpatchResult(
                        rule=s, matches=by_rule.get(s, []),
                        errors=[f"Batch timeout after {timeout}s"],
                        returncode=-1,
                        forged_markers=forged,
                    )
                    for s in rule_stems
                }
                out.update(refused)
                return out
            except OSError as e:
                out = {
                    s: SpatchResult(
                        rule=s, errors=[str(e)], returncode=-1,
                    )
                    for s in rule_stems
                }
                out.update(refused)
                return out

            elapsed = int((time.monotonic() - start) * 1000)
            all_matches = _dedup_matches(
                _parse_results(proc.stdout, "batch", nonce=nonce)
                + _parse_results(proc.stderr, "batch", nonce=nonce),
            )
            errors = _parse_errors(proc.stderr)
            forged = _warn_forged_markers(
                proc.stdout, proc.stderr,
                nonce=nonce, rule_name="batch", target=target,
            )

            by_rule = _demux_batch_matches(all_matches, rule_stems, alias_of)

            out = {
                s: SpatchResult(
                    rule=s, rule_path=str(r),
                    matches=by_rule.get(s, []),
                    errors=errors,
                    elapsed_ms=elapsed,
                    returncode=proc.returncode,
                    forged_markers=forged,
                )
                for s, r in zip(rule_stems, batched_rules)
            }
            out.update(refused)
            return out
        finally:
            try:
                Path(tmp_name).unlink()
            except OSError:
                pass


# Emitted-rule-id extraction for the batch demux. Matches the JSON /
# Python-dict literal shape every shipped rule's scripting block uses
# to stamp its COCCIRESULT payload: `"rule": "<id>"` (single or double
# quotes, arbitrary spacing).
_EMITTED_RULE_ID_RE = re.compile(
    r"""["']rule["']\s*:\s*["']([A-Za-z0-9_.:-]+)["']""",
)


def _emitted_rule_ids(rule_text: str) -> set[str]:
    """Rule ids a .cocci file's scripting blocks stamp into their
    COCCIRESULT payloads. Used to build the batch demux alias map."""
    return set(_EMITTED_RULE_ID_RE.findall(rule_text))


def _demux_batch_matches(
    all_matches: list[SpatchMatch],
    rule_stems: list[str],
    alias_of: dict[str, str],
) -> dict[str, list[SpatchMatch]]:
    """Attribute batch matches to their emitting rule file.

    ``alias_of`` maps every emitted rule id (scanned from the rule
    text) plus each file stem to the owning stem. An id that maps to
    no batched rule is logged loudly — never silently dropped: with
    the evidence nonce in place any parsed match came from a batched
    rule's own scripting, so an unattributable id means the alias
    scan missed an emission shape and needs fixing.
    """
    by_rule: dict[str, list[SpatchMatch]] = {s: [] for s in rule_stems}
    for m in all_matches:
        stem = alias_of.get(m.rule)
        if stem is None or stem not in by_rule:
            logger.warning(
                "batched COCCIRESULT rule id %r not attributable to "
                "any batched rule file (stems: %s) — match at %s:%s "
                "dropped from per-rule results",
                m.rule, ", ".join(sorted(by_rule)), m.file, m.line,
            )
            continue
        by_rule[stem].append(m)
    return by_rule


def _dedup_matches(matches: list[SpatchMatch]) -> list[SpatchMatch]:
    """Remove duplicate matches (same file+line+col+rule+message),
    preserving order.

    The ``message`` field MUST be part of the key. Multi-rule cocci
    files (PR-4 function_inventory, source_intel multi-message rules)
    legitimately emit multiple distinct messages at the same
    (file, line) — for example ``def:foo`` and ``call:bar`` both
    landing at line 1 of a one-line function definition that also
    contains a call. Dropping `message` from the key would silently
    coalesce these into a single match, losing the per-message
    information.
    """
    seen: set = set()
    result = []
    for m in matches:
        key = (m.file, m.line, m.column, m.rule, m.message)
        if key not in seen:
            seen.add(key)
            result.append(m)
    return result


def _collect_files_examined(target: Path, match_files: set) -> list[str]:
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
    named rule — only correct for single-rule SmPL files, so files
    with more than one distinct rule name are detected and returned
    un-harnessed (spatch still runs, just without COCCIRESULT
    structured output).

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

    # ASCII-restricted via re.ASCII above, but the captured name
    # becomes a Python identifier inside the @script:python@ harness
    # below — it sits in scope alongside ``json``, ``sys``, ``int``,
    # ``_p``, ``_m`` etc. A hostile coccinelle rule could pick a
    # name that shadows a builtin (``int``, ``open``, ``__import__``)
    # or our own scratch vars and confuse the embedded interpreter.
    # Reject anything in the Python builtin/keyword namespace or
    # starting with a DUNDER (``__``); rule names that fail this
    # check skip harness injection (spatch still runs, just
    # without COCCIRESULT structured output).
    #
    # Pre-fix this rejected ALL underscore-prefixed names
    # (``startswith("_")`` was the first clause), which clobbered
    # legitimate C-style single-underscore positions like
    # ``position _pos``. Single-underscore now flows through —
    # only the Python-dunder pattern + the explicit
    # ``_COCCI_POS_VAR_DENY`` blocklist (``_p`` / ``_m`` etc.)
    # block injection.
    if pos_var.startswith("__") or pos_var in _COCCI_POS_VAR_DENY:
        return rule_text

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
    rule_names = re.findall(r"@[ \t]*(\w+)[ \t]*@", rule_text, re.ASCII)
    if len(set(rule_names)) > 1:
        # Multi-rule file — harness injection isn't safe.
        # Caller handles the no-output case via spatch's
        # raw stdout.
        return rule_text
    if not rule_names:
        return rule_text
    rule_id = rule_names[0]

    safe_name = _SAFE_NAME_RE.sub("_", rule_name)
    # ``json.dumps(safe_name)`` produces a properly-quoted Python
    # string literal — including escapes for any backslashes or
    # double quotes that might end up in safe_name after a future
    # widening of _SAFE_NAME_RE. Pre-fix the f-string interpolated
    # safe_name BETWEEN double quotes; today's regex (``[A-Za-z0-9_-]``)
    # prevents quote/backslash chars but a single regex change
    # would let a hostile rule break out of the string literal.
    safe_name_repr = json.dumps(safe_name)

    harness = f"""

@script:python@
{pos_var} << {rule_id}.{pos_var};
@@

import json, sys
for _p in {pos_var}:
    _m = {{"file": _p.file, "line": int(_p.line), "col": int(_p.column), "line_end": int(_p.line_end), "col_end": int(_p.column_end), "rule": {safe_name_repr}}}
    sys.stderr.write("{RESULT_PREFIX}" + json.dumps(_m) + "\\n")
"""
    return rule_text + harness


def _parse_results(
    output: str, rule_name: str, nonce: str | None = None,
) -> list[SpatchMatch]:
    """Parse COCCIRESULT lines from spatch stdout or stderr.

    When ``nonce`` is given (every runner invocation passes one), only
    lines carrying the per-invocation ``COCCIRESULT-<nonce>:`` marker
    are accepted — a bare ``COCCIRESULT:`` line (or one with a guessed
    nonce) planted in hostile source and re-emitted by spatch's diff
    output is NOT parseable evidence (U14-F2). ``nonce=None`` keeps
    the legacy plain-prefix parse for callers that post-process raw
    spatch output outside a runner invocation (unit tests).
    """
    prefix = _nonced_prefix(nonce) if nonce else RESULT_PREFIX
    matches = []
    for line in output.splitlines():
        line = line.strip()
        if line.startswith(prefix):
            json_str = line[len(prefix):]
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


def _forged_marker_lines(output: str, nonce: str) -> list[str]:
    """COCCIRESULT-shaped lines that do NOT carry the invocation nonce.

    These are exactly the lines the pre-nonce parser would have
    accepted as verified matches: a repo-planted ``COCCIRESULT:{...}``
    surviving in an ``#if 0`` block, a #define continuation, or any
    context line spatch's diff output re-emits. Rejected from the
    match set by _parse_results; surfaced here as an attack signal.
    """
    prefix = _nonced_prefix(nonce)
    forged = []
    for line in output.splitlines():
        s = line.strip()
        if not s.startswith("COCCIRESULT"):
            continue
        if s.startswith(prefix):
            continue
        forged.append(s[:200])
    return forged


def _warn_forged_markers(
    stdout: str, stderr: str, *, nonce: str, rule_name: str, target: Path,
) -> int:
    """Count + log forged COCCIRESULT markers across both streams."""
    forged = (
        _forged_marker_lines(stdout or "", nonce)
        + _forged_marker_lines(stderr or "", nonce)
    )
    if forged:
        logger.warning(
            "COCCIRESULT forgery signal: %d marker line(s) without the "
            "per-invocation nonce rejected (rule %s, target %s) — "
            "likely hostile-source evidence-forgery attempt; first: %s",
            len(forged), rule_name, target, forged[0],
        )
    return len(forged)


_ERROR_PATTERNS = (
    "parse error", "semantic error", "fatal error", "syntax error",
    "unbound metavariable", "already tagged token", "metavariable not used",
)


def _parse_errors(stderr: str) -> list[str]:
    """Extract error messages from spatch stderr, ignoring info lines."""
    errors = []
    for line in stderr.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COCCIRESULT"):
            # Covers both the plain prefix and the per-invocation
            # nonced marker (COCCIRESULT-<nonce>:).
            continue
        if line.startswith("init_defs_builtins:"):
            continue
        if line.startswith("HANDLING:"):
            continue
        low = line.lower()
        if any(p in low for p in _ERROR_PATTERNS):
            errors.append(line)
    return errors
