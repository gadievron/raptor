"""Mechanical patch-validation gate — annotates, never blocks, never applies.

Runs after ``generate_patch`` receives the LLM's patch response and
produces a :class:`GateResult` the operator reads next to the saved
patch. The gate's premise (docs/security.md A3): a prompt-injected patch
corrupts output *text*, and semantic backdoor detection in arbitrary
diffs is not closable — but a mechanical plausibility gate is. Four
deterministic checks, each with an honest "couldn't check" annotation
when its precondition is missing:

* **format** — the response must contain one strictly parseable unified
  diff (``format: unified-diff`` / ``not-a-unified-diff``). No diff →
  every downstream check is skipped; the patch is still saved for the
  operator exactly as before.
* **scope** — pure Python: every hunk must target the finding's file
  and fall within ``scope_slack`` lines of the finding span
  (``scope: in-bounds`` / ``OUT-OF-SCOPE HUNKS`` + the hunk list). An
  attacker's favourite move is an unrelated hunk touching auth code.
* **detector** — re-run the tool that produced the finding against a
  patched scratch copy (``detector: silenced`` / ``still-firing``).
  Dispatch on the finding's source: synthesized checkers replay from
  the run's ``checkers/`` dir; Semgrep findings replay from the local
  registry-pack cache (``RaptorConfig.SEMGREP_REGISTRY_CACHE_DIR``);
  CodeQL has no practical per-file re-check, annotated honestly as
  ``recheck-unsupported (codeql)`` rather than faked.
* **control** — the same detector must still fire on the UNPATCHED
  copy (``control: ok`` / ``FAILED``). A broken re-run would otherwise
  masquerade as "silenced". Direct port of the negative-control idea in
  ``packages/checker_synthesis/synthesise.py`` (``_fix_mutant_control``
  / ``_dual_control``), including its fail-closed convention that a
  match with no line information counts as in-region.
* **compile** — differential ``cc -fsyntax-only`` for C/C++ when the
  baseline copy compiles standalone (``compile: ok|failed|skipped``).

Sandbox posture mirrors ``core/audit/dark_verify/_execute.py``: the
apply step and every tool re-run execute under ``core.sandbox`` with
network blocked, and when the sandbox is unavailable the gate refuses
(``gate: unavailable``) instead of degrading to a bare subprocess.

Rendering: :func:`render_gate_block` emits the markdown header block
prepended to the saved patch artifact. This file is registered in
``core/security/report_writer_audit.py`` — every value that may carry
LLM-derived text (diff paths, tool stderr) is routed through
``sanitise_string`` before it reaches the report surface.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from core.paths import strip_file_uri

logger = logging.getLogger(__name__)


# Default hunk slack around the finding span, in lines. Deliberately
# generous — legitimate fixes often add a helper or a guard a few
# dozen lines above the flagged sink. Override per-call via
# ``scope_slack=`` or process-wide via the environment variable.
_DEFAULT_SCOPE_SLACK = 40
_SCOPE_SLACK_ENV = "RAPTOR_PATCH_GATE_SCOPE_SLACK"

# Registry-cache pack files are semgrep.dev JSON exports — a corrupt or
# adversarially fattened cache entry should not stall the gate.
_MAX_CACHE_PACK_BYTES = 50 * 1024 * 1024

_SANDBOX_REFUSAL = (
    "sandbox unavailable — refusing to run patch apply / detector "
    "re-runs outside core.sandbox"
)


# ---------------------------------------------------------------------------
# Unified-diff parsing (strict)
# ---------------------------------------------------------------------------

_HUNK_HEADER_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))?"
    r" \+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@"
)

# Same anchoring rationale as agent.py's _CODE_FENCE_RE: fences must
# open at line start and the language tag must end cleanly, so prose
# mentioning ```diff inline doesn't count as a block.
_FENCE_RE = re.compile(
    r"^```(?P<lang>[a-zA-Z0-9_+-]*)\s*\n"
    r"(?P<body>.*?)"
    r"^```\s*$",
    re.MULTILINE | re.DOTALL,
)

# git-style noise lines tolerated between file sections.
_NOISE_PREFIXES = (
    "diff --git",
    "index ",
    "new file mode",
    "deleted file mode",
    "old mode",
    "new mode",
    "similarity index",
    "rename from",
    "rename to",
)


@dataclass
class DiffHunk:
    """One ``@@`` hunk. ``lines`` keeps the prefixed body verbatim."""

    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: list[str] = field(default_factory=list)

    @property
    def old_end(self) -> int:
        return self.old_start + max(self.old_count, 1) - 1


@dataclass
class FileDiff:
    """All hunks addressed to one file pair in the diff."""

    old_path: str
    new_path: str
    hunks: list[DiffHunk] = field(default_factory=list)


@dataclass
class ParsedDiff:
    """A strictly validated unified diff.

    ``text`` is the normalised diff text (newline-terminated) that the
    apply step feeds to ``git apply`` — never the raw LLM response.
    """

    files: list[FileDiff]
    text: str


def _strip_diff_prefix(path: str) -> str:
    """Normalise a diff header path: drop ``a/`` / ``b/`` and ``./``."""
    p = path.strip()
    if p.startswith(("a/", "b/")):
        p = p[2:]
    while p.startswith("./"):
        p = p[2:]
    return p


def _parse_hunks(lines: list[str], i: int) -> tuple[list[DiffHunk], int, bool]:
    """Parse consecutive hunks starting at ``lines[i]``.

    Returns ``(hunks, next_index, ok)``. Strictness: every body line
    must carry a valid prefix and the counts in the ``@@`` header must
    be exactly consumed — a truncated or miscounted hunk rejects the
    whole diff (the apply step would reject it anyway; failing at parse
    gives the operator the clearer ``not-a-unified-diff`` annotation).
    """
    hunks: list[DiffHunk] = []
    n = len(lines)
    while i < n:
        m = _HUNK_HEADER_RE.match(lines[i])
        if not m:
            break
        hunk = DiffHunk(
            old_start=int(m.group("old_start")),
            old_count=int(m.group("old_count") or 1),
            new_start=int(m.group("new_start")),
            new_count=int(m.group("new_count") or 1),
        )
        i += 1
        remaining_old = hunk.old_count
        remaining_new = hunk.new_count
        while (remaining_old > 0 or remaining_new > 0) and i < n:
            body = lines[i]
            if body.startswith("\\"):
                # "\ No newline at end of file" — legal, uncounted.
                hunk.lines.append(body)
                i += 1
                continue
            if body.startswith("+"):
                remaining_new -= 1
            elif body.startswith("-"):
                remaining_old -= 1
            elif body.startswith(" ") or body == "":
                # Empty line = context line whose trailing space was
                # stripped somewhere in transit — ubiquitous in
                # LLM-emitted diffs; git apply tolerates it too.
                remaining_old -= 1
                remaining_new -= 1
            else:
                return hunks, i, False
            hunk.lines.append(body)
            i += 1
        if remaining_old != 0 or remaining_new != 0:
            return hunks, i, False
        hunks.append(hunk)
    return hunks, i, bool(hunks)


def _parse_unified_diff(text: str) -> ParsedDiff | None:
    """Strictly parse ``text`` as a unified diff, or return None.

    Accepts one or more file sections (``--- `` / ``+++ `` header pair
    followed by well-formed hunks). Trailing prose AFTER at least one
    complete file section is tolerated and excluded from the normalised
    text; anything malformed before or inside a section rejects.
    """
    lines = text.splitlines()
    n = len(lines)
    i = 0
    files: list[FileDiff] = []
    consumed_end = 0
    while i < n:
        line = lines[i]
        if not line.strip() or line.startswith(_NOISE_PREFIXES):
            i += 1
            continue
        if line.startswith("--- ") and i + 1 < n and lines[i + 1].startswith("+++ "):
            old_path = line[4:].split("\t")[0].strip()
            new_path = lines[i + 1][4:].split("\t")[0].strip()
            hunks, i, ok = _parse_hunks(lines, i + 2)
            if not ok:
                return None
            files.append(FileDiff(old_path=old_path, new_path=new_path, hunks=hunks))
            consumed_end = i
            continue
        if files:
            # Prose after a complete diff — stop, keep what parsed.
            break
        return None
    if not files:
        return None
    normalised = "\n".join(lines[:consumed_end]) + "\n"
    return ParsedDiff(files=files, text=normalised)


def extract_unified_diff(response: str) -> ParsedDiff | None:
    """Extract the unified diff from an LLM patch response.

    Preference order: fenced ```diff / ```patch blocks, then any fenced
    block whose body looks diff-shaped, then the raw response from its
    first diff header onward. Returns None when nothing parses — the
    caller annotates ``format: not-a-unified-diff`` and skips the rest.
    """
    if not response or not response.strip():
        return None

    tagged: list[str] = []
    untagged: list[str] = []
    for m in _FENCE_RE.finditer(response):
        lang = (m.group("lang") or "").lower()
        body = m.group("body")
        if lang in ("diff", "patch", "udiff"):
            tagged.append(body)
        elif "--- " in body and "@@" in body:
            untagged.append(body)
    for body in tagged + untagged:
        parsed = _parse_unified_diff(body)
        if parsed is not None:
            return parsed

    # Raw fallback: response contains a bare diff outside any fence.
    lines = response.splitlines()
    for idx, line in enumerate(lines):
        if line.startswith("diff --git") or (
            line.startswith("--- ")
            and idx + 1 < len(lines)
            and lines[idx + 1].startswith("+++ ")
        ):
            return _parse_unified_diff("\n".join(lines[idx:]))
    return None


# ---------------------------------------------------------------------------
# Gate result
# ---------------------------------------------------------------------------


@dataclass
class GateResult:
    """Annotation vocabulary for one gated patch.

    * ``format``: ``unified-diff`` | ``not-a-unified-diff``
    * ``gate``: ``ran`` | ``unavailable`` | ``skipped``
    * ``scope``: ``in-bounds`` | ``OUT-OF-SCOPE HUNKS`` |
      ``skipped (no finding span)`` (finding carries no usable line
      anchor — detector checks then consider the whole file)
    * ``apply``: ``ok`` | ``failed``
    * ``detector``: ``silenced`` | ``still-firing`` |
      ``recheck-unsupported (<source>)`` | ``error`` | ``skipped (...)``
    * ``control``: ``ok`` | ``FAILED`` | ``skipped``
    * ``compile``: ``ok`` | ``failed`` | ``skipped``
    * ``reliable``: False when a failed negative control or a detector
      error means the detector/control lines cannot be trusted.

    ``None`` for a stage means the pipeline never reached it (e.g. no
    parseable diff).
    """

    format: str = "not-a-unified-diff"
    gate: str = "ran"
    scope: str | None = None
    out_of_scope_hunks: list[str] = field(default_factory=list)
    apply: str | None = None
    detector: str | None = None
    control: str | None = None
    compile: str | None = None
    reliable: bool = True
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "format": self.format,
            "gate": self.gate,
            "scope": self.scope,
            "out_of_scope_hunks": list(self.out_of_scope_hunks),
            "apply": self.apply,
            "detector": self.detector,
            "control": self.control,
            "compile": self.compile,
            "reliable": self.reliable,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Scope check (pure Python — runs even without a sandbox)
# ---------------------------------------------------------------------------


def _same_file(diff_path: str, finding_path: str) -> bool:
    """Match a diff header path against the finding's repo-relative path.

    Suffix-tolerant in both directions because diffs and findings are
    frequently rooted differently (``src/x.c`` vs ``x.c``).
    """
    a = _strip_diff_prefix(diff_path)
    b = _strip_diff_prefix(finding_path)
    if not a or not b:
        return False
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)


def _scope_check(
    diff: ParsedDiff,
    file_path: str,
    start_line: int,
    end_line: int,
    slack: int,
) -> list[str]:
    """Return descriptions of every out-of-scope hunk (empty = in-bounds)."""
    out: list[str] = []
    lo = max(1, start_line - slack)
    hi = end_line + slack
    for fd in diff.files:
        target = fd.new_path if fd.new_path != "/dev/null" else fd.old_path
        in_finding_file = _same_file(target, file_path)
        display = _strip_diff_prefix(target)
        for h in fd.hunks:
            if not in_finding_file:
                out.append(
                    f"{display}:@@ -{h.old_start},{h.old_count} "
                    f"(different file than the finding)"
                )
            elif h.old_start < lo or h.old_end > hi:
                out.append(
                    f"{display}:@@ -{h.old_start},{h.old_count} "
                    f"(outside finding lines {start_line}-{end_line} "
                    f"±{slack})"
                )
    return out


def _net_added_lines(diff: ParsedDiff, file_path: str) -> int:
    """Net line growth in the finding's file (for patched-copy region math)."""
    total = 0
    for fd in diff.files:
        target = fd.new_path if fd.new_path != "/dev/null" else fd.old_path
        if _same_file(target, file_path):
            total += sum(h.new_count - h.old_count for h in fd.hunks)
    return total


# ---------------------------------------------------------------------------
# Sandbox access — FAIL CLOSED (mirrors core/audit/dark_verify/_execute.py)
# ---------------------------------------------------------------------------


def _import_sandbox_run() -> Callable | None:
    """Import the sandbox entry point, or None when core.sandbox is missing.

    Callers FAIL CLOSED: git-apply consumes an LLM-authored diff and the
    detector re-runs parse a file rewritten by that diff — both are
    target/LLM-derived inputs. "No sandbox" means "no execution", never
    a plain subprocess fallback. Mirrors ``_import_sandbox_run`` in
    core/audit/dark_verify/_execute.py.
    """
    try:
        from core.sandbox.context import run as sandbox_run
    except ImportError:
        return None
    return sandbox_run


def _make_runner(sandbox_run: Callable, scratch_root: Path) -> Callable:
    """subprocess.run-shaped wrapper over core.sandbox.run.

    Same shape as ``make_sandbox_runner`` in
    packages/hypothesis_validation/adapters/base.py, minus its
    subprocess.run fallback — the caller has already fail-closed on
    sandbox availability, so no degradation path exists here. Network
    blocked; Landlock reads/writes scoped to the scratch tree.
    """

    def _runner(cmd, **kwargs):
        kwargs.pop("shell", None)
        return sandbox_run(
            cmd,
            block_network=True,
            target=str(scratch_root),
            output=str(scratch_root),
            # Throwaway HOME: semgrep writes ~/.semgrep/semgrep.log and
            # its settings file unconditionally; with the real home
            # outside the Landlock write scope that denial is fatal to
            # the scan (and the negative control then flags every
            # re-run as broken).
            fake_home=True,
            caller_label="patch-gate",
            env_caller_filtered=True,
            **kwargs,
        )

    return _runner


# ---------------------------------------------------------------------------
# Detector resolution + replay
# ---------------------------------------------------------------------------


@dataclass
class DetectorSpec:
    """A locally re-runnable detector for one finding source."""

    engine: str            # "semgrep" | "coccinelle"
    config: Path           # rule file / cached pack to run
    label: str             # provenance for the notes line
    filter_rule_id: bool   # multi-rule config → filter matches by id


def _rule_ids_match(a: str, b: str) -> bool:
    """Tolerant rule-id equality.

    Semgrep prefixes local-config rule ids with the sanitised config
    path, so the id recorded on the finding and the id in a re-run of
    the same rules frequently differ by a dotted prefix.
    """
    if not a or not b:
        return False
    return a == b or a.endswith("." + b) or b.endswith("." + a)


def _find_cached_semgrep_rule(rule_id: str) -> Path | None:
    """Locate the cached registry pack that defines ``rule_id``.

    Scan runs resolve registry packs to local cache files via
    ``RaptorConfig.get_semgrep_config`` — the same cache is the only
    way to re-run a registry rule with the sandbox's network block in
    force. No cached pack carrying the rule → None (the caller
    annotates recheck-unsupported honestly).
    """
    if not rule_id:
        return None
    try:
        from core.config import RaptorConfig
        cache_dir = Path(RaptorConfig.SEMGREP_REGISTRY_CACHE_DIR)
    except Exception:  # noqa: BLE001 — config import/shape drift
        return None
    if not cache_dir.is_dir():
        return None
    for cache_file in sorted(cache_dir.glob("c.*.json")):
        try:
            if cache_file.stat().st_size > _MAX_CACHE_PACK_BYTES:
                continue
            data = json.loads(cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        rules = data.get("rules") if isinstance(data, dict) else None
        if not isinstance(rules, list):
            continue
        for r in rules:
            if isinstance(r, dict) and _rule_ids_match(str(r.get("id", "")), rule_id):
                return cache_file
    return None


def _resolve_detector(
    rule_id: str,
    tool: str,
    checkers_dir: Path | None,
    rule_config: Path | None,
) -> tuple[DetectorSpec | None, str]:
    """Resolve the finding's detector to something locally re-runnable.

    Returns ``(spec, reason)`` — exactly one is meaningful. Resolution
    order: explicit config from the caller, synthesized checker in the
    run's ``checkers/`` dir (the checker-synthesis replay path), then
    the Semgrep registry cache. CodeQL needs a full database build per
    re-check — annotated unsupported rather than faked.
    """
    if rule_config is not None:
        p = Path(rule_config)
        if p.is_file():
            engine = "coccinelle" if p.suffix == ".cocci" else "semgrep"
            return DetectorSpec(engine, p, f"explicit {engine} rule",
                                filter_rule_id=False), ""
        return None, "explicit rule config not found"

    # Synthesized-checker replay: checker_synthesis._write_rule saves
    # rules as checkers/<rule_id>.yml|.cocci in the run dir.
    if rule_id and checkers_dir is not None and "/" not in rule_id \
            and ".." not in rule_id:
        base = Path(checkers_dir)
        for ext, engine in ((".yml", "semgrep"), (".yaml", "semgrep"),
                            (".cocci", "coccinelle")):
            cand = base / f"{rule_id}{ext}"
            if cand.is_file():
                return DetectorSpec(engine, cand, "synthesized checker",
                                    filter_rule_id=False), ""

    t = (tool or "").lower()
    if "semgrep" in t:
        cached = _find_cached_semgrep_rule(rule_id)
        if cached is not None:
            return DetectorSpec("semgrep", cached, "cached registry pack",
                                filter_rule_id=True), ""
        return None, "semgrep: rule not in local registry cache"
    if "codeql" in t:
        return None, "codeql"
    return None, t or "unknown source"


def _run_detector(
    spec: DetectorSpec,
    target_file: Path,
    runner: Callable,
    rule_id: str,
    timeout: int,
) -> tuple[list[int], list[str]]:
    """Replay the detector against one file; return (match lines, errors).

    Thin dispatch over the existing runners — the semgrep and
    coccinelle invocation logic lives in packages/semgrep/runner.py and
    packages/coccinelle/runner.py; both accept ``subprocess_runner=``
    so the sandbox wrapper slots straight in.
    """
    from core.config import RaptorConfig
    env = RaptorConfig.get_safe_env()
    try:
        if spec.engine == "semgrep":
            from packages.semgrep.runner import run_rule
            res = run_rule(
                target=target_file,
                config=str(spec.config),
                timeout=timeout,
                env=env,
                subprocess_runner=runner,
            )
            if not res.ok:
                return [], list(res.errors or []) or [
                    f"semgrep returned {res.returncode}"
                ]
            lines = [
                f.line for f in (res.findings or [])
                if not spec.filter_rule_id
                or _rule_ids_match(f.rule_id, rule_id)
            ]
            return lines, []
        if spec.engine == "coccinelle":
            from packages.coccinelle.runner import run_rule as cocci_run
            res = cocci_run(
                target_file,
                spec.config,
                no_includes=True,
                timeout=timeout,
                env=env,
                subprocess_runner=runner,
            )
            errors = list(getattr(res, "errors", []) or [])
            if errors:
                return [], errors
            return [int(getattr(m, "line", 0) or 0)
                    for m in getattr(res, "matches", []) or []], []
        return [], [f"unsupported engine: {spec.engine!r}"]
    except Exception as e:  # noqa: BLE001 — detector replay must not crash the gate
        return [], [f"{spec.engine} replay error: {e}"]


def _in_region(match_lines: list[int], lo: int, hi: int) -> list[int]:
    """Matches inside [lo, hi]. Line 0 (engine gave no location) counts
    as in-region — same fail-closed convention as
    checker_synthesis._fix_mutant_control."""
    return [ln for ln in match_lines if ln == 0 or lo <= ln <= hi]


# ---------------------------------------------------------------------------
# Apply + compile steps (sandboxed)
# ---------------------------------------------------------------------------


def _git_apply(
    runner: Callable, workdir: Path, patch_path: Path, timeout: int,
) -> tuple[bool, str]:
    """Apply the diff to the scratch copy with git apply --check first.

    Tries -p1 (``a/`` / ``b/`` prefixed paths — what the prompt asks
    for) then -p0. git apply refuses paths that escape the working
    tree, and the sandbox's Landlock write scope confines it further.
    """
    last_err = ""
    for strip in ("-p1", "-p0"):
        check = runner(
            ["git", "apply", "--check", strip, str(patch_path)],
            cwd=str(workdir), capture_output=True, text=True,
            timeout=timeout,
        )
        if check.returncode != 0:
            last_err = (check.stderr or check.stdout or "").strip()
            continue
        proc = runner(
            ["git", "apply", strip, str(patch_path)],
            cwd=str(workdir), capture_output=True, text=True,
            timeout=timeout,
        )
        if proc.returncode == 0:
            return True, ""
        last_err = (proc.stderr or proc.stdout or "").strip()
    return False, last_err[:500]


_C_SUFFIXES = frozenset({".c"})
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".C", ".c++"})


def _compile_annotation(
    runner: Callable,
    baseline_file: Path,
    patched_file: Path,
    timeout: int,
    notes: list[str],
) -> str:
    """Differential single-file syntax check for C/C++.

    A standalone ``cc -fsyntax-only`` fails on most real-world files
    (project-local includes), so the baseline copy is compiled first —
    only when the ORIGINAL passes is a patched-copy failure meaningful.
    """
    suffix = baseline_file.suffix
    if suffix in _C_SUFFIXES:
        compiler = "cc"
    elif suffix in _CXX_SUFFIXES:
        compiler = "c++"
    else:
        return "skipped"
    if shutil.which(compiler) is None:
        notes.append(f"compile: {compiler} not on PATH")
        return "skipped"
    base = runner(
        [compiler, "-fsyntax-only", str(baseline_file)],
        capture_output=True, text=True, timeout=timeout,
        cwd=str(baseline_file.parent),
    )
    if base.returncode != 0:
        notes.append(
            "compile: baseline does not compile standalone — "
            "differential syntax check skipped"
        )
        return "skipped"
    patched = runner(
        [compiler, "-fsyntax-only", str(patched_file)],
        capture_output=True, text=True, timeout=timeout,
        cwd=str(patched_file.parent),
    )
    return "ok" if patched.returncode == 0 else "failed"


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------


def _env_scope_slack() -> int:
    """Read the hunk-slack override from the env var, fall back to
    the default. Malformed values (non-integer / negative) warn and
    fall back — same posture as the scan-threshold sibling
    (``RAPTOR_SCAN_THIN_COVERAGE_THRESHOLD``) — so a typo doesn't
    silently re-widen the gate's scope check."""
    raw = os.environ.get(_SCOPE_SLACK_ENV, "")
    if not raw:
        return _DEFAULT_SCOPE_SLACK
    try:
        value = int(raw)
    except ValueError:
        logger.warning(
            "%s=%r is not an int; using default %d",
            _SCOPE_SLACK_ENV, raw, _DEFAULT_SCOPE_SLACK,
        )
        return _DEFAULT_SCOPE_SLACK
    if value < 0:
        logger.warning(
            "%s=%d must be >= 0; using default %d",
            _SCOPE_SLACK_ENV, value, _DEFAULT_SCOPE_SLACK,
        )
        return _DEFAULT_SCOPE_SLACK
    return value


def run_patch_gate(
    response_text: str,
    *,
    repo_path: Path,
    file_path: str,
    start_line: int,
    end_line: int,
    rule_id: str = "",
    tool: str = "",
    checkers_dir: Path | None = None,
    rule_config: Path | None = None,
    scope_slack: int | None = None,
    timeout: int = 300,
) -> GateResult:
    """Run the full mechanical gate over one LLM patch response.

    Never raises for content-shaped reasons; every degradation is an
    annotation. The result feeds :func:`render_gate_block` and the
    finding's ``patch_gate`` dict — nothing here blocks the patch from
    being saved and nothing ever applies it to the real tree.
    """
    result = GateResult()
    slack = scope_slack if scope_slack is not None else _env_scope_slack()

    diff = extract_unified_diff(response_text)
    if diff is None:
        result.format = "not-a-unified-diff"
        result.notes.append(
            "no parseable unified diff in the response — remaining "
            "checks skipped"
        )
        return result
    result.format = "unified-diff"

    # Some flows (multi-model PatchTask over imported or SCA-shaped
    # findings) genuinely lack file or line context — annotate honestly
    # rather than scope-checking against a guessed anchor.
    if not str(file_path).strip():
        result.gate = "skipped"
        result.notes.append(
            "finding has no file context — mechanical checks skipped"
        )
        return result
    has_span = start_line >= 1

    # Scope: pure Python, no sandbox needed.
    if has_span:
        oos = _scope_check(diff, file_path, start_line, end_line, slack)
        result.out_of_scope_hunks = oos
        result.scope = "OUT-OF-SCOPE HUNKS" if oos else "in-bounds"
    else:
        result.scope = "skipped (no finding span)"

    # Resolve + confine the finding's source file (same containment
    # check as VulnerabilityContext.get_full_file_path).
    # Leading-scheme strip only — the old substring-replace corrupted
    # paths containing a literal file:// mid-string.
    rel = strip_file_uri(_strip_diff_prefix(file_path))
    source_file = (Path(repo_path) / rel).resolve()
    try:
        source_file.relative_to(Path(repo_path).resolve())
    except ValueError:
        result.gate = "skipped"
        result.notes.append("finding path escapes the repo — gate skipped")
        return result
    if not source_file.is_file():
        result.gate = "skipped"
        result.notes.append("finding's source file not found — gate skipped")
        return result

    sandbox_run = _import_sandbox_run()
    if sandbox_run is None:
        result.gate = "unavailable"
        result.detector = "skipped"
        result.control = "skipped"
        result.compile = "skipped"
        result.notes.append(_SANDBOX_REFUSAL)
        return result

    with tempfile.TemporaryDirectory(prefix="raptor_pg_") as tmp:
        scratch = Path(tmp)
        patched_file = scratch / "patched" / rel
        baseline_file = scratch / "baseline" / rel
        patched_file.parent.mkdir(parents=True, exist_ok=True)
        baseline_file.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_file, patched_file)
        shutil.copyfile(source_file, baseline_file)
        patch_path = scratch / "candidate.diff"
        patch_path.write_text(diff.text, encoding="utf-8")

        runner = _make_runner(sandbox_run, scratch)

        applied, apply_err = _git_apply(
            runner, scratch / "patched", patch_path, timeout,
        )
        if not applied:
            result.apply = "failed"
            result.detector = "skipped (patch did not apply)"
            result.control = "skipped"
            result.compile = "skipped"
            if apply_err:
                result.notes.append(f"apply: {apply_err}")
            return result
        result.apply = "ok"

        spec, reason = _resolve_detector(rule_id, tool, checkers_dir, rule_config)
        if spec is None:
            result.detector = f"recheck-unsupported ({reason})"
            result.control = "skipped"
        else:
            result.notes.append(f"detector: {spec.label} ({spec.engine})")
            base_lines, base_errs = _run_detector(
                spec, baseline_file, runner, rule_id, timeout,
            )
            pat_lines, pat_errs = _run_detector(
                spec, patched_file, runner, rule_id, timeout,
            )
            if base_errs or pat_errs:
                result.detector = "error"
                result.control = "skipped"
                result.reliable = False
                for err in (base_errs + pat_errs)[:3]:
                    result.notes.append(f"detector re-run: {str(err)[:300]}")
            else:
                # No span → whole-file region: "silenced" then means
                # the rule no longer fires anywhere in the file.
                lo = max(1, start_line - slack) if has_span else 1
                base_hi = end_line + slack if has_span else 10**9
                pat_hi = base_hi + max(0, _net_added_lines(diff, file_path))
                base_hits = _in_region(base_lines, lo, base_hi)
                pat_hits = _in_region(pat_lines, lo, pat_hi)
                result.detector = "silenced" if not pat_hits else "still-firing"
                if base_hits:
                    result.control = "ok"
                else:
                    result.control = "FAILED"
                    result.reliable = False
                    result.notes.append(
                        "negative control FAILED: detector did not fire "
                        "on the unpatched copy — the detector verdict "
                        "is not trustworthy"
                    )

        result.compile = _compile_annotation(
            runner, baseline_file, patched_file, timeout, result.notes,
        )

    return result


# ---------------------------------------------------------------------------
# Rendering (report surface — registered in report_writer_audit)
# ---------------------------------------------------------------------------


def render_gate_block(result: GateResult) -> str:
    """Markdown gate-results header for the saved patch artifact.

    Out-of-scope hunk descriptions embed diff header paths and notes
    may embed tool stderr — both LLM/target-derived, so everything
    dynamic passes through ``sanitise_string``.
    """
    from core.security.prompt_output_sanitise import sanitise_string

    lines = [
        "## Patch Gate (mechanical — annotates only, never auto-applies)",
        "",
        f"- format: {sanitise_string(result.format, max_chars=120)}",
    ]
    if result.gate != "ran":
        lines.append(f"- gate: {sanitise_string(result.gate, max_chars=120)}")
    for label, value in (
        ("scope", result.scope),
        ("apply", result.apply),
        ("detector", result.detector),
        ("control", result.control),
        ("compile", result.compile),
    ):
        if value:
            lines.append(f"- {label}: {sanitise_string(value, max_chars=200)}")
    for hunk in result.out_of_scope_hunks[:10]:
        lines.append(f"  - out-of-scope: {sanitise_string(hunk, max_chars=200)}")
    if not result.reliable:
        lines.append("- reliability: UNRELIABLE — see notes")
    for note in result.notes[:10]:
        lines.append(f"- note: {sanitise_string(note, max_chars=300)}")
    return "\n".join(lines) + "\n"
