"""Tool-grounded sweep execution for /audit.

Wraps existing tool packages (semgrep, coccinelle) and SMT verb shims
to run a hypothesis test against a specific file/function, then logs
the result to the audit trail.  The sweep log entry is the breadcrumb
that G3 (NO-SELF-CRITIQUE) checks: re-recording a function requires a
sweep since the last record.

Uses ``packages.semgrep.runner.run_rule``,
``packages.coccinelle.runner.run_rule``, and the
``libexec/raptor-smt-*`` CLI shims.
"""

from __future__ import annotations

import json as _json
import logging
import os
import pickle
import re as _re
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ._util import is_valid_identifier, safe_join

logger = logging.getLogger(__name__)


_ROLE_RE = _re.compile(r"^//\s*@role:\s*(\w+)", _re.MULTILINE)


def get_rule_role(rule_path: str) -> str:
    """Parse ``// @role: detection|verification`` from a rule file.

    Returns ``"detection"`` (default for stock rules without an
    annotation) or ``"verification"``.  Detection rules surface
    candidates; only verification rules may promote status directly.
    Dynamic per-hypothesis rules (not on disk) bypass this check
    entirely — the orchestrator's ``_is_detection_only`` returns
    False for files not in the stock library.
    """
    try:
        with open(rule_path) as f:
            head = f.read(2048)
        m = _ROLE_RE.search(head)
        if m:
            role = m.group(1).lower()
            if role in ("detection", "verification"):
                return role
    except OSError:
        pass
    return "detection"


_IDENTIFIER_QUALIFIED_RE = None  # lazy import


def _is_valid_qualified(name: str) -> bool:
    """Validate a potentially qualified identifier (e.g., os.system)."""
    global _IDENTIFIER_QUALIFIED_RE
    if _IDENTIFIER_QUALIFIED_RE is None:
        import re
        _IDENTIFIER_QUALIFIED_RE = re.compile(
            r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$"
        )
    return bool(_IDENTIFIER_QUALIFIED_RE.match(name))


@dataclass
class SarifCache:
    """Index of prior SARIF results keyed by (file, rule_id).

    Loaded once at orchestrator start from scan/*.sarif in the output
    directory. When the sweep engine wants to run semgrep on a file,
    it checks here first — a cache hit returns the pre-existing matches
    without spawning a subprocess.
    """
    _by_file: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    hit_count: int = 0
    miss_count: int = 0
    _counter_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __bool__(self) -> bool:
        return bool(self._by_file)

    def __len__(self) -> int:
        return len(self._by_file)

    def lookup(
        self, file_path: str, line_start: int = 0, line_end: int = 0,
    ) -> Optional[List[Dict[str, Any]]]:
        """Return SARIF results overlapping the given file and line range.

        Returns None on cache miss (file not in any prior SARIF).
        Returns [] if the file was scanned but had no hits in range.
        """
        normalized = _normalize_sarif_path(file_path)
        results = self._by_file.get(normalized)
        if results is None:
            with self._counter_lock:
                self.miss_count += 1
            return None

        with self._counter_lock:
            self.hit_count += 1
        if not line_start:
            return results

        return [
            r for r in results
            if _sarif_result_in_range(r, line_start, line_end)
        ]

    @classmethod
    def from_directory(cls, out_dir: Path) -> "SarifCache":
        """Load all .sarif files from out_dir/scan/."""
        cache = cls()
        scan_dir = out_dir / "scan"
        if not scan_dir.is_dir():
            return cache

        for sarif_file in scan_dir.glob("*.sarif"):
            try:
                data = _json.loads(sarif_file.read_text())
            except (OSError, _json.JSONDecodeError):
                continue
            for run in data.get("runs", []):
                tool_name = (
                    run.get("tool", {}).get("driver", {}).get("name", "")
                ).lower()
                is_codeql = "codeql" in tool_name
                for result in run.get("results", []):
                    locs = result.get("locations") or [{}]
                    loc = locs[0] if locs else {}
                    phys = loc.get("physicalLocation", {})
                    uri = phys.get("artifactLocation", {}).get("uri", "")
                    normalized = _normalize_sarif_path(uri)
                    if normalized:
                        result["_sarif_source"] = "codeql" if is_codeql else "semgrep"
                        cache._by_file.setdefault(normalized, []).append(result)

        total = sum(len(v) for v in cache._by_file.values())
        if total:
            logger.info(
                "sarif_cache: loaded %d results across %d files",
                total, len(cache._by_file),
            )
        return cache


def _normalize_sarif_path(uri_or_path: str) -> str:
    """Normalize a SARIF artifact URI or file path to a stable key.

    Strips leading ``file://`` and ``./`` prefixes, collapses to a
    forward-slash-separated relative path so that lookup keys match
    insertion keys regardless of how the caller spells the path.
    """
    p = uri_or_path
    if p.startswith("file://"):
        p = p[len("file://"):]
    p = p.lstrip("/")
    if p.startswith("./"):
        p = p[2:]
    return p.replace("\\", "/")


def _sarif_result_in_range(
    result: Dict[str, Any], line_start: int, line_end: int,
) -> bool:
    locs = result.get("locations") or [{}]
    loc = locs[0] if locs else {}
    region = loc.get("physicalLocation", {}).get("region", {})
    rline = region.get("startLine", 0)
    if not rline:
        return True
    if line_end:
        return line_start <= rline <= line_end
    return rline >= line_start


def _match_in_range(
    match: Dict[str, Any], line_start: int, line_end: int,
) -> bool:
    """Return True if a match dict falls within the function line range."""
    match_line = match.get("line", 0)
    if not match_line:
        return True
    return line_start <= match_line <= line_end


def _check_path_containment(
    target_path: Path, file_path: str, tool: str,
) -> Optional[SweepResult]:
    """Return an error SweepResult if file_path escapes target_path."""
    if safe_join(target_path, file_path) is None:
        return SweepResult(
            tool=tool,
            file_path=file_path,
            function_name="",
            outcome="error",
            errors=[f"path escapes target: {file_path}"],
        )
    return None


@dataclass
class SweepResult:
    tool: str
    file_path: str
    function_name: str
    outcome: str  # confirmed | refuted | error | inconclusive
    matches: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    rule_id: Optional[str] = None
    raw_output: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_log_entry(self) -> Dict[str, Any]:
        entry: Dict[str, Any] = {
            "action": "sweep",
            "key": f"{self.file_path}:{self.function_name}",
            "file": self.file_path,
            "function": self.function_name,
            "tool": self.tool,
            "outcome": self.outcome,
        }
        if self.rule_id:
            entry["rule_id"] = self.rule_id
        if self.matches:
            entry["match_count"] = len(self.matches)
        if self.errors:
            entry["errors"] = self.errors
        return entry


def run_semgrep_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    rule_config: str,
    line_start: int = 0,
    line_end: int = 0,
) -> SweepResult:
    """Run a semgrep rule against a single file and classify matches.

    Args:
        target_path: Root of the target codebase.
        file_path: Relative path to the source file.
        function_name: Function being audited (for match filtering).
        rule_config: Semgrep config — can be a .yaml path, rule pack, or
            inline rule written to a temp file by the caller.
        line_start: Function start line (for filtering matches to function).
        line_end: Function end line.

    Returns:
        SweepResult with outcome and matches.
    """
    escape = _check_path_containment(target_path, file_path, "semgrep")
    if escape:
        return escape

    full_path = target_path / file_path
    if not full_path.exists():
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"file not found: {full_path}"],
        )

    try:
        from packages.semgrep.runner import run_rule, is_available

        if not is_available():
            return SweepResult(
                tool="semgrep",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["semgrep not installed"],
            )

        result = run_rule(full_path, rule_config, timeout=120)

        in_function = []
        for finding in result.findings:
            if hasattr(finding, "line"):
                finding_line = finding.line
            elif isinstance(finding, dict):
                finding_line = finding.get("start", {}).get("line", 0)
            else:
                finding_line = 0
            if line_start and line_end:
                if line_start <= finding_line <= line_end:
                    in_function.append(finding)
            else:
                in_function.append(finding)

        outcome = "confirmed" if in_function else "refuted"
        serialized = []
        for f in in_function:
            if hasattr(f, "to_dict"):
                serialized.append(f.to_dict())
            elif isinstance(f, dict):
                serialized.append(f)
            else:
                serialized.append({"line": getattr(f, "line", 0),
                                   "rule_id": getattr(f, "rule_id", ""),
                                   "message": getattr(f, "message", "")})
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=serialized,
            rule_id=rule_config,
            errors=result.errors,
        )
    except Exception as exc:
        return SweepResult(
            tool="semgrep",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


def run_coccinelle_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    cocci_rule: str,
    defines: Optional[Dict[str, str]] = None,
    line_start: Optional[int] = None,
    line_end: Optional[int] = None,
    domain_vocab: Any = None,
) -> SweepResult:
    """Run a Coccinelle rule against a single C file.

    Args:
        target_path: Root of the target codebase.
        file_path: Relative path to the C source file.
        function_name: Function being audited.
        cocci_rule: Path to the .cocci rule file.
        defines: Optional spatch -D defines (e.g. {"func": "parse_input"}).

    Returns:
        SweepResult with outcome and matches.
    """
    escape = _check_path_containment(target_path, file_path, "coccinelle")
    if escape:
        return escape

    full_path = target_path / file_path
    if not full_path.exists():
        return SweepResult(
            tool="coccinelle",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"file not found: {full_path}"],
        )

    try:
        from packages.coccinelle.runner import run_rule, is_available

        if not is_available():
            return SweepResult(
                tool="coccinelle",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["coccinelle (spatch) not installed"],
            )

        effective_rule = cocci_rule
        _rendered_tmp = None
        if domain_vocab is not None:
            try:
                from engine.coccinelle.vocab_renderer import render as _render_cocci
                _rendered_tmp = _render_cocci(Path(cocci_rule), domain_vocab)
                if _rendered_tmp is not None:
                    effective_rule = str(_rendered_tmp)
            except Exception:
                pass

        try:
            result = run_rule(
                full_path,
                effective_rule,
                defines=defines or {},
                timeout=120,
            )
        finally:
            if _rendered_tmp is not None:
                _rendered_tmp.unlink(missing_ok=True)

        matches = []
        for f in result.matches:
            if hasattr(f, "to_dict"):
                matches.append(f.to_dict())
            else:
                matches.append({"raw": str(f)})

        if line_start is not None and line_end is not None:
            matches = [
                m for m in matches
                if _match_in_range(m, line_start, line_end)
            ]

        outcome = "confirmed" if matches else "refuted"
        return SweepResult(
            tool="coccinelle",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=matches,
            rule_id=cocci_rule,
            errors=result.errors if hasattr(result, "errors") else [],
        )
    except Exception as exc:
        return SweepResult(
            tool="coccinelle",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


# SMT verb names → libexec shim basenames
_SMT_VERBS = {
    "check-overflow": "raptor-smt-check-overflow",
    "check-oob": "raptor-smt-check-oob",
    "check-null-deref": "raptor-smt-check-null-deref",
    "check-overflow-to-oob": "raptor-smt-check-overflow-to-oob",
    "check-negative-bypass": "raptor-smt-check-negative-bypass",
    "validate-path": "raptor-smt-validate-path",
    "check-auth-bypass": "raptor-smt-check-auth-bypass",
    "check-lock-discipline": "raptor-smt-check-lock-discipline",
    "check-resource-leak": "raptor-smt-check-resource-leak",
    "check-null-propagation": "raptor-smt-check-null-propagation",
    "check-integer-narrowing": "raptor-smt-check-integer-narrowing",
    "check-early-release": "raptor-smt-check-early-release",
    "check-lock-domain": "raptor-smt-check-lock-domain",
    "check-toctou": "raptor-smt-check-toctou",
}

_SMT_VERB_ROLES = {
    "check-overflow": "verification",
    "check-oob": "verification",
    "check-null-deref": "verification",
    "check-overflow-to-oob": "detection",
    "check-negative-bypass": "detection",
    "validate-path": "verification",
    "check-auth-bypass": "verification",
    "check-lock-discipline": "verification",
    "check-resource-leak": "verification",
    "check-null-propagation": "verification",
    "check-integer-narrowing": "verification",
    "check-early-release": "verification",
    "check-lock-domain": "detection",
    "check-toctou": "verification",
}


def get_smt_verb_role(verb: str) -> str:
    """Return the role of an SMT verb: ``"detection"`` or ``"verification"``.

    Detection verbs identify arithmetic patterns that *could* be
    exploitable but lack domain constraints (e.g. caller-enforced
    ranges).  Verification verbs model enough semantics to be
    authoritative — their findings can promote status directly.

    Unknown verbs default to ``"detection"``.
    """
    bare = verb.split(":")[0]
    return _SMT_VERB_ROLES.get(bare, "detection")


def run_smt_sweep(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    smt_args: Dict[str, Any],
) -> SweepResult:
    """Run an SMT verb shim and classify the result.

    Args:
        file_path: Source file being audited (for logging).
        function_name: Function being audited.
        verb: SMT verb name (e.g. "check-overflow", "validate-path").
        smt_args: Dict of CLI args for the verb (keys become --key flags,
            values become their arguments). List values are serialised
            as JSON.

    Returns:
        SweepResult with outcome ``confirmed`` (sat — the condition is
        feasible) or ``refuted`` (unsat — the condition is infeasible).
    """
    shim_name = _SMT_VERBS.get(verb)
    if not shim_name:
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"unknown SMT verb {verb!r}; valid: {sorted(_SMT_VERBS)}"],
        )

    raptor_dir = Path(__file__).resolve().parents[2]
    shim_path = raptor_dir / "libexec" / shim_name
    if not shim_path.exists():
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"shim not found: {shim_path}"],
        )

    cmd = ["python3", str(shim_path)]
    import re as _re
    _safe_key_re = _re.compile(r"^[a-zA-Z][a-zA-Z0-9_-]*$")
    for key, value in smt_args.items():
        if not _safe_key_re.match(key):
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=[
                    f"invalid smt_args key {key!r}: "
                    "must be alphanumeric/underscore/hyphen"
                ],
            )
        flag = f"--{key}"
        if isinstance(value, bool):
            if value:
                cmd.append(flag)
        elif isinstance(value, list):
            for item in value:
                cmd.extend([flag, str(item)])
        elif isinstance(value, dict):
            cmd.extend([flag, _json.dumps(value)])
        else:
            cmd.extend([flag, str(value)])

    try:
        try:
            from core.config import RaptorConfig
            safe_env = RaptorConfig.get_safe_env()
        except ImportError:
            safe_env = dict(os.environ)
            for var in ("TERMINAL", "EDITOR", "VISUAL", "BROWSER", "PAGER"):
                safe_env.pop(var, None)

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            env=safe_env,
        )
        raw = proc.stdout.strip()

        if proc.returncode != 0:
            return SweepResult(
                tool="smt",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=[proc.stderr.strip() or f"exit code {proc.returncode}"],
                raw_output=raw,
                rule_id=f"smt:{verb}",
            )

        try:
            result_data = _json.loads(raw)
        except _json.JSONDecodeError:
            result_data = {"raw": raw}

        smt_result = result_data.get("result", raw.lower())
        if smt_result in ("sat", "satisfiable", "feasible"):
            outcome = "confirmed"
        elif smt_result in ("unsat", "unsatisfiable", "infeasible"):
            outcome = "refuted"
        else:
            outcome = "inconclusive"

        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=[result_data] if outcome == "confirmed" else [],
            rule_id=f"smt:{verb}",
            raw_output=raw,
        )
    except subprocess.TimeoutExpired:
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["SMT solver timed out (60s)"],
            rule_id=f"smt:{verb}",
        )
    except Exception as exc:
        return SweepResult(
            tool="smt",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
            rule_id=f"smt:{verb}",
        )


def run_smt_verb_direct(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    source: str,
    hypothesis: str,
) -> SweepResult:
    """Call an SMT verb directly from Python (no shim subprocess).

    Extracts operands from the hypothesis text and calls the verb
    function.  Falls back to inconclusive if operands can't be extracted
    or Z3 is unavailable.

    Runs in a forked subprocess so Z3 assertion failures (segfaults in
    the C++ core) return inconclusive instead of killing the parent.
    """
    return _smt_verb_in_subprocess(
        file_path=file_path,
        function_name=function_name,
        verb=verb,
        source=source,
        hypothesis=hypothesis,
    )


_SMT_VERB_CHILD_SCRIPT = (
    "import sys,os,pickle\n"
    "sys.path.insert(0,os.environ['RAPTOR_DIR'])\n"
    "from core.audit.sweep import _run_smt_verb_inner\n"
    "r=_run_smt_verb_inner(**pickle.loads(sys.stdin.buffer.read()))\n"
    "sys.stdout.buffer.write(pickle.dumps(r))\n"
)


def _smt_verb_in_subprocess(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    source: str,
    hypothesis: str,
    timeout: int = 10,
) -> SweepResult:
    """Run SMT verb in an isolated subprocess.

    Uses subprocess.Popen (fork+exec) rather than bare os.fork() so the
    child gets a clean, single-threaded process image -- safe when the
    parent has worker threads.
    """
    payload = pickle.dumps({
        "file_path": file_path,
        "function_name": function_name,
        "verb": verb,
        "source": source,
        "hypothesis": hypothesis,
    })
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _SMT_VERB_CHILD_SCRIPT],
            input=payload, capture_output=True, timeout=timeout,
        )
        if proc.returncode == 0:
            try:
                sr = pickle.loads(proc.stdout)
                if isinstance(sr, SweepResult):
                    return sr
            except Exception:
                pass
        logger.warning(
            "SMT subprocess exited %d for %s:%s verb=%s",
            proc.returncode, file_path, function_name, verb,
        )
    except subprocess.TimeoutExpired:
        logger.warning(
            "SMT subprocess timed out for %s:%s verb=%s",
            file_path, function_name, verb,
        )
    return SweepResult(
        tool="smt", file_path=file_path,
        function_name=function_name, outcome="inconclusive",
        errors=["Z3 subprocess crashed or timed out"],
        rule_id=f"smt:{verb}",
    )


def _run_smt_verb_inner(
    *,
    file_path: str,
    function_name: str,
    verb: str,
    source: str,
    hypothesis: str,
) -> SweepResult:
    """Actual SMT verb execution (runs inside forked child)."""
    try:
        if verb == "check-negative-bypass":
            from packages.exploit_feasibility.smt_verbs import check_negative_bypass
            value, limit = _extract_negative_bypass_operands(hypothesis, source)
            if not value or not limit:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_negative_bypass(value, limit, profile="int32")
        elif verb == "check-null-deref":
            from packages.exploit_feasibility.smt_verbs import check_null_deref
            ptr = _extract_ptr_operand(hypothesis)
            if not ptr:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_null_deref(ptr, profile="uint64")
        elif verb == "check-overflow":
            if _lang_has_overflow_safety(file_path):
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            from packages.exploit_feasibility.smt_verbs import check_overflow
            operands = _extract_arithmetic_operands(hypothesis, source)
            if len(operands) < 2:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_overflow(operands, "+", profile="uint32")
            if result.get("feasible") and not any(
                _re.search(
                    r"\b" + _re.escape(op) + r"\b.*[<>!=]=?",
                    source,
                )
                for op in operands
            ):
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                    details={"summary": "overflow feasible but no source-level guards on operands"},
                )
        elif verb == "check-oob":
            if _lang_has_overflow_safety(file_path):
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            from packages.exploit_feasibility.smt_verbs import check_oob
            index, size = _extract_oob_operands(hypothesis, source)
            if not index or not size:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_oob(size, index, profile="uint64")
        elif verb == "check-overflow-to-oob":
            from packages.exploit_feasibility.smt_verbs import check_overflow_to_oob
            count, elem_size, index = _extract_overflow_to_oob_operands(
                hypothesis, source,
            )
            if not count or not elem_size or not index:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = check_overflow_to_oob(count, elem_size, index, profile="uint32")
        elif verb == "check-auth-bypass":
            from core.audit.condition_smt import check_auth_bypass
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            auth_result = check_auth_bypass(source)
            if auth_result.bypass_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=auth_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=auth_result.to_dict(),
            )
        elif verb == "check-integer-narrowing":
            from core.audit.condition_smt import check_integer_narrowing
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            narr_result = check_integer_narrowing(source)
            if narr_result.narrowing_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=narr_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=narr_result.to_dict(),
            )
        elif verb == "check-lock-discipline":
            from core.audit.condition_smt import check_lock_discipline
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            lock_result = check_lock_discipline(source)
            if lock_result.violation_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=lock_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=lock_result.to_dict(),
            )
        elif verb == "check-null-propagation":
            from core.audit.condition_smt import check_null_propagation
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            null_result = check_null_propagation(source)
            if null_result.null_deref_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=null_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=null_result.to_dict(),
            )
        elif verb == "check-resource-leak":
            from core.audit.condition_smt import check_resource_leak
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            leak_result = check_resource_leak(source)
            if leak_result.leak_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=leak_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=leak_result.to_dict(),
            )
        elif verb == "check-early-release":
            from core.audit.condition_smt import check_early_release
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            er_result = check_early_release(source)
            if er_result.early_release_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=er_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=er_result.to_dict(),
            )
        elif verb == "check-lock-domain":
            from core.audit.condition_smt import check_lock_domain
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            ld_result = check_lock_domain(source)
            if ld_result.mismatch_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=ld_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=ld_result.to_dict(),
            )
        elif verb == "check-toctou":
            from core.audit.condition_smt import check_toctou
            if not source:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            tt_result = check_toctou(source)
            if tt_result.toctou_found:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="confirmed",
                    rule_id=f"smt:{verb}",
                    details=tt_result.to_dict(),
                )
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="refuted",
                rule_id=f"smt:{verb}",
                details=tt_result.to_dict(),
            )
        elif verb == "validate-path":
            from packages.exploit_feasibility.smt_path import validate_path
            conditions = _extract_path_conditions(hypothesis, source)
            if not conditions:
                return SweepResult(
                    tool="smt", file_path=file_path,
                    function_name=function_name, outcome="inconclusive",
                    rule_id=f"smt:{verb}",
                )
            result = validate_path(conditions)
        else:
            return SweepResult(
                tool="smt", file_path=file_path,
                function_name=function_name, outcome="inconclusive",
                errors=[f"no direct caller for verb {verb!r}"],
                rule_id=f"smt:{verb}",
            )

        feasible = result.get("feasible")
        if feasible is True:
            outcome = "confirmed"
        elif feasible is False:
            outcome = "refuted"
        else:
            outcome = "inconclusive"

        return SweepResult(
            tool="smt", file_path=file_path,
            function_name=function_name, outcome=outcome,
            matches=[result] if outcome == "confirmed" else [],
            rule_id=f"smt:{verb}",
            raw_output=_json.dumps(result),
        )
    except Exception as exc:
        return SweepResult(
            tool="smt", file_path=file_path,
            function_name=function_name, outcome="error",
            errors=[str(exc)], rule_id=f"smt:{verb}",
        )


_IDENT_RE = __import__("re").compile(r"[a-z_][a-z0-9_]*", __import__("re").IGNORECASE)


def _extract_negative_bypass_operands(
    hypothesis: str, source: str,
) -> tuple:
    """Extract (value, limit) from hypothesis like 'negative msg_qbytes bypasses size check'."""
    import re
    hyp = hypothesis.lower()
    m = re.search(
        r"negative\s+(?:value\s+(?:for\s+)?)?(?:the\s+)?[`'\"]?(\w+)[`'\"]?",
        hyp,
    )
    value = m.group(1) if m else None

    m = re.search(
        r"(?:bypass|exceed|circumvent)\w*\s+(?:the\s+)?[`'\"]?(\w+)[`'\"]?\s+(?:check|limit|bound)",
        hyp,
    )
    if m:
        limit = m.group(1)
    else:
        identifiers = _IDENT_RE.findall(source)
        limit_candidates = [
            i for i in identifiers
            if any(kw in i.lower() for kw in ("limit", "max", "size", "bound", "rlim"))
        ]
        limit = limit_candidates[0] if limit_candidates else None

    if value and not _IDENT_RE.fullmatch(value):
        value = None
    if limit and not _IDENT_RE.fullmatch(limit):
        limit = None

    return value, limit


_OVERFLOW_SAFE_EXTS = frozenset({".go", ".py", ".rs", ".java"})


def _lang_has_overflow_safety(file_path: str) -> bool:
    """Languages where unconstrained SMT overflow/OOB checks are meaningless."""
    from pathlib import Path
    return Path(file_path).suffix in _OVERFLOW_SAFE_EXTS


def _operand_in_source_arithmetic(operand: str, source: str) -> bool:
    """Check if *operand* appears adjacent to an arithmetic operator in source."""
    import re
    cleaned = re.sub(
        r'//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'',
        " ", source, flags=re.DOTALL,
    )
    pat = rf"(?:\b{re.escape(operand)}\b\s*[+\-*/%]|[+\-*/%]\s*\b{re.escape(operand)}\b)"
    return bool(re.search(pat, cleaned))


def _extract_ptr_operand(hypothesis: str) -> Optional[str]:
    """Extract pointer name from hypothesis like 'NULL pointer dereference of ptr'."""
    import re
    m = re.search(r"[`'\"]?(\w+)[`'\"]?\s+(?:is\s+)?(?:null|NULL)", hypothesis)
    if m and _IDENT_RE.fullmatch(m.group(1)):
        return m.group(1)
    m = re.search(r"(?:null|NULL)\s+(?:pointer\s+)?(?:dereference\s+)?(?:of\s+)?[`'\"]?(\w+)[`'\"]?", hypothesis)
    if m and _IDENT_RE.fullmatch(m.group(1)):
        return m.group(1)
    return None


def _extract_arithmetic_operands(
    hypothesis: str, source: str,
) -> list:
    """Extract operand identifiers from hypothesis about integer overflow.

    After extracting candidates from hypothesis text, verifies each
    actually participates in an arithmetic expression in the source.
    """
    import re
    backtick_ids = re.findall(r"`(\w+)`", hypothesis)
    if len(backtick_ids) >= 2:
        raw = [i for i in backtick_ids[:3] if _IDENT_RE.fullmatch(i)]
    else:
        ids = _IDENT_RE.findall(hypothesis)
        raw = [
            i for i in ids
            if i.lower() not in {
                "integer", "overflow", "the", "in", "of", "can", "cause",
                "value", "large", "leading", "to", "size", "check", "a",
                "an", "this", "that", "with", "from", "by", "for", "is",
            }
        ]
        raw = raw[:3]
    if source:
        verified = [c for c in raw if _operand_in_source_arithmetic(c, source)]
        return verified[:2]
    return raw[:2]


def _extract_oob_operands(
    hypothesis: str, source: str,
) -> tuple:
    """Extract (index, size) from hypothesis about out-of-bounds access."""
    import re
    m = re.search(r"[`'\"]?(\w+)[`'\"]?\s+(?:is\s+)?(?:used\s+)?(?:as\s+)?(?:an?\s+)?(?:array\s+)?index", hypothesis.lower())
    index = m.group(1) if m and _IDENT_RE.fullmatch(m.group(1)) else None

    m = re.search(r"(?:array|buffer)\s+(?:of\s+)?(?:size\s+)?[`'\"]?(\w+)[`'\"]?", hypothesis.lower())
    if m and _IDENT_RE.fullmatch(m.group(1)):
        size = m.group(1)
    else:
        ids = _IDENT_RE.findall(source)
        size_candidates = [
            i for i in ids
            if any(kw in i.lower() for kw in ("size", "len", "count", "num", "nsems"))
        ]
        size = size_candidates[0] if size_candidates else None

    return index, size


_PROSE_STOP_WORDS = frozenset({
    "a", "an", "and", "are", "as", "at", "be", "but", "by", "can",
    "cause", "check", "could", "do", "does", "for", "from", "has",
    "have", "if", "in", "into", "is", "it", "its", "leading", "may",
    "no", "not", "of", "on", "or", "overflow", "so", "the", "that",
    "then", "this", "to", "via", "was", "when", "which", "will",
    "with", "without", "would", "writes", "integer", "large", "value",
})


def _extract_overflow_to_oob_operands(
    hypothesis: str, source: str,
) -> tuple:
    """Extract (count, element_size, index) for CWE-680 check."""
    import re
    backtick_ids = re.findall(r"`(\w+)`", hypothesis)
    if len(backtick_ids) >= 3:
        valid = [i for i in backtick_ids[:3] if _IDENT_RE.fullmatch(i)]
        if len(valid) == 3:
            return tuple(valid)

    ids = [
        i for i in _IDENT_RE.findall(hypothesis)
        if i.lower() not in _PROSE_STOP_WORDS and len(i) > 1
    ]
    count_kw = ("count", "num", "nelem", "nitems")
    size_kw = ("size", "elem_size", "element_size", "stride", "width")
    idx_kw = ("index", "idx", "offset")

    count = next(
        (i for i in ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in count_kw)), None,
    )
    elem = next(
        (i for i in ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in size_kw)), None,
    )
    index = next(
        (i for i in ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in idx_kw)), None,
    )

    if not count:
        src_ids = [
            i for i in _IDENT_RE.findall(source)
            if i.lower() not in _PROSE_STOP_WORDS and len(i) > 1
        ]
        count = next(
            (i for i in src_ids if any(k == i.lower() or i.lower().startswith(k + "_") or i.lower().endswith("_" + k) for k in count_kw)), None,
        )
    if not elem:
        elem = "4"

    return count, elem, index


def _extract_path_conditions(
    hypothesis: str, source: str,
) -> list:
    """Extract condition strings for validate-path from hypothesis text.

    Looks for backtick-quoted expressions first, then falls back to
    quoted conditions or simple relational expressions.
    """
    import re
    backtick_conds = re.findall(r"`([^`]*[<>=!]+[^`]*)`", hypothesis)
    if backtick_conds:
        return backtick_conds

    quoted_conds = re.findall(r'"([^"]*[<>=!]+[^"]*)"', hypothesis)
    if quoted_conds:
        return quoted_conds

    relational = re.findall(
        r"(\w+\s*(?:[<>=!]=?|!=)\s*\w+)", hypothesis,
    )
    return relational or []


def run_codeql_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    query_path: str,
    database_path: Optional[str] = None,
    line_start: int = 0,
    line_end: int = 0,
) -> SweepResult:
    """Run a CodeQL query against a database and classify matches.

    Args:
        target_path: Root of the target codebase.
        file_path: Relative path to the source file being audited.
        function_name: Function being audited.
        query_path: Path to the .ql query file.
        database_path: Path to the CodeQL database. If None, attempts
            to find one under ``target_path``.
        line_start: Function start line (for match filtering).
        line_end: Function end line.

    Returns:
        SweepResult with outcome based on whether any matches fall
        within the target function.
    """
    qpath = Path(query_path)
    if not qpath.exists():
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"query file not found: {query_path}"],
        )

    try:
        from core.dataflow.codeql_augmented_run import analyze

        db = database_path
        if not db:
            for candidate in (
                target_path / "codeql-db",
                target_path / ".codeql" / "db",
                target_path / "codeql-database",
            ):
                if candidate.is_dir():
                    db = str(candidate)
                    break

        if not db:
            return SweepResult(
                tool="codeql",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=["no CodeQL database found; build one first"],
            )

        result = analyze(
            database=db,
            query=str(qpath),
            timeout=300,
        )

        if result.get("error"):
            return SweepResult(
                tool="codeql",
                file_path=file_path,
                function_name=function_name,
                outcome="error",
                errors=[result["error"]],
            )

        sarif_results = result.get("results", [])
        in_function = []
        for r in sarif_results:
            locs = r.get("locations") or [{}]
            loc = locs[0] if locs else {}
            phys = loc.get("physicalLocation", {})
            art = phys.get("artifactLocation", {}).get("uri", "")
            region = phys.get("region", {})
            rline = region.get("startLine", 0)

            if art.endswith("/" + file_path) or art == file_path:
                if line_start and line_end:
                    if line_start <= rline <= line_end:
                        in_function.append(r)
                else:
                    in_function.append(r)

        outcome = "confirmed" if in_function else "refuted"
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome=outcome,
            matches=in_function,
            rule_id=query_path,
        )
    except ImportError:
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["core.dataflow.codeql_augmented_run not available"],
        )
    except Exception as exc:
        return SweepResult(
            tool="codeql",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


def run_consistency_check(
    *,
    target_path: Path,
    function_name: str,
    cocci_rule: str,
    domain_vocab: Any = None,
) -> SweepResult:
    """Run a Coccinelle consistency check across the entire target.

    The design pattern: "9/10 callers check return, find the 10th."
    Runs a parametric Coccinelle rule with -D func=<function_name>
    against the full target tree to find callers that violate a
    consistency pattern (e.g. unchecked return value).

    Unlike run_coccinelle_sweep (single file), this scans the whole
    codebase — it's the Mode 2 (checker synthesis) pattern applied
    to inconsistency detection.

    Args:
        target_path: Root of the target codebase.
        function_name: Function whose callers to check.
        cocci_rule: Path to the .cocci rule file. Must accept
            -D func=<name> for parametric matching.

    Returns:
        SweepResult with matches being the inconsistent call sites.
    """
    if not is_valid_identifier(function_name):
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome="error",
            errors=[f"invalid function name for -D define: {function_name!r}"],
        )

    try:
        from packages.coccinelle.runner import run_rule, is_available

        if not is_available():
            return SweepResult(
                tool="coccinelle_consistency",
                file_path="<codebase>",
                function_name=function_name,
                outcome="error",
                errors=["coccinelle (spatch) not installed"],
            )

        effective_rule = cocci_rule
        _rendered_tmp = None
        if domain_vocab is not None:
            try:
                from engine.coccinelle.vocab_renderer import render as _render_cocci
                _rendered_tmp = _render_cocci(Path(cocci_rule), domain_vocab)
                if _rendered_tmp is not None:
                    effective_rule = str(_rendered_tmp)
            except Exception:
                pass

        try:
            result = run_rule(
                target_path,
                effective_rule,
                defines={"func": function_name},
                timeout=300,
            )
        finally:
            if _rendered_tmp is not None:
                _rendered_tmp.unlink(missing_ok=True)

        matches = []
        for match in result.matches:
            if hasattr(match, "to_dict"):
                matches.append(match.to_dict())
            else:
                matches.append({"raw": str(match)})

        outcome = "confirmed" if matches else "refuted"
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome=outcome,
            matches=matches,
            rule_id=cocci_rule,
        )
    except ImportError:
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome="error",
            errors=["coccinelle package not available"],
        )
    except Exception as exc:
        return SweepResult(
            tool="coccinelle_consistency",
            file_path="<codebase>",
            function_name=function_name,
            outcome="error",
            errors=[str(exc)],
        )


# ── Joern CPG sweep ─────────────────────────────────────────────────


def run_joern_sweep(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    source_param: str,
    sink_call: str,
    cpg=None,
    timeout: int = 300,
) -> SweepResult:
    """Run a Joern taint query for a specific function.

    If cpg is provided, reuses it. If not, returns an error (CPG
    should be built once per run via run_joern_pre_sweep).
    """
    escape = _check_path_containment(target_path, file_path, "joern")
    if escape:
        return escape

    if not is_valid_identifier(function_name):
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"invalid function name: {function_name!r}"],
        )

    if not _is_valid_qualified(source_param):
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"invalid source_param: {source_param!r}"],
        )

    if not _is_valid_qualified(sink_call):
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=[f"invalid sink_call: {sink_call!r}"],
        )

    try:
        from packages.joern.runner import run_taint_query
    except ImportError:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["joern package not available"],
        )

    if cpg is None:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=["no CPG provided (build via run_joern_pre_sweep)"],
        )

    # Use per-language max_call_depth_targeted instead of the
    # hardcoded default (2) -- deeper languages like C need depth 3.
    try:
        from packages.joern.lang_config import detect_language, profile_for
        _lang = detect_language(file_path)
        _depth = profile_for(_lang).max_call_depth_targeted
    except Exception:
        _depth = 2

    flows = run_taint_query(
        cpg,
        function_name,
        sink_call,
        source_param=source_param,
        timeout=timeout,
        max_call_depth=_depth,
    )

    if flows:
        matches = [f.to_dict() for f in flows]
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=matches,
            rule_id=f"joern:taint:{function_name}->{sink_call}",
        )

    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=f"joern:taint:{function_name}->{sink_call}",
    )


def run_joern_pre_sweep(
    target_path: Path,
    checklist: dict,
    cache_dir: Optional[Path] = None,
    on_progress: Optional[Callable] = None,
    stall_timeout: int = 600,
    query_timeout: int = 300,
    heap_mb: Optional[int] = None,
    server=None,
) -> Dict[str, list]:
    """Run standard taint queries before the LLM loop.

    Builds the CPG once and runs the standard_sinks.sc query.
    Returns per-function flows keyed by "file:function".
    When cache_dir is set, reuses a cached CPG if fresh.
    When server is provided, uses the already-running JoernServer.

    Returns {} when joern is unavailable.
    """
    try:
        from packages.joern.prereqs import is_available
        from packages.joern.runner import (
            build_cpg,
            build_cpg_cached,
            cleanup_cpg,
            run_query,
        )
    except ImportError:
        logger.debug("joern package not importable; skipping pre-sweep")
        return {}

    if server is None and not is_available():
        logger.debug("joern not available on PATH; skipping pre-sweep")
        return {}

    target_path = Path(target_path)
    if not target_path.is_dir():
        return {}

    queries_dir = Path(__file__).resolve().parents[2] / "packages" / "joern" / "queries"
    sinks_script = queries_dir / "standard_sinks.sc"
    if not sinks_script.exists():
        logger.warning("standard_sinks.sc not found at %s", sinks_script)
        return {}

    if server is not None:
        result = server.query_script(sinks_script, timeout=query_timeout)
        if result.errors:
            logger.warning("joern pre-sweep errors: %s", result.errors)

        flows_by_key: Dict[str, list] = {}
        for flow in result.flows:
            if flow.steps:
                step_file = flow.steps[0].file
                if safe_join(target_path, step_file) is None:
                    logger.debug("joern flow step has unsafe path: %s", step_file)
                    continue
                key = f"{step_file}:{flow.source_method}"
                flows_by_key.setdefault(key, []).append(flow)
        return flows_by_key

    build_kwargs = {"timeout": stall_timeout, "on_progress": on_progress}
    if heap_mb is not None:
        build_kwargs["heap_mb"] = heap_mb

    if cache_dir is not None:
        cpg = build_cpg_cached(target_path, cache_dir, **build_kwargs)
    else:
        cpg = build_cpg(target_path, **build_kwargs)
    if not cpg.exists():
        logger.warning("CPG build produced no output")
        return {}

    try:
        result = run_query(cpg, str(sinks_script), timeout=query_timeout)
        if result.errors:
            logger.warning("joern pre-sweep errors: %s", result.errors)

        flows_by_key: Dict[str, list] = {}
        for flow in result.flows:
            if flow.steps:
                step_file = flow.steps[0].file
                if safe_join(target_path, step_file) is None:
                    logger.debug("joern flow step has unsafe path: %s", step_file)
                    continue
                key = f"{step_file}:{flow.source_method}"
                flows_by_key.setdefault(key, []).append(flow)

        return flows_by_key
    finally:
        cleanup_cpg(cpg)


_MECHANICAL_CHECK_PATTERNS: Dict[str, str] = {
    "unchecked return": (
        "$X = $FUNC(...);\n"
        "...\n"
        "// ERROR: missing NULL check on $X"
    ),
    "missing null check": (
        "$X = $FUNC(...);\n"
        "...\n"
        "// ERROR: no null check on $X before use"
    ),
    "missing bounds check": (
        "$BUF[$IDX]\n"
        "// ERROR: index $IDX not bounds-checked"
    ),
    "format string": (
        "printf($FMT, ...);\n"
        "// ERROR: format string from user input"
    ),
}


def mechanical_check_to_semgrep(check: str) -> Optional[str]:
    """Map a mechanical_check string to a Semgrep pattern.

    Returns the pattern string if the check maps to a known shape,
    None otherwise.
    """
    check_lower = check.lower().strip()
    for keyword, pattern in _MECHANICAL_CHECK_PATTERNS.items():
        if keyword in check_lower:
            return pattern
    return None
