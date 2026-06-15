#!/usr/bin/env python3
"""
RAPTOR Truly Autonomous Security Agent

This agent provides TRUE agentic behaviour with NO templates:
1. LLM-powered vulnerability analysis
2. Context-aware exploit generation
3. Intelligent patch creation
4. Multi-model support (Claude, GPT-4, Ollama/DeepSeek/Qwen)
5. Automatic fallback and cost optimisation

"""

import argparse
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Also run as standalone subprocess: python3 packages/llm_analysis/agent.py
sys.path.insert(0, str(Path(__file__).parents[2]))  # repo root

from core.json import load_json, save_json
from core.config import RaptorConfig
from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE, SandboxSetupError
from core.llm.task_types import TaskType
from core.logging import get_logger
from core.progress import HackerProgress
from core.run.output import unique_run_suffix
from core.sarif.parser import parse_sarif_findings, deduplicate_findings
from core.inventory.lookup import lookup_function as _lookup_function
from core.llm.client import LLMClient, _is_auth_error
from core.llm.config import LLMConfig
from core.llm.detection import detect_llm_availability
from core.llm.providers import ClaudeCodeProvider

logger = get_logger()


def _file_matches_globs(file_path: str, globs: List[str]) -> bool:
    """True if ``file_path`` matches any glob in ``globs`` (fnmatch OR)."""
    import fnmatch as _fnmatch
    return any(_fnmatch.fnmatch(file_path or "", g) for g in globs)


def apply_prefer_globs(
    findings: List[Dict[str, Any]],
    prefer_globs: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """Re-bucket findings: matches sort to the front, others keep their
    relative order. Stable within each bucket so existing ordering
    (dataflow-prioritised, then SARIF-order) survives — operator can
    tell from a diff which findings shifted positions on a re-run.

    No-op when ``prefer_globs`` is None/empty. Findings with no
    ``file_path`` are treated as non-matching and end up in the
    ``others`` bucket — the empty-string fnmatch against any non-empty
    glob returns False, so they stay where they were.
    """
    if not prefer_globs:
        return findings
    preferred: List[Dict[str, Any]] = []
    others: List[Dict[str, Any]] = []
    for f in findings:
        if _file_matches_globs(f.get("file_path", ""), prefer_globs):
            preferred.append(f)
        else:
            others.append(f)
    return preferred + others


def _dir_to_glob(d: str) -> str:
    """Convert a catalog directory path (``src/http``) to an
    fnmatch glob that matches files inside it (``src/http/*``).
    Already-glob entries (``src/device/sysdep_*``) pass through
    unchanged.

    fnmatch ``*`` is greedy across ``/`` (per Python's
    ``fnmatch.translate``), so ``src/http/*`` matches both
    ``src/http/server.c`` AND ``src/http/foo/bar.c`` — no need
    for ``src/http/**`` or similar.
    """
    if "*" in d:
        return d
    return d.rstrip("/") + "/*"


def resolve_prefer_globs(
    operator_globs: Optional[List[str]],
    repo_path: Optional[Path],
) -> tuple:
    """Resolve the effective attack-surface prefer-globs for an
    /agentic run. Operator-supplied globs win unconditionally;
    when absent, fall back to the target-type catalog's
    ``attack_surface.high_priority_dirs`` for the matched target
    type.

    Returns ``(effective_globs, source_label)`` where
    ``source_label`` is for the operator-facing log line
    (``--prefer`` or ``catalog '<name>'``); both are None when
    neither operator nor catalog supplied anything (operator
    didn't pass --prefer AND no catalog entry matched, or repo_path
    is missing entirely).

    Module-level (rather than agent-method) so unit tests can
    drive it without instantiating the full AutonomousSecurityAgentV2
    (which pulls in LLMConfig, scorecard, sandbox, etc.).
    """
    if operator_globs:
        return list(operator_globs), "--prefer"
    if not repo_path:
        return None, None
    try:
        from core.run.target_types import load
        entry = load(Path(repo_path))
    except Exception:  # noqa: BLE001
        # Catalog substrate is best-effort; never fail the agent
        # on a catalog-load issue.
        return None, None
    if entry is None or not entry.attack_surface_high:
        return None, None
    globs = [_dir_to_glob(d) for d in entry.attack_surface_high]
    return globs, f"catalog '{entry.name}'"


def apply_exclude_dir_globs(
    findings: List[Dict[str, Any]],
    exclude_globs: Optional[List[str]],
) -> List[Dict[str, Any]]:
    """Drop findings whose ``file_path`` matches any glob in
    ``exclude_globs``. Order-preserving. Operator escape hatch for
    cases the structural filters (binary-oracle, dataflow priority)
    can't help with: vendored third-party code in the target tree,
    test fixtures, generated dirs.

    No-op when ``exclude_globs`` is None/empty. Findings with no
    ``file_path`` are kept (defensively — operator excludes shouldn't
    accidentally drop findings whose path metadata is malformed; if
    that happens the operator wants to see them, not have them
    silently filtered).
    """
    if not exclude_globs:
        return findings
    return [
        f for f in findings
        if not _file_matches_globs(f.get("file_path", ""), exclude_globs)
    ]


def _enrich_finding_with_ast_view(
    finding: Dict[str, Any], repo_path: Path,
) -> None:
    """Attach a compact per-function AST view to ``finding["ast_view"]``.

    Mutates ``finding`` in-place. Idempotent — a pre-existing
    ``ast_view`` is preserved (caller-supplied or earlier-run wins).
    Best-effort: parse failure / unsupported language / function not
    in inventory / file missing all leave ``finding["ast_view"]``
    unset and the prompt builder's ``ast-view`` block is skipped.

    Function name resolution order:
      1. ``finding["metadata"]["name"]`` (set by the inventory
         enrichment block that runs just before this).
      2. ``finding["function"]`` (some scanners set this directly).
      3. Otherwise → no enrichment.

    File-path resolution:
      * Absolute paths pass through.
      * Relative paths resolve under ``repo_path``.

    Runs once per finding before any LLM call sees it; the four
    analysis-family tasks (Analysis, Consensus, Judge, Retry) all
    share the result via
    ``build_analysis_prompt_bundle_from_finding`` reading
    ``finding["ast_view"]``.
    """
    if finding.get("ast_view"):
        return
    fpath = finding.get("file_path") or finding.get("file") or ""
    fline = (
        finding.get("start_line")
        if finding.get("start_line") is not None
        else finding.get("startLine", 0)
    )
    metadata = finding.get("metadata") or {}
    function_name = (
        metadata.get("name")
        or finding.get("function")
        or ""
    )
    if not (function_name and fpath):
        return
    try:
        # Lazy-import keeps the agent.py module load light when
        # core.ast / tree-sitter grammars aren't installed (the
        # ImportError shouldn't break the whole agent).
        from core.ast import view as _view
    except ImportError:
        logger.debug("ast_view enrichment: core.ast not importable")
        return
    try:
        fp = Path(fpath)
        if not fp.is_absolute():
            fp = repo_path / fp
        fv = _view(fp, function_name, at_line=fline)
        if fv is not None:
            finding["ast_view"] = fv.to_dict()
    except Exception:                                       # noqa: BLE001
        logger.debug(
            "ast_view enrichment failed for %s:%s %s",
            fpath, fline, function_name,
            exc_info=True,
        )


def get_vuln_type(rule_id: str) -> Optional[str]:
    """Map SARIF rule_id to vulnerability type for mitigation checks."""
    try:
        from packages.exploit_feasibility import get_vuln_type_for_rule
        return get_vuln_type_for_rule(rule_id)
    except ImportError:
        return None


class VulnerabilityContext:
    """Represents a vulnerability with full context for autonomous analysis."""

    def __init__(self, finding: Dict[str, Any], repo_path: Path):
        self.finding = finding
        self.repo_path = repo_path
        self.finding_id = finding.get("finding_id")
        self.rule_id = finding.get("rule_id")
        self.file_path = finding.get("file")
        self.start_line = finding.get("startLine")
        self.end_line = finding.get("endLine")
        self.snippet = finding.get("snippet")
        self.message = finding.get("message")
        self.level = finding.get("level", "warning")
        self.cwe_id = finding.get("cwe_id")
        self.tool = finding.get("tool")

        # Dataflow analysis fields
        self.has_dataflow: bool = finding.get("has_dataflow", False)
        self.dataflow_path: Optional[Dict[str, Any]] = finding.get("dataflow_path")
        self.dataflow_source: Optional[Dict[str, Any]] = None
        self.dataflow_sink: Optional[Dict[str, Any]] = None
        self.dataflow_steps: List[Dict[str, Any]] = []
        self.sanitizers_found: List[str] = []

        # Function metadata from inventory (if available)
        self.metadata: Optional[Dict[str, Any]] = finding.get("metadata")

        # Feasibility data from validation pipeline (if available)
        from packages.exploitability_validation.models import Feasibility
        self.feasibility: Dict[str, Any] = Feasibility.from_dict(finding.get("feasibility")).to_dict()
        self.attack_path_ref: Optional[str] = self.feasibility.get("attack_path_ref")

        # Will be populated by LLM analysis
        self.full_code: Optional[str] = None
        self.surrounding_context: Optional[str] = None
        self.exploitable: bool = False
        self.exploitability_score: float = 0.0
        self.exploit_code: Optional[str] = None
        # Compilation-verification result for ``exploit_code``. ``None``
        # means verification was not attempted (no LLM exploit emitted,
        # or compiler unavailable / skipped); ``True`` / ``False``
        # reflect gcc's verdict in a sandbox.
        # ``exploit_compile_errors`` carries the parsed compiler
        # diagnostics when compilation fails — preserved so
        # downstream consumers (reporting, /validate, future
        # refinement loop) can see why the LLM's exploit didn't
        # build. Empty list means "no errors observed" or
        # "compilation not attempted".
        self.exploit_compiled: Optional[bool] = None
        self.exploit_compile_errors: List[str] = []
        # Intent-match verdict on ``exploit_code`` — whether the
        # LLM-emitted exploit targets THIS finding or hit a
        # different bug / didn't engage at all. Produced by
        # ``packages.llm_analysis.intent_match.intent_match`` and
        # stored as a dict (the dataclass's ``asdict()`` form) so
        # ``to_dict()`` can serialise it cleanly. ``None`` means the
        # judge was not invoked (no exploit produced, or
        # ``--no-judge-intent`` opt-out).
        self.intent_match: Optional[Dict[str, Any]] = None
        self.patch_code: Optional[str] = None
        self.analysis: Optional[Dict[str, Any]] = None

    def get_full_file_path(self) -> Optional[Path]:
        """Get absolute path to vulnerable file."""
        if not self.file_path:
            return None
        clean_path = self.file_path.replace("file://", "")
        return self.repo_path / clean_path

    def read_vulnerable_code(self) -> bool:
        """Read the actual vulnerable code from the file."""
        file_path = self.get_full_file_path()
        if not file_path or not file_path.exists():
            logger.warning(f"Cannot read file: {file_path}")
            return False

        # Cap source-file read at 10 MB. Pre-fix `f.readlines()`
        # loaded the whole file into memory before any size check —
        # a generated source file (single-line concatenated bundle,
        # vendored data file misclassified as code, hostile target
        # repo with a giant binary mislabeled as `.c`) would
        # OOM-kill the analyser. Real C/C++/Java/Python source files
        # are well under 1 MB; 10 MB leaves headroom for unusually
        # large generated parsers / lexers while bounding
        # pathological input. Truncated reads still return True so
        # the agent can analyse the visible portion.
        _MAX_SOURCE_BYTES = 10 * 1024 * 1024
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(_MAX_SOURCE_BYTES + 1)
            if len(content) > _MAX_SOURCE_BYTES:
                logger.warning(
                    f"Source file {file_path} exceeded "
                    f"{_MAX_SOURCE_BYTES}-byte cap; analysis sees "
                    f"truncated content"
                )
                content = content[:_MAX_SOURCE_BYTES]
            lines = content.splitlines(keepends=True)

            # Get the specific vulnerable lines
            if self.start_line and self.end_line:
                start_idx = max(0, self.start_line - 1)
                end_idx = min(len(lines), self.end_line)
                self.full_code = "".join(lines[start_idx:end_idx])

                # Get surrounding context (50 lines before and after)
                context_start = max(0, start_idx - 50)
                context_end = min(len(lines), end_idx + 50)
                self.surrounding_context = "".join(lines[context_start:context_end])
            else:
                # If no line numbers, take first 100 lines
                self.full_code = "".join(lines[:100])
                self.surrounding_context = self.full_code

            return True
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return False

    def _read_code_at_location(self, file_uri: str, line: int, context_lines: int = 5) -> str:
        """
        Read code at a specific location with surrounding context.

        Args:
            file_uri: File URI from SARIF
            line: Line number (1-indexed)
            context_lines: Number of lines before/after to include

        Returns:
            Code snippet with context
        """
        try:
            # Clean up the file URI and validate path stays within repo
            clean_path = file_uri.replace("file://", "")
            file_path = (self.repo_path / clean_path).resolve()

            try:
                file_path.relative_to(self.repo_path.resolve())
            except ValueError:
                return f"[Path traversal blocked: {file_uri}]"

            if not file_path.exists():
                return f"[File not found: {file_uri}]"

            # Same byte cap as read_vulnerable_code above. Same
            # rationale: bound the in-flight memory regardless of
            # source-file size.
            _MAX_SOURCE_BYTES = 10 * 1024 * 1024
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read(_MAX_SOURCE_BYTES + 1)
            if len(content) > _MAX_SOURCE_BYTES:
                content = content[:_MAX_SOURCE_BYTES]
            lines = content.splitlines(keepends=True)

            # Get context around the line
            start = max(0, line - context_lines - 1)
            end = min(len(lines), line + context_lines)

            context = []
            for i in range(start, end):
                marker = ">>>" if i == line - 1 else "   "
                context.append(f"{marker} {i + 1:4d} | {lines[i].rstrip()}")

            return "\n".join(context)

        except Exception as e:
            return f"[Error reading code: {e}]"

    def _is_sanitizer(self, label: str) -> bool:
        """
        Heuristic to identify if a dataflow step is a sanitizer.

        Args:
            label: Step label from SARIF

        Returns:
            True if this looks like a sanitizer
        """
        sanitizer_keywords = [
            'sanitiz', 'validat', 'filter', 'escape', 'encode',
            'clean', 'strip', 'remove', 'replace', 'whitelist',
            'blacklist', 'check', 'verify', 'safe'
        ]

        label_lower = label.lower()
        return any(keyword in label_lower for keyword in sanitizer_keywords)

    def extract_dataflow(self) -> bool:
        """
        Extract and enrich dataflow path information.

        Returns:
            True if dataflow was successfully extracted
        """
        if not self.has_dataflow or not self.dataflow_path:
            return False

        try:
            # Extract source
            if self.dataflow_path.get("source"):
                src = self.dataflow_path["source"]
                self.dataflow_source = {
                    "file": src["file"],
                    "line": src["line"],
                    "column": src.get("column", 0),
                    "label": src["label"],
                    "snippet": src.get("snippet", ""),
                    "code": self._read_code_at_location(src["file"], src["line"])
                }

            # Extract sink
            if self.dataflow_path.get("sink"):
                sink = self.dataflow_path["sink"]
                self.dataflow_sink = {
                    "file": sink["file"],
                    "line": sink["line"],
                    "column": sink.get("column", 0),
                    "label": sink["label"],
                    "snippet": sink.get("snippet", ""),
                    "code": self._read_code_at_location(sink["file"], sink["line"])
                }

            # Extract intermediate steps
            for step in self.dataflow_path.get("steps", []):
                is_sanitizer = self._is_sanitizer(step["label"])

                step_info = {
                    "file": step["file"],
                    "line": step["line"],
                    "column": step.get("column", 0),
                    "label": step["label"],
                    "snippet": step.get("snippet", ""),
                    "is_sanitizer": is_sanitizer,
                    "code": self._read_code_at_location(step["file"], step["line"])
                }

                self.dataflow_steps.append(step_info)

                if is_sanitizer:
                    self.sanitizers_found.append(step["label"])

            logger.info(f"✓ Extracted dataflow: {len(self.dataflow_steps)} steps, {len(self.sanitizers_found)} sanitizers")
            return True

        except Exception as e:
            logger.error(f"Failed to extract dataflow: {e}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialisation."""
        result = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "level": self.level,
            "message": self.message,
            "cwe_id": self.cwe_id,
            "tool": self.tool,
            "exploitable": self.exploitable,
            "exploitability_score": self.exploitability_score,
            "analysis": self.analysis,
            "has_exploit": self.exploit_code is not None,
            "has_patch": self.patch_code is not None,
        }

        # Surface compile-verification verdict on the finding so
        # reporting / downstream consumers can distinguish a viable
        # PoC from a hallucinated one. Omitted entirely when no
        # exploit was emitted (no value to encode "not attempted on
        # a non-existent artefact").
        if self.exploit_code is not None:
            result["exploit_compiled"] = self.exploit_compiled
            if self.exploit_compile_errors:
                result["exploit_compile_errors"] = list(
                    self.exploit_compile_errors
                )

        # Surface the intent-match verdict when present. Only emit
        # when actually populated — None means the judge wasn't
        # invoked (no exploit, opt-out, or pre-judge stage) and
        # there's no value in encoding that absence.
        if self.intent_match is not None:
            result["intent_match"] = dict(self.intent_match)

        # Add function metadata if available (from inventory checklist)
        if self.metadata:
            result["metadata"] = self.metadata

        # Add code context if available (populated by read_vulnerable_code)
        if self.full_code:
            result["code"] = self.full_code
        if self.surrounding_context:
            result["surrounding_context"] = self.surrounding_context

        # Add feasibility data if present (always a dict, check for non-default)
        if self.feasibility.get("status", "pending") != "pending" or self.feasibility.get("verdict"):
            result["feasibility"] = self.feasibility

        # Add dataflow information if present
        if self.has_dataflow:
            result["has_dataflow"] = True
            result["dataflow"] = {
                "source": self.dataflow_source,
                "sink": self.dataflow_sink,
                "steps": self.dataflow_steps,
                "sanitizers_found": self.sanitizers_found,
                "total_steps": len(self.dataflow_steps) + 2  # +2 for source and sink
            }
        else:
            result["has_dataflow"] = False

        return result


def convert_validated_to_agent_format(data: dict) -> List[Dict[str, Any]]:
    """Convert validation pipeline findings.json to VulnerabilityContext format.

    Skips ruled_out, confirmed_blocked, and unlikely-verdict findings.
    Normalizes status fields in-place before filtering (idempotent).
    """
    from packages.exploitability_validation.models import (
        Finding, EXPLOITABLE_FINAL_STATUSES,
    )

    try:
        from packages.exploitability_validation import normalize_findings
        normalize_findings(data)
    except ImportError:
        pass
    converted = []
    # Pre-fix the exclusion sets here had drifted from
    # core/schema_constants.py:
    #
    #   * `f.status in ("ruled_out", "disproven")` — fine.
    #   * `f.final_status in ("ruled_out", "confirmed_blocked")`
    #     — MISSED `disproven` (Stage B disqualifier outcome,
    #     which can land in final_status from upstream
    #     orchestrator wiring).
    #
    # Findings with `final_status="disproven"` then leaked
    # into the exploit / patch / report consumers as
    # warnings, even though they had been actively disproven
    # by Stage B. Operators saw "warning: this disproven
    # finding..." in reports.
    #
    # Add `disproven` to the exclusion set. Symmetric with
    # the `f.status` check above which already covers it.
    _SKIP_FINAL_STATUSES = ("ruled_out", "confirmed_blocked", "disproven")
    for raw in data.get("findings", []):
        f = Finding.from_dict(raw)
        # Check both status and final_status for exclusion
        if f.status in ("ruled_out", "disproven"):
            continue
        if f.final_status in _SKIP_FINAL_STATUSES:
            continue
        if f.feasibility.verdict == "unlikely":
            continue

        feasibility_d = f.feasibility.to_dict()
        converted.append({
            "finding_id": f.id,
            "rule_id": f.rule_id or f.vuln_type,
            "file": f.file,
            "startLine": f.line,
            "endLine": f.line,
            "snippet": f.proof.vulnerable_code,
            "message": f.candidate_reasoning or f.message or f.rule_id or f"{f.vuln_type} in {f.function or 'unknown'}",
            "level": "error" if f.final_status in EXPLOITABLE_FINAL_STATUSES else "warning",
            "has_dataflow": bool(f.proof.flow),
            "feasibility": feasibility_d,
            "attack_path_ref": f.feasibility.attack_path_ref,
            "ruling": f.ruling.to_dict(),
            "final_status": f.final_status or "pending",
            "tool": f.tool,
            "cwe_id": f.cwe_id,
        })
    return converted


class AutonomousSecurityAgentV2:
    def __init__(self, repo_path: Path, out_dir: Path, llm_config: Optional[LLMConfig] = None,
                 prep_only: bool = False,
                 synthesise_checkers: bool = True,
                 verify_exploits: bool = True,
                 judge_intent: bool = True,
                 record_witnesses: bool = True,
                 use_verified_exemplars: bool = True):
        self.repo_path = repo_path
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        # KNighter follow-up: synthesise a checker rule for every
        # confirmed exploitable finding and emit suspicious annotations
        # for variants found across the codebase. Default on; opt out
        # via ``--no-checker-synthesis`` for cost-sensitive runs.
        self.synthesise_checkers = synthesise_checkers
        # Compile-verify every LLM-emitted exploit by shelling out to
        # gcc in a sandboxed temp dir. Default on; opt out via
        # ``--no-verify-exploits`` for time-sensitive runs. Wall-clock
        # cost is ~140ms per finding in the steady state (measured on
        # a clean linux/x86_64 host; cold-start may add sandbox
        # init time on the first call). For a 100-finding run that's
        # ~14s of extra wall-clock — usually below the noise threshold
        # of the surrounding LLM calls, but the opt-out exists for
        # benchmarks / CI surfaces where every second counts.
        # See ``_verify_exploit_compiles`` for what the verdict
        # populates on each ``VulnerabilityContext``.
        self.verify_exploits = verify_exploits
        # IntentMatchJudge v1 — heuristic-first, LLM tiebreak on
        # ambiguous cases. Decides whether an LLM-generated exploit
        # actually targets the finding it was generated for, or
        # hit a different bug. Default on; opt out via
        # ``--no-judge-intent`` for runs where the extra LLM
        # tiebreak cost (~$0.001-0.01 per ambiguous finding) is
        # unwanted. See ``_judge_exploit_intent`` and
        # ``packages.llm_analysis.intent_match``.
        self.judge_intent = judge_intent
        # Record each LLM-emitted exploit as a canonical Witness
        # (source=LLM_EMIT_RUN, outcome=NOT_RUN) so the bytes are
        # available to downstream consumers (reporting, future
        # ZKPoX) on the same data path as fuzz witnesses. Lazy: the
        # WitnessStore is opened on the first successful exploit
        # generation rather than eagerly, so prep-only runs never
        # touch the filesystem. Failures are non-fatal — the
        # exploit artefact remains on disk regardless. Default on;
        # opt out via ``--no-record-witnesses``.
        self.record_witnesses = record_witnesses
        self._witness_store = None  # lazy
        # Tier-3 retrieval: prime each analysis prompt with RAPTOR's own
        # nearest previously-confirmed outcomes (this run's witness store +,
        # when a project is active, sibling runs') as exemplars beside the
        # curated CVE ones. Default on; opt out via ``--no-verified-exemplars``.
        # Empty corpus (fresh run, no project) -> no-op, so a first run's
        # prompts are unchanged.
        self.use_verified_exemplars = use_verified_exemplars
        self._verified_outcomes = None  # lazy, collected once per run

        # Detect LLM availability and choose provider
        availability = detect_llm_availability()

        if prep_only:
            # Phase 3 prep — read code, build structured findings
            self.llm_config = None
            self.llm = ClaudeCodeProvider()
            logger.debug(f"Prep mode: {repo_path} → {out_dir}")
        elif availability.external_llm:
            # External LLM configured — use LLMClient
            self.llm_config = llm_config or LLMConfig()
            self.llm = LLMClient(self.llm_config)

            logger.info("RAPTOR Autonomous Security Agent initialised")
            logger.info(f"Repository: {repo_path}")
            logger.info(f"Output: {out_dir}")
            logger.info(f"LLM: {self.llm_config.primary_model.provider}/{self.llm_config.primary_model.model_name}")

            # Also print to console so user can see
            print(f"\n🤖 Using LLM: {self.llm_config.primary_model.provider}/{self.llm_config.primary_model.model_name}")
            if self.llm_config.primary_model.cost_per_1k_tokens > 0:
                print(f"💰 Cost: ${self.llm_config.primary_model.cost_per_1k_tokens:.4f} per 1K tokens")
            else:
                print("💰 Cost: FREE (self-hosted model)")

            # Warn about Ollama model limitations for exploit generation
            if "ollama" in self.llm_config.primary_model.provider.lower():
                print()
                print("IMPORTANT: You are using an Ollama model.")
                print("   • Vulnerability analysis and patching: Works well with Ollama models")
                print("   • Exploit generation: Requires frontier models (Anthropic Claude / OpenAI GPT-4)")
                print("   • Ollama models may generate invalid/non-compilable exploit code")
                print()
                print("   For production-quality exploits, use:")
                print("     export ANTHROPIC_API_KEY=your_key  (recommended)")
                print("     export OPENAI_API_KEY=your_key")
            print()
        else:
            # No external LLM — use ClaudeCodeProvider
            self.llm_config = None
            self.llm = ClaudeCodeProvider()

            logger.info("RAPTOR Autonomous Security Agent initialised (prep-only mode)")
            logger.info(f"Repository: {repo_path}")
            logger.info(f"Output: {out_dir}")

            if availability.claude_code:
                print("\n🤖 No external LLM configured — Claude Code will handle analysis")
            else:
                print("\n⚠️  No LLM available — producing structured findings for manual review")
            print()

    def _load_attack_path(self, ref: str) -> Optional[Dict[str, Any]]:
        """Load attack path from a ref like 'attack-paths.json#PATH-001'.

        `ref` is read from finding JSON which may originate from
        an LLM response or a third-party SARIF — it is untrusted.
        Reject `file_name` segments that contain path separators
        or `..` so a malicious ref can't escape the intended search
        roots and load arbitrary attacker-controlled JSON files
        from the filesystem (e.g. `ref =
        "../../../tmp/attacker.json#x"` would otherwise resolve
        and the parsed list would feed straight into the
        validation pipeline as if it were a real attack path).
        """
        if not ref or '#' not in ref:
            return None
        try:
            file_name, path_id = ref.split('#', 1)
            # Containment: file_name must be a single bare filename
            # (no slashes, no parent traversal). Reject NUL bytes
            # for filesystem-API safety. Empty rejected too —
            # `Path / ""` is `Path` and would load the directory
            # listing as JSON (then fail at parse, but still
            # opens an unintended path).
            if (
                not file_name
                or "/" in file_name
                or "\\" in file_name
                or "\x00" in file_name
                or file_name in {".", ".."}
                or file_name.startswith("..")
            ):
                logger.debug(
                    "Refusing attack-path ref with non-bare filename: %r", ref,
                )
                return None
            # Search in validation directory — check multiple likely locations
            candidates = [
                self.out_dir.parent / "validation" / file_name,    # Normal pipeline layout
                self.out_dir / file_name,                           # Same directory as findings
                self.out_dir.parent / file_name,                    # One level up
            ]
            for search_path in candidates:
                paths = load_json(search_path)
                if paths is not None and isinstance(paths, list):
                    return next((p for p in paths if p.get("id") == path_id), None)
            return None
        except (json.JSONDecodeError, OSError, StopIteration) as e:
            logger.debug(f"Failed to load attack path from '{ref}': {e}")
            return None

    def validate_dataflow(self, vuln: VulnerabilityContext) -> Dict[str, Any]:
        """
        Deep validation of dataflow path using LLM to assess true exploitability.

        This is the CRITICAL step that separates real vulnerabilities from false positives.

        Args:
            vuln: VulnerabilityContext with extracted dataflow

        Returns:
            Dictionary with validation results
        """
        if not vuln.has_dataflow or not vuln.dataflow_source or not vuln.dataflow_sink:
            logger.warning("No dataflow to validate")
            return {}

        logger.info("=" * 70)
        logger.info("DATAFLOW VALIDATION (Deep Analysis)")
        logger.info("=" * 70)

        from packages.llm_analysis.prompts import (
            build_dataflow_validation_bundle,
            DATAFLOW_VALIDATION_SCHEMA,
        )

        bundle = build_dataflow_validation_bundle(
            rule_id=vuln.rule_id,
            message=vuln.message,
            dataflow_source=vuln.dataflow_source,
            dataflow_sink=vuln.dataflow_sink,
            dataflow_steps=vuln.dataflow_steps,
            sanitizers_found=vuln.sanitizers_found,
        )
        validation_prompt = next(m.content for m in bundle.messages if m.role == "user")
        system_prompt = next(m.content for m in bundle.messages if m.role == "system")
        validation_schema = DATAFLOW_VALIDATION_SCHEMA

        try:
            logger.info("Sending dataflow to LLM for deep validation...")

            raw_validation, _response = self.llm.generate_structured(
                prompt=validation_prompt,
                schema=validation_schema,
                system_prompt=system_prompt,
                task_type=TaskType.ANALYSE,
            )

            if raw_validation is None:
                logger.info("No external LLM available — skipping dataflow validation")
                return {}

            from core.llm.response_validation import (
                attempt_quality_retry, validate_structured_response,
            )
            validated = validate_structured_response(raw_validation, validation_schema)
            # Single-retry uplift: if the LLM's first response is missing
            # required fields or had to be coerced, re-prompt with the
            # specific problems called out. Returns the higher-quality
            # of the two responses (original if retry didn't beat it).
            validated = attempt_quality_retry(
                self.llm, validated, validation_prompt, validation_schema,
                system_prompt=system_prompt, task_type=TaskType.ANALYSE,
                threshold=0.5,
            )
            validation = validated.data
            if validated.quality < 0.5:
                logger.warning(f"Low-quality dataflow validation (q={validated.quality:.2f}), incomplete: {validated.incomplete}")

            logger.info("✓ Dataflow validation complete:")
            logger.info(f"  Source attacker-controlled: {validation.get('source_attacker_controlled')}")
            logger.info(f"  Sanitizers effective: {validation.get('sanitizers_effective')}")
            logger.info(f"  Path reachable: {validation.get('path_reachable')}")
            logger.info(f"  Is exploitable: {validation.get('is_exploitable')}")
            # `.get(key, default)` only fires the default for MISSING keys;
            # an explicit `null` from the LLM passes through as None, then
            # `f"{None:.2f}"` raises TypeError mid-log-write and aborts
            # the whole validate_dataflow call. Coalesce explicitly.
            _conf = validation.get('exploitability_confidence')
            logger.info(f"  Confidence: {(_conf if _conf is not None else 0):.2f}")
            logger.info(f"  Attack complexity: {validation.get('attack_complexity')}")
            logger.info(f"  False positive: {validation.get('false_positive')}")

            if validation.get('sanitizer_details'):
                logger.info("\n  Sanitizer Analysis:")
                for san_detail in validation.get('sanitizer_details', []):
                    logger.info(f"    - {san_detail.get('name')}")
                    logger.info(f"      Purpose: {san_detail.get('purpose')}")
                    logger.info(f"      Bypassable: {san_detail.get('bypass_possible')}")
                    if san_detail.get('bypass_method'):
                        logger.info(f"      Bypass: {san_detail.get('bypass_method')[:100]}")

            if validation.get('attack_payload_concept'):
                logger.info("\n  Attack Payload Concept:")
                logger.info(f"    {validation.get('attack_payload_concept')[:200]}")

            # Save validation details
            validation_file = self.out_dir / "validation" / f"{vuln.finding_id}_validation.json"
            save_json(validation_file, validation)

            return validation

        except Exception as e:
            logger.error(f"✗ Dataflow validation failed: {e}")
            return {}

    def analyze_vulnerability(self, vuln: VulnerabilityContext) -> bool:
        is_prep = isinstance(self.llm, ClaudeCodeProvider)

        if is_prep:
            logger.debug(f"Prepping: {vuln.rule_id} at {vuln.file_path}:{vuln.start_line}")
        else:
            logger.info("=" * 70)
            logger.info(f"Analysing vulnerability: {vuln.rule_id}")
            logger.info(f"  File: {vuln.file_path}:{vuln.start_line}")
            logger.info(f"  Severity: {vuln.level}")
            logger.info(f"  Has dataflow: {'Yes' if vuln.has_dataflow else 'No'}")
            logger.info(f"  Message: {vuln.message[:100]}..." if len(vuln.message) > 100 else f"  Message: {vuln.message}")

        # Read the actual vulnerable code
        if not vuln.read_vulnerable_code():
            logger.error(f"✗ Cannot read code for {vuln.finding_id}")
            return False

        if not is_prep:
            logger.info(f"✓ Read vulnerable code ({len(vuln.full_code)} chars)")
            logger.info(f"✓ Read context ({len(vuln.surrounding_context)} chars)")

        # Extract dataflow path if available
        if vuln.has_dataflow:
            if vuln.extract_dataflow():
                logger.info(f"✓ Dataflow path: {vuln.dataflow_path.get('total_steps', 0)} total steps")
                if vuln.sanitizers_found:
                    logger.info(f"  ⚠️  Sanitizers detected: {', '.join(vuln.sanitizers_found)}")
            else:
                logger.warning("⚠️  Failed to extract dataflow path")

        from packages.llm_analysis.prompts import (
            build_analysis_prompt_bundle,
            build_analysis_schema,
        )
        from packages.llm_analysis.source_intel_inject import (
            evidence_blocks_for_finding,
        )

        analysis_schema = build_analysis_schema(has_dataflow=vuln.has_dataflow)

        # Surface the function's inventory metadata to the strategy
        # picker so it can match on function-name keywords and any
        # known callees. ``vuln.metadata`` is populated upstream from
        # the inventory checklist when available.
        meta = vuln.metadata or {}
        function_name = meta.get("name") or ""
        file_includes = meta.get("includes") or ()
        function_calls_made = meta.get("calls") or meta.get("callees") or ()

        # Pull source_intel evidence (cached during sequential-mode
        # priming earlier in this run). Returns () for rule_ids not
        # in the memory-corruption set or when prep failed.
        si_blocks = evidence_blocks_for_finding({
            "rule_id": vuln.rule_id,
            "repo_path": str(vuln.repo_path),
            "metadata": meta,
        })
        extra_blocks = list(si_blocks)
        try:
            from core.threat_model import threat_model_untrusted_block
            tm_block = threat_model_untrusted_block(Path(vuln.repo_path))
            if tm_block:
                extra_blocks.append(tm_block)
        except Exception:
            pass

        bundle = build_analysis_prompt_bundle(
            rule_id=vuln.rule_id,
            level=vuln.level,
            file_path=vuln.file_path,
            start_line=vuln.start_line,
            end_line=vuln.end_line,
            message=vuln.message,
            code=vuln.full_code,
            surrounding_context=vuln.surrounding_context,
            has_dataflow=vuln.has_dataflow,
            dataflow_source=vuln.dataflow_source,
            dataflow_sink=vuln.dataflow_sink,
            dataflow_steps=vuln.dataflow_steps,
            metadata=meta,
            repo_path=str(vuln.repo_path),
            cwe_id=vuln.cwe_id,
            function_name=function_name,
            file_includes=file_includes,
            function_calls_made=function_calls_made,
            extra_blocks=extra_blocks,
            verified_outcomes=(
                self._get_verified_outcomes()
                if self.use_verified_exemplars else ()
            ),
        )
        prompt = next(m.content for m in bundle.messages if m.role == "user")
        system_prompt = next(m.content for m in bundle.messages if m.role == "system")

        try:
            if not isinstance(self.llm, ClaudeCodeProvider):
                logger.info("Sending vulnerability to LLM for analysis...")

            # Use LLM for intelligent analysis
            raw_analysis, _full_response = self.llm.generate_structured(
                prompt=prompt,
                schema=analysis_schema,
                system_prompt=system_prompt,
                task_type=TaskType.ANALYSE,
            )

            if raw_analysis is None:
                logger.debug("Prep mode — Phase 4 will handle analysis")
                return False

            from core.llm.response_validation import (
                attempt_quality_retry, validate_structured_response,
            )
            validated = validate_structured_response(raw_analysis, analysis_schema)
            # See validate_dataflow above for the retry rationale.
            validated = attempt_quality_retry(
                self.llm, validated, prompt, analysis_schema,
                system_prompt=system_prompt, task_type=TaskType.ANALYSE,
                threshold=0.5,
            )
            analysis = validated.data
            if validated.quality < 0.5:
                logger.warning(f"Low-quality LLM response (q={validated.quality:.2f}), incomplete: {validated.incomplete}")

            vuln.exploitable = analysis.get("is_exploitable", False)
            vuln.exploitability_score = analysis.get("exploitability_score", 0.0)
            vuln.analysis = analysis

            logger.info("✓ LLM analysis complete:")
            logger.info(f"  True Positive: {analysis.get('is_true_positive', False)}")
            logger.info(f"  Exploitable: {vuln.exploitable}")
            logger.info(f"  Exploitability Score: {vuln.exploitability_score:.2f}")
            logger.info(f"  Severity Assessment: {analysis.get('severity_assessment', 'unknown')}")
            # Compute CVSS score from vector if provided
            from packages.cvss import score_finding
            score_finding(analysis)
            if analysis.get("cvss_score_estimate"):
                logger.info(f"  CVSS: {analysis['cvss_score_estimate']} ({analysis.get('severity_assessment', '?')}) from {analysis.get('cvss_vector')}")
            else:
                logger.info(f"  CVSS Estimate: {analysis.get('cvss_score_estimate', 'N/A')}")

            # Log dataflow-specific analysis
            if vuln.has_dataflow and 'source_attacker_controlled' in analysis:
                logger.info("\n  Dataflow Analysis:")
                logger.info(f"    Source attacker-controlled: {analysis.get('source_attacker_controlled', 'N/A')}")
                logger.info(f"    Sanitizers effective: {analysis.get('sanitizers_effective', 'N/A')}")
                if analysis.get('sanitizer_bypass_technique'):
                    logger.info(f"    Bypass technique: {(analysis.get('sanitizer_bypass_technique') or '')[:100]}...")
                logger.info(f"    Dataflow exploitable: {analysis.get('dataflow_exploitable', 'N/A')}")

            logger.info(f"\n  Reasoning: {(analysis.get('reasoning') or '')[:150]}...")
            if analysis.get('attack_scenario'):
                logger.info(f"  Attack Scenario: {analysis.get('attack_scenario')[:150]}...")

            # Deep dataflow validation for high-confidence findings
            if vuln.has_dataflow and vuln.exploitable:
                # IRIS Tier 1 pre-flight — same pattern as the
                # `generate_exploit` gate below. A free CodeQL refutation
                # short-circuits the LLM-backed deep validation entirely.
                # Reuses the cached Tier 1 verdict if `validate_dataflow_claims`
                # already ran (the /agentic --validate-dataflow path);
                # otherwise discovers DBs lazily and runs Tier 1 against
                # this finding. Inconclusive / confirmed / no_check fall
                # through and the LLM call proceeds as before.
                gate = self._tier1_pre_flight(vuln)
                if gate == "refuted":
                    logger.info(
                        f"⚠️  IRIS Tier 1 refuted dataflow for "
                        f"{vuln.rule_id} at "
                        f"{vuln.file_path}:{vuln.start_line} — "
                        f"skipping LLM deep validation"
                    )
                    vuln.exploitable = False
                    vuln.exploitability_score = 0.0
                    # Record the verdict in the same shape the LLM-backed
                    # validation would, so downstream consumers (report
                    # rendering, _tier1_pre_flight cache reuse from
                    # `generate_exploit`) see a consistent dataflow_validation
                    # record.
                    analysis["dataflow_validation"] = {
                        "verdict": "refuted",
                        "tier": "iris_tier1",
                        "false_positive": True,
                        "false_positive_reason": (
                            "iris_tier1_refuted: LocalFlowSource query "
                            "found no path; LLM deep validation skipped"
                        ),
                        "is_exploitable": False,
                    }
                else:
                    logger.info("\n" + "─" * 70)
                    logger.info("🔍 Performing DEEP DATAFLOW VALIDATION...")
                    logger.info("─" * 70)

                    validation = self.validate_dataflow(vuln)

                    if validation:
                        # Update exploitability based on validation
                        if validation.get('false_positive'):
                            logger.info("⚠️  Validation marked as FALSE POSITIVE:")
                            logger.info(f"    Reason: {validation.get('false_positive_reason')}")
                            vuln.exploitable = False
                            vuln.exploitability_score = 0.0
                        elif not validation.get('is_exploitable'):
                            logger.info("⚠️  Validation determined NOT EXPLOITABLE:")
                            logger.info(f"    Reason: {(validation.get('exploitability_reasoning') or '')[:150]}")
                            vuln.exploitable = False
                            # Same null-vs-missing distinction as the
                            # log site above — explicit None from the
                            # LLM crashes `None * 0.5`.
                            _conf = validation.get('exploitability_confidence')
                            if _conf is None:
                                _conf = 0.0
                            vuln.exploitability_score = _conf * 0.5
                        else:
                            # Validation confirms exploitability
                            logger.info("✓ Validation confirms EXPLOITABLE")
                            # Use validation confidence to refine score —
                            # fall back to existing score if missing OR
                            # explicit null (max(float, None) → TypeError).
                            _conf = validation.get('exploitability_confidence')
                            if _conf is None:
                                _conf = vuln.exploitability_score
                            vuln.exploitability_score = max(
                                vuln.exploitability_score, _conf,
                            )

                        # Store validation in analysis
                        analysis['dataflow_validation'] = validation

            # Save detailed analysis
            analysis_file = self.out_dir / "analysis" / f"{vuln.finding_id}.json"
            save_json(analysis_file, {
                "finding_id": vuln.finding_id,
                "rule_id": vuln.rule_id,
                "file": vuln.file_path,
                "analysis": analysis,
            })

            return True

        except Exception as e:
            logger.error(f"✗ LLM analysis failed: {e}")
            if _is_auth_error(e):
                print("⚠️  LLM authentication failed — check your API key. Falling back to heuristic analysis.")
            else:
                logger.warning("  Using fallback heuristic analysis")
            # Fallback to marking as potentially exploitable
            vuln.exploitable = vuln.level == "error"
            vuln.exploitability_score = 0.5
            return False

    def _tier1_pre_flight(self, vuln: VulnerabilityContext) -> str:
        """Run IRIS Tier 1 against `vuln` if a CodeQL DB is available.

        Returns one of "confirmed" / "refuted" / "inconclusive" /
        "no_check". Refuted is the only verdict that gates exploit
        generation — everything else proceeds. See
        `dataflow_validation.tier1_check_finding` for the verdict
        semantics.

        Two paths to a verdict, in priority order:

          1. Reuse `vuln.analysis['dataflow_validation']` if the
             orchestrator already ran `validate_dataflow_claims` on
             this finding. Avoids a second CodeQL invocation
             (free-but-not-zero), and survives the case where the
             CodeQL DB has been cleaned up between phases — the
             cached verdict still tells us what to do.
          2. Otherwise: discover DBs lazily from `<out_dir>/codeql/`
             and call `tier1_check_finding`. If the codeql phase
             didn't run for this target, the DB dict is empty and
             the gate becomes a no-op.

        The gate must never raise — any exception falls through to
        "no_check" so a sandbox / discovery / config bug can't break
        the exploit pipeline.
        """
        # Path 1: reuse orchestrator's earlier validation if present.
        existing = (vuln.analysis or {}).get("dataflow_validation") or {}
        verdict = existing.get("verdict")
        if verdict in ("confirmed", "refuted", "inconclusive"):
            return verdict

        # Path 2: fresh Tier 1 check against the run's CodeQL DBs.
        if getattr(self, "_codeql_dbs", None) is None:
            try:
                from packages.llm_analysis.dataflow_validation import (
                    discover_codeql_databases,
                )
                self._codeql_dbs = discover_codeql_databases(self.out_dir) or {}
            except Exception as e:
                logger.debug(f"Tier 1 gate: DB discovery failed: {e}")
                self._codeql_dbs = {}
        if not self._codeql_dbs:
            return "no_check"
        try:
            from packages.llm_analysis.dataflow_validation import (
                tier1_check_finding,
            )
            return tier1_check_finding(vuln.finding, self._codeql_dbs,
                                       target_path=self.repo_path)
        except Exception as e:
            # The gate must never break the pipeline. Log and proceed.
            logger.debug(f"Tier 1 gate: check raised: {e}")
            return "no_check"

    def _smt_pre_flight(self, vuln: VulnerabilityContext) -> str:
        """Free SMT path-feasibility check using the LLM-extracted
        ``path_conditions`` / ``path_profile`` fields on this finding's
        analysis. Same shape as ``_tier1_pre_flight`` but reads SMT
        instead of CodeQL.

        Returns one of "refuted" / "confirmed" / "no_check":

          "refuted"   — SMT proved the conditions mutually exclusive;
                        the dangerous path is unreachable. Caller
                        should skip downstream LLM cost.
          "confirmed" — SMT found a satisfying assignment. Path is
                        reachable; falls through to exploit gen as
                        before. (Witness model is also recorded in
                        the analysis dict for downstream PoC seeding
                        in a future PR.)
          "no_check"  — no path_conditions on the analysis OR Z3 not
                        installed OR conditions unparseable. Same
                        meaning as the IRIS gate's no_check: caller
                        proceeds without information.

        Never raises — any failure mode returns "no_check" so the
        exploit pipeline is never broken by SMT issues.
        """
        analysis = vuln.analysis or {}
        # Same field-precedence as Tier 4 (`_tier4_smt_refine` in
        # dataflow_validation.py): nested deep-validation block wins
        # over top-level analysis.
        nested = analysis.get("dataflow_validation") or {}
        conditions = (
            nested.get("path_conditions")
            or analysis.get("path_conditions")
            or []
        )
        if not conditions:
            return "no_check"
        profile = (
            nested.get("path_profile")
            or analysis.get("path_profile")
            or "uint64"
        ).strip().lower()

        try:
            from packages.exploit_feasibility.smt_path import validate_path
        except ImportError as e:
            logger.debug(f"SMT pre-flight: substrate unavailable: {e}")
            return "no_check"

        try:
            smt = validate_path(conditions, profile=profile)
        except Exception as e:
            logger.debug(f"SMT pre-flight: check raised: {e}")
            return "no_check"

        if not smt.get("smt_available"):
            return "no_check"

        feasible = smt.get("feasible")
        if feasible is False:
            return "refuted"
        if feasible is True:
            return "confirmed"
        # feasible is None — Z3 timed out / all conditions unparseable.
        return "no_check"

    def generate_exploit(self, vuln: VulnerabilityContext) -> bool:

        if not vuln.exploitable:
            logger.debug("⊘ Skipping exploit generation (not exploitable)")
            return False

        # IRIS Tier 1 pre-flight gate — free CodeQL check before paying
        # for LLM exploit generation. If discovery surfaces an in-repo
        # LocalFlowSource query for the finding's (lang, CWE) and that
        # query refutes the dataflow (zero matches under the broad
        # source model), skip generation. Inconclusive / confirmed /
        # no_check fall through and proceed as before.
        gate = self._tier1_pre_flight(vuln)
        if gate == "refuted":
            logger.info(
                f"⊘ Skipping exploit generation: IRIS Tier 1 refuted the "
                f"dataflow claim for {vuln.rule_id} at "
                f"{vuln.file_path}:{vuln.start_line}"
            )
            vuln.analysis = (vuln.analysis or {})
            vuln.analysis["exploit_skipped_reason"] = (
                "iris_tier1_refuted: Tier 1 LocalFlowSource query "
                "found no path; no LLM tokens spent"
            )
            return False

        # SMT pre-flight gate — free Z3 check using the same
        # `path_conditions` field that /agentic --validate-dataflow
        # Tier 4 reads. Fires only when the per-finding analysis
        # populated path_conditions (typically CWE-190/125/787/476/191).
        # Refute on unsat → skip exploit gen for free. Mirrors the IRIS
        # Tier 1 gate above; same fail-open semantics (any failure
        # → no_check → fall through).
        smt_gate = self._smt_pre_flight(vuln)
        if smt_gate == "refuted":
            logger.info(
                f"⊘ Skipping exploit generation: SMT proved path "
                f"conditions unsatisfiable for {vuln.rule_id} at "
                f"{vuln.file_path}:{vuln.start_line}"
            )
            vuln.analysis = (vuln.analysis or {})
            vuln.analysis["exploit_skipped_reason"] = (
                "smt_unsat: path conditions are mutually exclusive; "
                "the dangerous path is unreachable. No LLM tokens spent."
            )
            return False

        logger.info("─" * 70)
        logger.info(f"Generating exploit PoC for {vuln.rule_id}")
        logger.info(f"   Target: {vuln.file_path}:{vuln.start_line}")

        from packages.llm_analysis.prompts.exploit import build_exploit_prompt_bundle
        from packages.llm_analysis.source_intel_inject import (
            evidence_blocks_for_finding,
        )

        si_blocks = evidence_blocks_for_finding({
            "rule_id": vuln.rule_id,
            "repo_path": str(vuln.repo_path),
            "metadata": vuln.metadata or {},
        })

        bundle = build_exploit_prompt_bundle(
            rule_id=vuln.rule_id,
            file_path=vuln.file_path,
            start_line=vuln.start_line,
            level=vuln.level,
            analysis=vuln.analysis,
            code=vuln.full_code,
            surrounding_context=vuln.surrounding_context,
            feasibility=vuln.feasibility if hasattr(vuln, 'feasibility') else None,
            extra_blocks=si_blocks,
        )
        prompt = next(m.content for m in bundle.messages if m.role == "user")
        system_prompt = next(m.content for m in bundle.messages if m.role == "system")

        try:
            logger.info("Requesting exploit code from LLM...")

            response = self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.8,  # Higher creativity for exploit generation. YMMV
                task_type=TaskType.GENERATE_CODE,
            )

            if response is None:
                logger.info("No external LLM available — skipping exploit generation")
                return False

            # Extract code from response
            exploit_code = self._extract_code(response.content)

            if exploit_code:
                vuln.exploit_code = exploit_code

                # Save exploit
                exploit_file = self.out_dir / "exploits" / f"{vuln.finding_id}_exploit.cpp"
                exploit_file.parent.mkdir(exist_ok=True, parents=True)
                exploit_file.write_text(exploit_code)

                logger.info(f"   ✓ Exploit generated: {len(exploit_code)} bytes")
                logger.info(f"   ✓ Saved to: {exploit_file.name}")

                # Compile-verify the LLM's output. Pre-fix, exploit_code
                # was saved unconditionally with no signal about whether
                # it would build — operators downstream had no way to
                # distinguish a viable PoC from a hallucinated one. The
                # sandbox-wrapped gcc invocation here matches the
                # pattern /codeql --autonomous has used since v2.0; the
                # only new thing is wiring it into /agentic's path.
                # Verdict populates ``ExploitResult.result``-equivalent
                # fields on the finding so reporting can surface
                # "exploit compiled" rates per run. Gated on
                # ``self.verify_exploits`` so operators with tight
                # time budgets can opt out via constructor / CLI flag.
                if self.verify_exploits:
                    self._verify_exploit_compiles(vuln, exploit_code)

                # Intent-match judgement on the (possibly compile-
                # verified) exploit. Runs heuristics first (cheap);
                # escalates to a 2-step LLM tiebreak on ambiguous
                # cases. Gated on ``self.judge_intent`` so operators
                # opting out via ``--no-judge-intent`` skip the
                # tiebreak's LLM cost. See
                # ``packages.llm_analysis.intent_match`` for design.
                if self.judge_intent:
                    self._judge_exploit_intent(vuln, exploit_code)

                # Record the LLM-emitted exploit as a canonical
                # Witness (source=LLM_EMIT_RUN, outcome=NOT_RUN).
                # Same data path as fuzz witnesses; downstream
                # consumers filter by ``source`` when they care
                # about provenance. Gated on
                # ``self.record_witnesses``; failures are non-
                # fatal — the exploit file on disk is unaffected.
                if self.record_witnesses:
                    self._record_exploit_witness(vuln, exploit_code)

                return True
            else:
                logger.warning("   ✗ LLM response did not contain valid code")
                return False

        except Exception as e:
            logger.error(f"   ✗ Exploit generation failed: {e}")
            if _is_auth_error(e):
                print("⚠️  LLM authentication failed — check your API key.")
            return False

    # File extensions that map to languages the gcc-based validator
    # can compile. Retained as a class attribute for back-compat with
    # external tests that mirror it onto stub agents; the canonical
    # set now lives in ``packages.llm_analysis.exploit_verify``.
    _COMPILABLE_EXTENSIONS = frozenset({
        ".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp",
    })

    def _verify_exploit_compiles(
        self, vuln: VulnerabilityContext, exploit_code: str,
    ) -> None:
        """Compile-check the LLM-emitted exploit in a sandbox.

        Thin wrapper around
        :func:`packages.llm_analysis.exploit_verify.compile_verify`
        that maps the shared helper's ``(compiled, errors)`` tuple
        onto the finding's ``exploit_compiled`` /
        ``exploit_compile_errors`` fields. See ``exploit_verify`` for
        the verification mechanics, language gate, sanitisation, and
        failure-mode semantics.

        Failures here are non-fatal: the helper returns ``None`` on
        unattempted/aborted verification rather than raising, so the
        exploit artefact remains on disk regardless and downstream
        reporting can distinguish "not attempted" (None) from
        "failed to compile" (False) from "compiled cleanly" (True).
        """
        from packages.llm_analysis.exploit_verify import compile_verify
        compiled, errors = compile_verify(
            exploit_code,
            vuln.file_path,
            vuln.finding_id,
            logger,
        )
        vuln.exploit_compiled = compiled
        vuln.exploit_compile_errors = errors

    def _judge_exploit_intent(
        self, vuln: VulnerabilityContext, exploit_code: str,
    ) -> None:
        """Run IntentMatchJudge v1 against the LLM-emitted exploit.

        Skips findings the analysis pass already triaged as false
        positives — judging an exploit for a finding the LLM
        rejected is allocation that's not worth the cost.

        Heuristic-first; LLM tiebreak only on ambiguous results.
        Failures (LLM error, missing config) leave the verdict as
        ``uncertain`` with the error captured in
        ``intent_match['llm_error']`` — never raises.
        """
        # Skip when analysis already classified the finding as FP.
        # No exploit can meaningfully target a non-bug. Be defensive
        # against ``vuln.analysis`` being non-dict — the type hint
        # says ``Optional[Dict[str, Any]]`` but in-flight pipelines
        # have been observed to set it to other shapes (raw response
        # strings, lists). Treat anything non-dict as "no analysis
        # signal" and proceed to judge.
        if isinstance(vuln.analysis, dict):
            is_tp = vuln.analysis.get("is_true_positive")
            if is_tp is False:
                logger.debug(
                    f"   · Skipping intent-match for {vuln.finding_id} "
                    "(analysis is_true_positive=False)"
                )
                return

        # Function name from inventory-checklist metadata. Defensive
        # against ``vuln.metadata`` being non-dict — same shape-
        # tolerance reasoning as for vuln.analysis above.
        if isinstance(vuln.metadata, dict):
            function_name = vuln.metadata.get("name")
        else:
            function_name = None

        from dataclasses import asdict
        from packages.llm_analysis.intent_match import intent_match

        verdict = intent_match(
            exploit_code=exploit_code,
            finding_file_path=vuln.file_path,
            finding_function_name=function_name,
            finding_cwe=vuln.cwe_id,
            finding_message=vuln.message,
            exploit_compile_errors=list(vuln.exploit_compile_errors),
            llm_client=self.llm,
            logger=logger,
        )
        vuln.intent_match = asdict(verdict)

        if verdict.verdict == "matches":
            logger.info(
                f"   ✓ Intent-match: matches "
                f"(confidence={verdict.confidence:.2f}, "
                f"used_llm={verdict.used_llm})"
            )
        elif verdict.verdict == "off_target":
            logger.info(
                f"   ⚠ Intent-match: off_target "
                f"(confidence={verdict.confidence:.2f}, "
                f"used_llm={verdict.used_llm}) — "
                "exploit may have hit a different bug"
            )
        else:
            logger.info(
                f"   · Intent-match: uncertain "
                f"(used_llm={verdict.used_llm})"
            )

    def _get_verified_outcomes(self):
        """Collect (once per run) the verified-outcome corpus visible to this
        run — its own witness store plus, when a project is active, sibling
        runs'. The substrate that primes analysis prompts with RAPTOR's own
        prior confirmations (Tier-3 retrieval).

        Best-effort: returns ``[]`` on any failure (substrate absent, no
        stores, project resolution error) so analysis is never blocked.
        """
        if self._verified_outcomes is not None:
            return self._verified_outcomes
        outcomes = []
        try:
            from core.verified_outcome import collect_outcomes
            project_root = None
            try:
                from core.run.output import _resolve_active_project
                active = _resolve_active_project()
                if active:
                    project_root = Path(active[0])
            except Exception:
                project_root = None
            outcomes = collect_outcomes(self.out_dir, project_root=project_root)
        except Exception as e:
            logger.debug(
                f"verified-outcome collection skipped: {e}", exc_info=True,
            )
            outcomes = []
        self._verified_outcomes = outcomes
        return outcomes

    def _record_exploit_witness(
        self, vuln: VulnerabilityContext, exploit_code: str,
    ) -> None:
        """Record the LLM-emitted exploit as a canonical Witness.

        Lazy-opens ``self._witness_store`` against
        ``self.out_dir / "witnesses"`` on first call so prep-only
        runs never touch the filesystem. Reads ``compile_verify``
        and ``intent_match`` verdicts off the finding for the
        ``outcome_detail``; both may be ``None`` if their gates
        were disabled.

        Failures are non-fatal: a witness-store I/O error, an
        adapter exception, or a non-UTF-8 exploit_code (LLMs
        sometimes emit binary-looking fixtures inside code blocks)
        all log+continue. The exploit artefact on disk is the
        primary record; the witness is a downstream-facing
        secondary record.
        """
        try:
            if self._witness_store is None:
                from core.witness import WitnessStore
                self._witness_store = WitnessStore(
                    self.out_dir / "witnesses"
                )
            from packages.llm_analysis.witness_adapter import (
                witness_from_exploit,
            )
            target_source_path = vuln.get_full_file_path()
            intent_verdict = None
            intent_confidence = None
            if vuln.intent_match is not None:
                intent_verdict = getattr(
                    vuln.intent_match, "verdict", None,
                )
                intent_confidence = getattr(
                    vuln.intent_match, "confidence", None,
                )
            witness, data = witness_from_exploit(
                exploit_code,
                finding_id=vuln.finding_id,
                cwe_id=vuln.cwe_id,
                rule_id=vuln.rule_id,
                file_path=vuln.file_path,
                compiled=vuln.exploit_compiled,
                compile_error_count=len(
                    vuln.exploit_compile_errors or []
                ),
                intent_verdict=intent_verdict,
                intent_confidence=intent_confidence,
                target_source_path=target_source_path,
            )
            self._witness_store.put(witness, data)
            logger.debug(
                f"   · Recorded witness {witness.bytes_hash[:12]} "
                f"({witness.bytes_len}B)"
            )
        except Exception as e:  # noqa: BLE001 — best-effort
            logger.warning(
                f"   · Witness record failed for "
                f"{vuln.finding_id}: {type(e).__name__}: {e}"
            )

    def generate_patch(self, vuln: VulnerabilityContext) -> bool:
        logger.info("─" * 70)
        logger.info(f"🔧 Generating secure patch for {vuln.rule_id}")
        logger.info(f"   Target: {vuln.file_path}:{vuln.start_line}")

        # Read full file content for better context
        file_path = vuln.get_full_file_path()
        if not file_path or not file_path.exists():
            logger.error(f"   ✗ File not found: {file_path}")
            return False

        logger.info("   ✓ Reading full file for context...")

        with open(file_path) as f:
            full_file_content = f.read()

        from packages.llm_analysis.prompts.patch import build_patch_prompt_bundle
        from packages.llm_analysis.source_intel_inject import (
            evidence_blocks_for_finding,
        )

        # Load attack path if available
        attack_path = None
        if vuln.attack_path_ref:
            attack_path = self._load_attack_path(vuln.attack_path_ref)

        si_blocks = evidence_blocks_for_finding({
            "rule_id": vuln.rule_id,
            "repo_path": str(vuln.repo_path),
            "metadata": vuln.metadata or {},
        })

        bundle = build_patch_prompt_bundle(
            rule_id=vuln.rule_id,
            file_path=vuln.file_path,
            start_line=vuln.start_line,
            end_line=vuln.end_line,
            message=vuln.message,
            analysis=vuln.analysis,
            code=vuln.full_code,
            full_file_content=full_file_content,
            feasibility=vuln.feasibility,
            attack_path=attack_path,
            extra_blocks=si_blocks,
        )
        prompt = next(m.content for m in bundle.messages if m.role == "user")
        system_prompt = next(m.content for m in bundle.messages if m.role == "system")

        try:
            logger.info("   🤖 Requesting secure patch from LLM...")

            response = self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.3,  # Lower temperature for safer patches
                task_type=TaskType.GENERATE_CODE,
            )

            if response is None:
                logger.info("   No external LLM available — skipping patch generation")
                return False

            patch_content = response.content

            # Save patch
            patch_file = self.out_dir / "patches" / f"{vuln.finding_id}_patch.md"
            patch_file.parent.mkdir(exist_ok=True, parents=True)

            from core.reporting.formatting import display_rule_id
            patch_content_formatted = f"""# Security Patch for {display_rule_id(vuln.rule_id)}

**File:** {vuln.file_path}
**Lines:** {vuln.start_line}-{vuln.end_line}
**Severity:** {vuln.level}

## Vulnerability Analysis
{json.dumps(vuln.analysis, indent=2)}

## Patch

{patch_content}

---
*Generated by RAPTOR Autonomous Security Agent*
*Review and test before applying to production*
"""

            patch_file.write_text(patch_content_formatted)
            vuln.patch_code = patch_content

            logger.info(f"   ✓ Patch generated: {len(patch_content)} bytes")
            logger.info(f"   ✓ Saved to: {patch_file.name}")
            return True

        except Exception as e:
            logger.error(f"   ✗ Patch generation failed: {e}")
            if _is_auth_error(e):
                print("⚠️  LLM authentication failed — check your API key.")
            return False

    # Match a markdown fenced code block. Captures the optional
    # language tag and the body between fences. The language tag
    # must end at a newline or the closing fence — pre-fix the
    # plain `"```c" in content` substring check matched ```cpp,
    # ```csharp, ```cmake, ```css, and even ```c++ as if they were
    # the C-language branch (because "```c" is a prefix of all of
    # them). Anchored on a per-line basis (re.MULTILINE) so prose
    # text containing "```cpp" inline (`"like ```cpp would match"`)
    # doesn't false-positive as a code block.
    _CODE_FENCE_RE = re.compile(
        r"^```(?P<lang>[a-zA-Z0-9_+-]*)\s*\n"
        r"(?P<body>.*?)"
        r"^```\s*$",
        re.MULTILINE | re.DOTALL,
    )

    def _extract_code(self, content: str) -> Optional[str]:
        """Extract code from LLM response (handles markdown code blocks).

        Preference order: ```cpp > ```c > ```python > untagged
        ``` > raw content. Pre-fix the substring matches conflated
        ```cpp / ```csharp / ```cmake / ```css with ```c, and
        matched ``` substrings inside prose as code blocks. The
        regex requires the fence to be at line start and the
        language tag to be a clean identifier ending at whitespace
        / newline.
        """
        # Find every fenced block and choose by language tag.
        blocks = list(self._CODE_FENCE_RE.finditer(content))
        if blocks:
            by_lang: Dict[str, str] = {}
            for m in blocks:
                lang = (m.group("lang") or "").lower()
                # First occurrence per language wins (preserve order).
                by_lang.setdefault(lang, m.group("body").rstrip())
            for preferred in ("cpp", "c++", "c", "python", "py", ""):
                if preferred in by_lang:
                    return by_lang[preferred].strip()
            # Fall back to the first block of any other language so
            # captions like ```rust still extract.
            return next(iter(by_lang.values())).strip()

        # No code block — return content as-is.
        return content.strip()

    def _load_validated_findings(self, findings_path: str) -> List[Dict[str, Any]]:
        """Load pre-validated findings from the validation pipeline's findings.json.

        Skips ruled_out findings and unlikely verdict findings.
        Converts validation format to VulnerabilityContext expected format.
        """
        data = load_json(findings_path, strict=True)
        if data is None:
            raise FileNotFoundError(f"Findings file not found: {findings_path}")

        converted = convert_validated_to_agent_format(data)

        logger.info(f"Loaded {len(converted)} findings from {Path(findings_path).name} "
                    f"(skipped {len(data.get('findings', [])) - len(converted)} ruled out/unlikely)")
        return converted

    def _emit_finding_annotation(
        self, vuln: "VulnerabilityContext",
        checklist: Optional[Dict[str, Any]],
    ) -> Optional[Path]:
        """Emit a per-function annotation for ``vuln`` after analysis
        completes. Best-effort — any exception is logged at DEBUG and
        swallowed so annotation failures cannot break the analysis loop.

        Returns the annotation path on success, or ``None`` if the
        emit was skipped (no checklist, no inventory match, manual
        annotation already present, or an error was swallowed).
        Caller can use the return value for telemetry.
        """
        try:
            from packages.llm_analysis.annotation_emit import (
                emit_finding_annotation,
            )
            return emit_finding_annotation(
                vuln,
                base_dir=self.out_dir / "annotations",
                checklist=checklist,
                repo_root=self.repo_path,
            )
        except Exception:
            logger.debug("annotation emit error", exc_info=True)
            return None

    def _resolve_prefer_globs(
        self, operator_globs: Optional[List[str]],
    ) -> tuple:
        """Instance-method wrapper around module-level
        ``resolve_prefer_globs`` — passes the agent's
        ``self.repo_path``. Kept as a method so the call site in
        ``process_findings`` stays brief."""
        return resolve_prefer_globs(operator_globs, self.repo_path)

    def process_findings(self, sarif_paths: List[str] = None, findings_path: str = None,
                         max_findings: int = 10, checklist: Dict[str, Any] = None,
                         emit_annotations: bool = True,
                         prefer_globs: Optional[List[str]] = None,
                         exclude_globs: Optional[List[str]] = None) -> Dict[str, Any]:
        """Process findings with full LLM-powered autonomous workflow.

        ``emit_annotations``: when False, skip the per-finding
        annotation emit and the end-of-run coverage record. Useful
        for operators who want analysis without the side effect of
        modifying the annotation tree (e.g. CI runs that compare
        scanner output rather than persist review state).

        ``prefer_globs``: optional list of fnmatch globs against each
        finding's ``file_path``. Matching findings sort to the front
        of the analysis queue (before ``max_findings`` caps the set),
        so a low cap reaches attack-surface code first instead of
        analysing in arbitrary file-order. Stable within each bucket —
        existing dataflow-then-SARIF order survives for non-matching
        findings (and for ties among matches).

        ``exclude_globs``: optional list of fnmatch globs; findings
        whose ``file_path`` matches any glob are dropped before
        analysis. Operator escape hatch for vendored / test /
        generated paths the structural filters can't cover. Applied
        BEFORE prefer + cap so excluded paths don't push attack-
        surface candidates out of the captured set.
        """
        start_time = time.time()

        # Parse findings
        is_prep_only = isinstance(self.llm, ClaudeCodeProvider)
        if not is_prep_only:
            logger.info("=" * 70)
            logger.info("AUTONOMOUS VULNERABILITY ANALYSIS")
            logger.info("=" * 70)

        if findings_path:
            # Load pre-validated findings
            unique_findings = self._load_validated_findings(findings_path)
        else:
            all_findings = []
            for sarif_path in (sarif_paths or []):
                findings = parse_sarif_findings(Path(sarif_path))
                logger.info(f"Loaded {len(findings)} findings from {Path(sarif_path).name}")
                all_findings.extend(findings)

            unique_findings = deduplicate_findings(all_findings)

        # Operator-controlled exclusion: --exclude-dir GLOB drops
        # findings whose file_path matches any glob before any of the
        # prioritisation/cap steps. Applied first so excluded paths
        # never compete for slots in the captured set.
        if exclude_globs:
            before = len(unique_findings)
            unique_findings = apply_exclude_dir_globs(
                unique_findings, exclude_globs,
            )
            dropped = before - len(unique_findings)
            if dropped and not is_prep_only:
                logger.info(
                    f"--exclude-dir filtered {dropped} of {before} "
                    f"findings ({exclude_globs})"
                )

        # Prioritize findings with dataflow paths (for better validation coverage)
        findings_with_dataflow = [f for f in unique_findings if f.get('has_dataflow')]
        findings_without_dataflow = [f for f in unique_findings if not f.get('has_dataflow')]

        # Put dataflow findings first, then others
        prioritized_findings = findings_with_dataflow + findings_without_dataflow

        # Attack-surface ordering: prefer-globs from operator
        # (--prefer GLOB) take precedence; when absent, the
        # target-type catalog's ``attack_surface.high_priority_dirs``
        # supplies an implicit default for the matched target type
        # so a low ``--max-findings`` cap reaches the architectural
        # attack surface (src/http, src/protocols, ...) instead of
        # spending budget on platform shims by SARIF order luck.
        # Operator override always wins; catalog only fires when
        # the operator didn't supply globs.
        effective_globs, prefer_source = self._resolve_prefer_globs(
            prefer_globs,
        )
        if effective_globs:
            total_before = len(prioritized_findings)
            prioritized_findings = apply_prefer_globs(
                prioritized_findings, effective_globs,
            )
            matched = sum(
                1 for f in prioritized_findings
                if _file_matches_globs(
                    f.get("file_path", ""), effective_globs,
                )
            )
            if matched and not is_prep_only:
                logger.info(
                    f"attack-surface ranking ({prefer_source}): "
                    f"{matched} of {total_before} findings match "
                    f"{effective_globs} (sorted to front)"
                )

        if not is_prep_only:
            # Cap in sequential mode — in prep mode, Phase 4 enforces the cap
            prioritized_findings = prioritized_findings[:max_findings]

        if is_prep_only:
            logger.debug(f"Dedup: {len(unique_findings)} unique, {len(findings_with_dataflow)} with dataflow")
        else:
            logger.info(f"After deduplication: {len(unique_findings)} unique findings")
            logger.info(f"  With dataflow: {len(findings_with_dataflow)}")
            logger.info(f"  Without dataflow: {len(findings_without_dataflow)}")
            logger.info(f"Processing top {max_findings} findings (dataflow prioritized)")
            logger.info("=" * 70)

        unique_findings = prioritized_findings

        # Phase D PR1: prime source_intel cache for sequential mode.
        # Parallel / prep-only mode is handled by orchestrate() in the
        # parent raptor_agentic.py process — priming there doesn't
        # help THIS subprocess. Sequential mode (full LLM analysis
        # happening here) needs the cache primed locally so
        # ``tasks.py:evidence_blocks_for_finding`` finds populated
        # state when each finding's prompt bundle is assembled.
        #
        # Pre-fix the per-finding ``evidence_blocks_for_finding``
        # silently returned ``()`` because no caller had populated
        # the cache for this subprocess — gap-#2-final-E2E surfaced
        # the latent bug by observing zero source-intel-evidence
        # blocks in an /agentic --sequential run despite the wiring
        # being in place.
        if not is_prep_only and self.repo_path:
            logger.info(
                "agent.py: priming source_intel cache for %s "
                "(sequential-mode finding analysis)",
                self.repo_path,
            )
            try:
                from packages.llm_analysis.source_intel_inject import (
                    prepare_source_intel,
                )
                prepare_source_intel(self.repo_path)
            except Exception as e:  # noqa: BLE001
                # Surface at INFO so the failure path is visible in
                # operator logs — gap-#2 verification on /agentic
                # subprocess made the prior debug-level log
                # invisible, making "did this call run?" impossible
                # to answer from the log alone.
                logger.info(
                    "agent.py: prepare_source_intel(%s) failed: %s — "
                    "continuing without source_intel evidence",
                    self.repo_path, e,
                )
        else:
            logger.info(
                "agent.py: skipping source_intel cache prime "
                "(is_prep_only=%s, repo_path=%s)",
                is_prep_only, self.repo_path,
            )

        results = []
        analyzed = 0
        exploitable = 0
        exploits_generated = 0
        patches_generated = 0
        dataflow_validated = 0
        false_positives_found = 0
        annotations_emitted = 0
        variant_annotations = 0
        # D-1 fixture-detection pre-flight metrics. Counts of
        # findings the pre-flight saw and how it ruled. Surfaced
        # in the autonomous report so operators can see whether
        # the pre-flight is firing usefully and how many LLM
        # tokens it saved.
        fixture_prep_outcomes = {"true": 0, "false": 0, "candidate": 0}
        fixture_skipped_llm_calls = 0
        # Reachability-chokepoint LLM-call skips (binary_oracle_absent /
        # module_aborts / lexical_dead). Counted separately so the operator
        # can see the savings split across the two short-circuit paths.
        reachability_skipped_llm_calls = 0
        idx = 0  # Initialize idx to prevent UnboundLocalError when unique_findings is empty

        is_prep = isinstance(self.llm, ClaudeCodeProvider)

        with HackerProgress(total=len(unique_findings), operation="Analyzing vulnerabilities",
                            disabled=is_prep) as progress:
            for idx, finding in enumerate(unique_findings, 1):
                progress.update(current=idx, message=f"{finding.get('rule_id', 'unknown')}")

                if is_prep and idx % 10 == 0:
                    print(f"  Preparing... {idx}/{len(unique_findings)}", flush=True)

                if not is_prep:
                    logger.info("")
                    logger.info(f"{'█' * 70}")
                    logger.info(f"VULNERABILITY {idx}/{len(unique_findings)}")
                    logger.info(f"{'█' * 70}")

                # Attach function metadata from inventory checklist
                if checklist and not finding.get("metadata"):
                    fpath = finding.get("file_path") or finding.get("file") or ""
                    fline = finding.get("start_line") if finding.get("start_line") is not None else finding.get("startLine", 0)
                    func = _lookup_function(
                        checklist, fpath, fline,
                        repo_root=str(self.repo_path),
                    )
                    if func and func.get("metadata"):
                        finding["metadata"] = dict(func["metadata"])
                    # If /understand --map enriched the checklist, also surface
                    # the priority markers so the analysis prompt can mention
                    # the function's architectural role (entry_point / sink).
                    # Use ``or {}`` (not setdefault) — finding["metadata"] can
                    # be explicitly None from upstream SARIF parsers, and
                    # setdefault would return None in that case, then
                    # None["priority"] = ... raises TypeError.
                    if func and func.get("priority"):
                        metadata = finding.get("metadata") or {}
                        metadata["priority"] = func["priority"]
                        if func.get("priority_reason"):
                            metadata["priority_reason"] = func["priority_reason"]
                        finding["metadata"] = metadata

                # Per-function AST view enrichment. Sits outside the
                # metadata-enrichment gate above so findings that
                # arrive pre-populated with metadata (from upstream
                # scanners) still get ast_view. See
                # ``_enrich_finding_with_ast_view`` for the contract.
                _enrich_finding_with_ast_view(finding, self.repo_path)

                vuln = VulnerabilityContext(finding, self.repo_path)

                # 0. Pre-flight: D-1 fixture-detection. When the
                # finding sits in test code AND the function isn't
                # reachable from any production entry point, the
                # LLM verdict is essentially deterministic — skip
                # the LLM call to save tokens and emit a clean
                # annotation directly. Only the high-confidence
                # ``true`` case skips; ``candidate`` (path matches
                # but reachability uncertain) still runs the LLM
                # so it can verify. ``manual_override`` operator
                # flag bypasses pre-flight entirely.
                #
                # See core/inventory/fixture_detection for the
                # path + reachability gate logic; mirrors the
                # /validate Stage D [D-1] integration.
                fixture_skipped_this = False
                if checklist and not finding.get("manual_override"):
                    try:
                        from core.inventory.fixture_detection import (
                            detect_fixture,
                        )
                        verdict = detect_fixture(
                            file_path=(
                                finding.get("file_path")
                                or finding.get("file") or ""
                            ),
                            function=(
                                finding.get("function")
                                or (finding.get("metadata") or {}).get(
                                    "function_name", ""
                                )
                            ),
                            inventory=checklist,
                        )
                        finding["likely_test_harness"] = (
                            verdict.likely_test_harness
                        )
                        finding["harness_evidence"] = [
                            e.to_dict() for e in verdict.evidence
                        ]
                        fixture_prep_outcomes[
                            verdict.likely_test_harness
                        ] = (
                            fixture_prep_outcomes.get(
                                verdict.likely_test_harness, 0,
                            ) + 1
                        )
                        if verdict.likely_test_harness == "true":
                            # Synthesise a deterministic clean
                            # analysis. _derive_status (in
                            # annotation_emit) maps
                            # is_true_positive=False to status=
                            # clean automatically; the
                            # ``fixture_demotion`` tag flags the
                            # reason for the operator's review.
                            vuln.analysis = {
                                "is_true_positive": False,
                                "is_exploitable": False,
                                "reasoning": (
                                    "Test-harness circularity: the "
                                    "finding's enclosing function is "
                                    "in test-fixture code and not "
                                    "reachable from any production "
                                    "entry point. See harness_evidence "
                                    "for the path-pattern match and "
                                    "reachability check that confirmed "
                                    "this. To override, set "
                                    "``manual_override: true`` on the "
                                    "finding and re-run."
                                ),
                                "fixture_demotion": True,
                                "harness_evidence": (
                                    finding["harness_evidence"]
                                ),
                            }
                            fixture_skipped_this = True
                    except Exception as e:  # noqa: BLE001
                        logger.debug(
                            "fixture pre-flight failed on %s: %s",
                            finding.get("finding_id") or finding.get("id"),
                            e,
                        )

                if fixture_skipped_this:
                    analyzed += 1
                    fixture_skipped_llm_calls += 1
                    if emit_annotations:
                        if self._emit_finding_annotation(vuln, checklist):
                            annotations_emitted += 1
                    continue  # skip LLM analyze + exploit + patch

                # 0b. Reachability chokepoint — SOUND, corpus-earned
                # dead witness (module_aborts / lexical_dead /
                # binary_oracle_absent) on the finding's enclosing
                # function means no exploit is reachable; skip the LLM
                # call. Mirrors the codeql autonomous_analyzer
                # suppression so semgrep findings get the same cost
                # savings (Phase 3b). Uses the shared
                # ``reach_chokepoint`` helper for path/module
                # normalisation — copy-paste-reductionism in the prior
                # implementation produced silent-drop bugs on absolute
                # paths, file:// URIs, and non-Python languages where
                # ``module`` was the literal path string (adversarial
                # review P0-C-1 / P0-C-2).
                reach_skipped_this = False
                if checklist:
                    try:
                        from core.inventory.reach_chokepoint import (
                            check_suppress,
                        )
                        rel = (finding.get("file_path")
                               or finding.get("file") or "")
                        fn = (finding.get("function")
                              or (finding.get("metadata") or {}).get(
                                  "function_name", ""))
                        line_no = int(finding.get("line") or 0)
                        decision = check_suppress(
                            checklist=checklist,
                            file_path=rel, function_name=fn,
                            line=line_no,
                            repo_root=Path(self.repo_path),
                            allow_unreachable=getattr(
                                self, "allow_unreachable", False),
                            manual_override=finding.get("manual_override"),
                        )
                        if decision is not None:
                            verdict, reason = decision
                            vuln.analysis = {
                                "is_true_positive": False,
                                "is_exploitable": False,
                                "reasoning": reason,
                                "reachability_suppression": True,
                                "reachability_verdict": verdict,
                            }
                            reach_skipped_this = True
                            # Aggregate audit trail (Agent C P1-1) —
                            # one-stop ``suppressions.jsonl`` so an
                            # operator can ``jq`` / count instead of
                            # walking each per-finding annotation.
                            # Best-effort; never blocks.
                            try:
                                from core.inventory.reach_chokepoint \
                                    import record_suppression
                                record_suppression(
                                    self.out_dir,
                                    finding=finding,
                                    verdict=verdict, reason=reason,
                                )
                            except Exception:  # noqa: BLE001
                                pass
                    except Exception as e:  # noqa: BLE001
                        logger.debug(
                            "reachability pre-flight failed on %s: %s",
                            finding.get("finding_id") or finding.get("id"),
                            e,
                        )

                if reach_skipped_this:
                    analyzed += 1
                    reachability_skipped_llm_calls += 1
                    if emit_annotations:
                        if self._emit_finding_annotation(vuln, checklist):
                            annotations_emitted += 1
                    continue  # skip LLM analyze + exploit + patch

                # 1. Autonomous analysis (LLM-powered, or prep-only)
                if self.analyze_vulnerability(vuln):
                    analyzed += 1
                    if emit_annotations:
                        if self._emit_finding_annotation(vuln, checklist):
                            annotations_emitted += 1

                    # Track dataflow validation
                    if vuln.has_dataflow and vuln.analysis and 'dataflow_validation' in vuln.analysis:
                        dataflow_validated += 1
                        validation = vuln.analysis['dataflow_validation']
                        if validation.get('false_positive'):
                            false_positives_found += 1

                    if vuln.exploitable:
                        exploitable += 1

                        # 2. Generate exploit using LLM
                        if self.generate_exploit(vuln):
                            exploits_generated += 1

                        # 3. Generate patch using LLM (only for exploitable)
                        if self.generate_patch(vuln):
                            patches_generated += 1

                        # 4. KNighter follow-up: synthesise a checker
                        # rule for the confirmed pattern, run across
                        # the codebase, emit suspicious annotations
                        # for variant matches. One bug → N candidate
                        # variants. Best-effort — failures don't break
                        # the analysis loop.
                        if (
                            emit_annotations
                            and getattr(self, "synthesise_checkers", True)
                        ):
                            try:
                                from packages.llm_analysis.checker_followup import (
                                    emit_variant_annotations_for_finding,
                                )
                                n_variants = emit_variant_annotations_for_finding(
                                    vuln,
                                    out_dir=self.out_dir,
                                    checklist=checklist,
                                    repo_root=self.repo_path,
                                    llm_client=self.llm,
                                )
                                variant_annotations += n_variants
                            except Exception:
                                logger.debug(
                                    "checker followup error", exc_info=True,
                                )
                    else:
                        logger.debug("⊘ Skipping patch generation (not exploitable)")

                # Always include finding in results (with or without LLM analysis)
                results.append(vuln.to_dict())

            # Show progress
            if isinstance(self.llm, ClaudeCodeProvider):
                logger.debug(f"Progress: {idx}/{len(unique_findings)} prepped")
            else:
                logger.info("")
                logger.info(f"Progress: {idx}/{len(unique_findings)} analyzed, "
                           f"{exploitable} exploitable, "
                           f"{exploits_generated} exploits, "
                           f"{patches_generated} patches, "
                           f"{dataflow_validated} dataflow validated")

        execution_time = time.time() - start_time

        # Get LLM stats from client (aggregates all provider stats)
        llm_stats = self.llm.get_stats()

        # Determine mode: full (external LLM did analysis) or prep_only (mechanical prep,
        # Claude Code or manual review handles reasoning)
        is_prep_only = isinstance(self.llm, ClaudeCodeProvider)

        report = {
            "mode": "prep_only" if is_prep_only else "full",
            "processed": len(unique_findings),
            "prepped": len(results),
            "analyzed": analyzed,
            "exploitable": exploitable,
            "exploits_generated": exploits_generated,
            "patches_generated": patches_generated,
            "dataflow_validated": dataflow_validated,
            "false_positives_caught": false_positives_found,
            "annotations_emitted": annotations_emitted,
            "variant_annotations": variant_annotations,
            "fixture_detection_metrics": {
                "prep_outcomes": fixture_prep_outcomes,
                "skipped_llm_calls": fixture_skipped_llm_calls,
            },
            "execution_time": execution_time,
            "llm_stats": llm_stats,
            "results": results,
        }

        # Save report
        report_file = self.out_dir / "autonomous_analysis_report.json"
        save_json(report_file, report)

        # Emit a coverage record from the annotations tree, so
        # ``raptor-coverage-summary`` picks them up as reviewed
        # functions. Best-effort — coverage record failures should
        # not break the analysis report. Skipped when annotation
        # emission was suppressed.
        if emit_annotations:
            try:
                from core.coverage.record import (
                    build_from_annotations, write_record,
                )
                ann_record = build_from_annotations(self.out_dir / "annotations")
                if ann_record:
                    write_record(self.out_dir, ann_record, tool_name="annotations")
            except Exception:
                logger.debug("annotation coverage record failed", exc_info=True)

        if is_prep_only:
            logger.debug(f"Prep complete: {len(unique_findings)} findings")
        else:
            logger.info(f"✓ Processed: {len(unique_findings)} findings")
            logger.info(f"✓ Analyzed: {analyzed} with LLM")
            logger.info(f"✓ Exploitable: {exploitable} vulnerabilities")
            logger.info(f"✓ Exploits generated: {exploits_generated}")
            logger.info(f"✓ Patches generated: {patches_generated}")
            if annotations_emitted > 0:
                logger.info(
                    f"✓ Annotations emitted: {annotations_emitted} "
                    f"(in {self.out_dir / 'annotations'})"
                )
            if variant_annotations > 0:
                logger.info(
                    f"✓ Checker-synthesised variants: {variant_annotations} "
                    f"(suspicious annotations from KNighter follow-up)"
                )
            if fixture_skipped_llm_calls > 0:
                logger.info(
                    f"✓ Fixture-detection (D-1): "
                    f"{fixture_skipped_llm_calls} LLM call(s) skipped "
                    f"(test-harness circularity); prep outcomes "
                    f"{fixture_prep_outcomes}"
                )
            logger.info("")
            if dataflow_validated > 0:
                logger.info("Dataflow Validation:")
                logger.info(f"   Deep validated: {dataflow_validated} dataflow paths")
                logger.info(f"   False positives caught: {false_positives_found}")
                logger.info("")
            logger.info("LLM Statistics:")
            logger.info(f"   Total requests: {llm_stats['total_requests']}")
            logger.info(f"   Total cost: ${llm_stats['total_cost']:.4f}")
            logger.info(f"   Execution time: {execution_time:.1f}s")
        if not is_prep_only:
            logger.info("")
            logger.info(f"Report saved: {report_file}")
            logger.info("=" * 70)

        return report


def find_validation_artifacts(workdir: Path = None) -> Optional[Path]:
    """Search for validation artifacts from recent pipeline runs.

    Checks:
    - workdir/validation/findings.json (from /agentic)
    - .out/exploitability-validation-*/findings.json (from /validate)

    Returns the most recent findings.json path, or None.
    """
    candidates = []

    # Check workdir/validation/ (from /agentic pipeline)
    if workdir:
        agentic_findings = workdir / "validation" / "findings.json"
        if agentic_findings.exists():
            candidates.append(agentic_findings)

    # Check .out/exploitability-validation-*/ (from /validate)
    out_dir = Path(".out").resolve()  # Lock to absolute path at call time
    if out_dir.exists():
        for d in sorted(out_dir.glob("exploitability-validation-*"), reverse=True):
            findings_path = d / "findings.json"
            if findings_path.exists():
                candidates.append(findings_path)
                break  # Most recent only

    if candidates:
        # Return most recently modified
        return max(candidates, key=lambda p: p.stat().st_mtime)
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="RAPTOR Autonomous Security Agent"
    )
    ap.add_argument("--repo", required=True, help="Repository path")
    ap.add_argument("--sarif", nargs="+", help="SARIF files")
    ap.add_argument("--findings", help="Validated findings.json from exploitability validation pipeline")
    ap.add_argument("--out", help="Output directory")
    ap.add_argument("--max-findings", type=int, default=10, help="Max findings to process")
    ap.add_argument(
        "--prefer", action="append", default=None, metavar="GLOB",
        help=(
            "Prioritise findings whose file_path matches GLOB. Repeatable for "
            "multiple patterns (OR semantics). Sorts matching findings to the "
            "front before --max-findings caps; stable within each bucket."
        ),
    )
    ap.add_argument(
        "--exclude-dir", action="append", default=None, metavar="GLOB",
        dest="exclude_dir",
        help=(
            "Drop findings whose file_path matches GLOB before analysis. "
            "Repeatable (OR semantics). Operator escape hatch for vendored "
            "code, test fixtures, generated dirs the structural filters "
            "can't cover. Example: ``--exclude-dir 'vendor/*' "
            "--exclude-dir '**/tests/*'``"
        ),
    )
    ap.add_argument("--checklist", help="Inventory checklist.json for function metadata lookup")
    ap.add_argument(
        "--no-annotations",
        action="store_true",
        help="Skip per-finding annotation emission and the "
             "annotation-derived coverage record",
    )
    ap.add_argument(
        "--no-checker-synthesis",
        action="store_true",
        help="Skip the KNighter follow-up: don't synthesise a "
             "checker rule per confirmed finding, don't emit "
             "variant annotations. Use to cut LLM cost on confirmed "
             "exploitable findings — at the price of losing variant "
             "discovery.",
    )
    ap.add_argument(
        "--no-verify-exploits",
        action="store_true",
        help="Skip the compile-verify step on LLM-emitted exploits "
             "(default on, ~140ms per finding). Use for "
             "benchmarks / CI surfaces where every second counts. "
             "When disabled, exploit_compiled stays unset on each "
             "finding (None — verification not attempted).",
    )
    ap.add_argument(
        "--no-judge-intent",
        action="store_true",
        help="Skip the intent-match judge on LLM-emitted exploits "
             "(default on). Judge runs 4 cheap heuristics first; "
             "escalates ambiguous cases to a 2-step LLM tiebreak "
             "(~$0.001-0.01 per ambiguous finding). When disabled, "
             "intent_match stays unset on each finding (None — "
             "judge not invoked). See "
             "packages/llm_analysis/intent_match.py for design.",
    )
    ap.add_argument(
        "--no-record-witnesses",
        action="store_true",
        help="Skip recording LLM-emitted exploits as canonical "
             "Witnesses under <out>/witnesses/ (default on). "
             "Each successful exploit generation otherwise produces "
             "one Witness with source=LLM_EMIT_RUN, "
             "outcome=NOT_RUN, carrying the compile + intent-match "
             "verdicts in outcome_detail. Negligible wall-clock "
             "cost (single sha256 + JSON write per finding); the "
             "opt-out exists for benchmarks that compare runs "
             "byte-for-byte and for ephemeral CI runs that don't "
             "persist the out/ tree.",
    )
    ap.add_argument(
        "--no-verified-exemplars",
        action="store_true",
        help="Don't prime analysis prompts with RAPTOR's own prior "
             "verified outcomes (default on). When a project is active, "
             "each finding's nearest previously-confirmed outcomes "
             "(witness / CodeQL backends) are rendered as exemplars "
             "beside the curated CVE ones. No effect on a fresh run with "
             "no prior corpus; the opt-out exists for cost control and "
             "byte-for-byte run comparison.",
    )
    ap.add_argument("--prep-only", action="store_true",
                    help="Skip LLM analysis; produce structured findings for external orchestration")
    ap.add_argument("--max-parallel", type=int, default=3, help="Max parallel dispatch threads")

    model_group = ap.add_argument_group(
        "multi-model analysis",
        "When any of these flags are provided, findings are prepped then "
        "dispatched through the parallel orchestrator with role support.",
    )
    model_group.add_argument("--model", metavar="MODEL", action="append", default=[],
                             help="Analysis model (repeatable for multi-model)")
    model_group.add_argument("--consensus", metavar="MODEL",
                             help="Blind second opinion model")
    model_group.add_argument("--judge", metavar="MODEL",
                             help="Non-blind review model")
    model_group.add_argument("--aggregate", metavar="MODEL",
                             help="Final synthesis model for multi-model results")

    # IRIS Tier 2/3 deep-validate gate. Mirrors raptor_agentic.py.
    # Without these flags /analyze can never reach Tier 4 SMT
    # refinement on findings the orchestrator passed through —
    # the auto-enable on path_conditions is the only path most
    # operators take, so we want it here too.
    ap.add_argument(
        "--deep-validate",
        action="store_true",
        help="Force-enable Tier 2 / Tier 3 of IRIS validation for ALL "
             "findings: when Tier 1 is inconclusive, ask the LLM to write "
             "source+sink predicates and retry on compile errors. Costs "
             "LLM tokens. Without this flag, Tier 2/3 auto-enables per-"
             "finding when the LLM emits `path_conditions` (usage-driven "
             "default); pass --no-deep-validate to disable even that auto-"
             "enable path.",
    )
    ap.add_argument(
        "--no-deep-validate",
        action="store_true",
        help="Hard kill-switch: disable Tier 2 / Tier 3 entirely, including "
             "the default usage-driven auto-enable. Takes precedence over "
             "--deep-validate.",
    )

    args = ap.parse_args()

    if not args.sarif and not args.findings:
        ap.error("Either --sarif or --findings is required")

    _has_role_flags = any([
        getattr(args, "model", []),
        getattr(args, "consensus", None),
        getattr(args, "judge", None),
        getattr(args, "aggregate", None),
    ])

    # Suggest --findings if validation artifacts exist nearby
    if args.sarif and not args.findings:
        out_path = Path(args.out).resolve() if args.out else None
        nearby = find_validation_artifacts(out_path)
        if nearby:
            logger.info(f"Validation artifacts found at {nearby}")
            logger.info("Use --findings for enriched analysis with feasibility data")

    repo_path = Path(args.repo).resolve()
    if args.out:
        out_dir = Path(args.out).resolve()
    else:
        # Collision-prevention via unique_run_suffix — see core/run/output.py.
        out_dir = RaptorConfig.get_out_dir() / f"autonomous_v2_{unique_run_suffix('_')}"

    # When role flags are present, force prep-only then hand off to orchestrator
    prep_only = args.prep_only or _has_role_flags
    agent = AutonomousSecurityAgentV2(
        repo_path, out_dir,
        prep_only=prep_only,
        synthesise_checkers=not args.no_checker_synthesis,
        verify_exploits=not args.no_verify_exploits,
        judge_intent=not args.no_judge_intent,
        record_witnesses=not args.no_record_witnesses,
        use_verified_exemplars=not args.no_verified_exemplars,
    )

    # Load checklist for metadata lookup
    checklist = None
    if args.checklist:
        # Non-strict: checklist is optional metadata, pipeline continues without it
        checklist = load_json(args.checklist)
        if checklist:
            logger.info(f"Loaded inventory checklist: {args.checklist}")
        else:
            logger.warning(f"Could not load checklist: {args.checklist}")

    # Process findings - route based on input type
    emit_annotations = not args.no_annotations
    if args.findings:
        report = agent.process_findings(findings_path=args.findings, max_findings=args.max_findings,
                                        checklist=checklist,
                                        emit_annotations=emit_annotations,
                                        prefer_globs=args.prefer,
                                        exclude_globs=args.exclude_dir)
    else:
        report = agent.process_findings(sarif_paths=args.sarif, max_findings=args.max_findings,
                                        checklist=checklist,
                                        emit_annotations=emit_annotations,
                                        prefer_globs=args.prefer,
                                        exclude_globs=args.exclude_dir)

    # Orchestrated path: role flags → prep then parallel dispatch
    if _has_role_flags and report.get("mode") == "prep_only":
        prep_report_path = out_dir / "autonomous_analysis_report.json"
        if prep_report_path.exists():
            from packages.llm_analysis.orchestrator import (
                build_llm_config_from_flags, orchestrate,
            )
            llm_config = build_llm_config_from_flags(
                models=args.model or [],
                consensus=args.consensus,
                judge=args.judge,
                aggregate=args.aggregate,
            )
            if llm_config:
                result = orchestrate(
                    prep_report_path=prep_report_path,
                    repo_path=repo_path,
                    out_dir=out_dir,
                    max_parallel=args.max_parallel,
                    max_findings=args.max_findings,
                    llm_config=llm_config,
                    deep_validate=getattr(args, "deep_validate", False),
                    deep_validate_disabled=getattr(args, "no_deep_validate", False),
                )
                if result:
                    return
        print("\n  Orchestration skipped — check model/API key configuration")
        return

    if report.get('mode') != 'prep_only':
        print("\n" + "=" * 70)
        print("Autonomous Security Agent Report")
        print("=" * 70)
        print(f"Analyzed: {report['analyzed']}")
        print(f"Exploitable: {report['exploitable']}")
        print(f"Exploits generated: {report['exploits_generated']} (LLM-generated)")
        print(f"Patches generated: {report['patches_generated']} (LLM-generated)")
        # IRIS Tier 1/2/3/4 + path_conditions telemetry — same
        # surfacing /agentic uses (raptor_agentic.py). Renders only
        # when validation actually ran on at least one finding;
        # silent on prep-only / no-CodeQL-DB runs. Indent at zero
        # because /analyze's report uses flat lines (no leading
        # whitespace), unlike /agentic which uses "   " for the
        # nested-under-summary cadence.
        from core.reporting.dataflow_summary import render_dataflow_validation_lines
        dv = (report or {}).get("dataflow_validation") or {}
        for line in render_dataflow_validation_lines(dv, indent=""):
            print(line)
        print(f"LLM cost: ${report['llm_stats']['total_cost']:.4f}")
        print(f"Output: {out_dir}")
        print("=" * 70)


if __name__ == "__main__":
    try:
        main()
    except SandboxSetupError as e:
        # Emit the dedicated exit code so the /agentic parent translates it
        # into a fail-loud abort instead of treating an empty report as a
        # silent "analysis produced no output".
        print(f"\n✗ Analysis aborted — sandbox isolation could not engage.\n{e}",
              file=sys.stderr)
        sys.exit(SANDBOX_ENGAGE_EXIT_CODE)
