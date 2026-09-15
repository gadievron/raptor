"""AST-based lint rule for report-writer output sanitisation.

Companion to :mod:`core.security.prompt_envelope_audit` (input side).
Where the envelope audit stops attacker text from reaching LLM prompts
raw, this audit stops LLM-returned text from reaching rendered report /
terminal surfaces raw. The canonical defence is
:mod:`core.security.prompt_output_sanitise` (``sanitise_string`` /
``sanitise_code``) plus the per-module single-line helpers built on it
(``_line`` / ``_cell`` / ``_prose`` / ``_md_heading`` /
``_md_escape_inline`` / ``_md_table_cell`` / ``_fence``).

Mechanism — deliberately explicit and low-maintenance:

* **Registry of audited writers** (:data:`_REPORT_WRITER_FILES`): only
  files registered here are walked. A new report writer must be added
  explicitly, which forces a security review at file-add time — the
  same opt-in discipline as ``_PROMPT_CONSTRUCTION_FILES`` in the
  envelope audit.
* **Known-foreign-value detection** (:data:`_LLM_DERIVED_KEYS` +
  :data:`_TOOL_OUTPUT_KEYS`): the rule looks for reads of free-text
  fields that carry LLM output (``title``, ``claim``, ``body``,
  ``reasoning``, ...) or tool output (``stderr``, ``stdout`` —
  subprocess streams quote hostile-target bytes) via attribute access
  (``entry.body``, ``proc.stderr``), string-key subscript
  (``f["title"]``), ``.get("title")`` calls, and ``getattr(x,
  "body")``. ``sys.stderr``/``sys.stdout`` (the streams themselves)
  are excluded.
* **Write-sink detection**: a violation fires only when such a value
  reaches a write sink — ``print(...)``, ``.write(...)`` /
  ``.write_text(...)``, ``.append(...)`` / ``.extend(...)`` on a
  report-line accumulator (receiver name containing ``lines`` /
  ``rows`` / ``sections`` / ``parts``), or a ``ReportSection(...)``
  constructor — without passing through a recognised sanitiser call
  (:data:`_SANITISERS`).
* **One-level local taint**: ``x = f.get("title")`` marks ``x`` tainted
  within the enclosing function (also through ``for x in <tainted>``),
  so the common assign-then-emit pattern is caught. Cross-function
  dataflow is out of scope (documented limitation, same as the envelope
  audit).
* **Mermaid fence rule** (:data:`_MERMAID_FENCE_FILES`): in the diagram
  renderer, any f-string interpolation *inside* a ```` ```mermaid ````
  fence must be a sanitiser call (``_fence`` / ``sanitise_code``) so a
  generated diagram string cannot terminate the fence and spill live
  markdown.

Extending:

* New report writer → append its repo-relative path to
  :data:`_REPORT_WRITER_FILES` and route every LLM-derived value
  through ``core.security.prompt_output_sanitise`` (free text) or a
  single-line helper (headings / labels / table cells).
* New LLM-derived field name → add to :data:`_LLM_DERIVED_KEYS`
  (tool-output field names go to :data:`_TOOL_OUTPUT_KEYS`).
* New sanitising helper → add its (function) name to
  :data:`_SANITISERS`; the helper must itself call
  ``sanitise_string`` / ``sanitise_code``.
* Genuinely-safe call site that fires anyway → add an
  :class:`AllowlistEntry` with a one-line ``audit_note`` explaining why
  (same discipline as the envelope audit; the test rejects empty / TODO
  notes).
"""

from __future__ import annotations

import ast
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

# Repository root (this file lives at core/security/report_writer_audit.py).
_REPO_ROOT = Path(__file__).resolve().parents[2]


# Free-text field names whose values carry LLM output (journal entries,
# findings, hypotheses, annotations, stage reviews). Reads of these via
# attribute / subscript / .get() / getattr() are treated as LLM-derived.
# Deliberately excludes ubiquitous label fields (``file``, ``function``,
# ``status``, ``severity``) — those are sanitised in the fixed writers
# too, but auditing them mechanically would drown the rule in noise from
# non-report code paths. The free-text fields are where markup/autofetch
# injection lives.
_LLM_DERIVED_KEYS = frozenset({
    "title",
    "claim",
    "body",
    "reasoning",
    "summary",
    "description",
    "remediation",
    "attack_scenario",
    "prediction",
    "rationale",
    "hypothesis",
    "stage_f_review",
    "stage_f_summary",
    "error",
    # OSV advisory free text (attacker-writable markdown; the sca
    # report embeds it inside a <details> block).
    "details",
})


# Tool-output field names: subprocess/tool stdout+stderr carry
# target-derived bytes (compiler diagnostics quote hostile source,
# `git apply` failures quote hostile context lines, ASAN reports quote
# hostile data). core.security.log_sanitisation names subprocess
# stderr a canonical untrusted input; the audit treats reads of these
# fields exactly like LLM-derived free text. Kept as a separate set so
# the two provenance classes stay individually documentable, merged at
# detection time.
_TOOL_OUTPUT_KEYS = frozenset({
    "stderr",
    "stdout",
})

_FOREIGN_KEYS = _LLM_DERIVED_KEYS | _TOOL_OUTPUT_KEYS


# Calls recognised as neutralising a value for report / terminal
# rendering. A subtree rooted at one of these calls is considered
# sanitised. ``escape_nonprintable`` is intentionally NOT in this set:
# it kills ANSI/control bytes but does not strip autofetch markup or
# defang markdown, and it has no length bound — the report layer
# requires the full prompt_output_sanitise pipeline.
# ``sanitise_for_terminal`` IS accepted: terminal-only writers escape
# control bytes and bound length, and markdown never renders on a TTY
# (the full pipeline would additionally strip line-leading `#`/`*`
# from operator-visible paths — wrong for terminal output). The
# surface type (terminal vs markdown) is adjudicated at file-add
# time, the registry's review checkpoint: markdown writers must use
# the prompt_output_sanitise family, terminal writers may use
# ``sanitise_for_terminal``.
_SANITISERS = frozenset({
    "sanitise_string",
    "sanitise_code",
    # Single-line-slot variant (headings / labels / table cells):
    # newline-flattened, autofetch-stripped, control-escaped, capped.
    "sanitise_inline",
    "sanitise_for_terminal",
    # Conventional local alias for sanitise_for_terminal
    # (`from core.security.log_sanitisation import sanitise_for_terminal
    # as _sft`) — same discipline as the _line/_cell helper names.
    "_sft",
    # sca bump's terminal helper (escape + bound, sanitise_for_terminal
    # grade).
    "_term",
    # Per-module single-line / cell / prose helpers built on the above.
    # exploitability_validation.report's shared helpers (sanitise_line
    # wraps sanitise_string; sanitise_cell adds pipe-escaping on top).
    "sanitise_line",
    "sanitise_cell",
    "_line",
    "_cell",
    "_prose",
    "_fence",
    "_err",
    "_md_heading",
    # binary_analysis' shared markdown-cell chokepoint
    # (investigation._md_escape: escape_nonprintable + pipe/newline
    # escaping — table-cell grade for binary-derived names).
    "_md_escape",
    # packages/diagram's Mermaid chokepoints: sanitize.sanitize
    # (imported as _sanitize; Mermaid-structure neutralisation +
    # fence-break ZWSP + escape_nonprintable), the context_map _text
    # wrapper over it, and sanitize_id (imported as _sid; strips to
    # [A-Za-z0-9_-]).
    "_sanitize",
    "_text",
    "_sid",
    "sanitize_id",
    "_md_escape_inline",
    "_md_table_cell",
    "_render_detail",
    # packages/sca's shared markdown neutralisers (packages.sca._md):
    # escape structural markdown/HTML + non-printables for inline text
    # and code spans/cells; every sca renderer routes untrusted values
    # through them.
    "neutralize_inline",
    "inline_code",
    "code_cell",
    "md_cell",
})


# Write sinks. ``echo``/``secho`` cover the typer/click terminal
# sinks in both import forms (``typer.echo(...)`` is an Attribute
# call, ``from typer import echo`` a Name call) — a CLI built on
# typer otherwise relays foreign text invisibly to this audit.
_SINK_FUNCTIONS = frozenset({"print", "echo", "secho"})
_SINK_METHODS = frozenset({"write", "write_text"})
_ACCUMULATE_METHODS = frozenset({"append", "extend"})
# ``bullets``: packages/sca/report.py's per-finding renderer
# accumulates its markdown through a ``bullets`` list — without the
# token the file's registration was vacuous (reverting its sanitiser
# calls never fired the audit; only the regression tests caught it).
_ACCUMULATOR_TOKENS = ("lines", "rows", "sections", "parts", "bullets")
_REPORT_CONSTRUCTORS = frozenset({"ReportSection"})


# Files whose job is writing operator-facing report / terminal output
# from LLM-derived data. The audit only walks these — a new report
# writer needs an explicit add (forcing a security review at file-add
# time).
_REPORT_WRITER_FILES = (
    "core/analysis/binary_oracle.py",
    "core/analysis/binary_oracle_cli.py",
    "core/audit/report.py",
    # The per-function review-progress stream (format_progress_line):
    # target-derived file/function names and verbatim announcement
    # bodies printed to the operator terminal by libexec/raptor-audit.
    "core/audit/_util.py",
    "core/llm/multi_model/replay.py",
    "core/progress/__init__.py",
    "core/project/cli.py",
    "core/reporting/renderer.py",
    "core/run/provenance.py",
    # SAGE boot-payload review: the compare display prints
    # server-derived variant diffs at the operator's approve/reject
    # surface. Terminal writer — sanitise_for_terminal grade via its
    # `_line` helper. (The install-lane sibling display lives in
    # libexec/raptor-sage-setup, a bash script this AST detector
    # cannot walk; the approval-surface registry test covers it.)
    "core/sage/boot_payload_review.py",
    "core/llm/scorecard/audit.py",
    "core/llm/scorecard/cli.py",
    "core/project/report.py",
    "core/reporting/findings.py",
    "core/sandbox/calibrate_cli.py",
    "core/sandbox/triage.py",
    "packages/binary_analysis/cli.py",
    "packages/binary_analysis/harness.py",
    "packages/binary_analysis/investigation.py",
    "packages/binary_analysis/pipeline.py",
    # cve_diff terminal lanes: bench result echoes (agent/tool error
    # text) and the run-mode flow.md relay (typer.echo sinks).
    "packages/cve_diff/cve_diff/cli/bench.py",
    "packages/cve_diff/cve_diff/cli/main.py",
    "packages/cve_env/cve_env/cli.py",
    "packages/describe/report.py",
    "packages/diagram/attack_paths.py",
    "packages/diagram/attack_tree.py",
    "packages/diagram/context_map.py",
    "packages/diagram/edge_obligations.py",
    "packages/diagram/flow_trace.py",
    "packages/diagram/hypotheses.py",
    "packages/diagram/renderer.py",
    "packages/exploitability_validation/report.py",
    # Second validation-report.md generator (the orchestrator's
    # inline _generate_report/_render_finding_lines) — same artifact,
    # same finding-derived interpolations, must stay under audit.
    "packages/exploitability_validation/orchestrator.py",
    # /understand verbose producers: model text + tool-arg summaries
    # reach the operator's stderr through a consumer-supplied logger
    # CALLBACK (raptor-understand's _verbose_logger). Callback
    # invocations are outside the detector's sink vocabulary (a
    # documented walk-scope limit) — the lanes are sanitised at
    # production AND at the raptor-understand sink; registration keeps
    # any future direct print/write lanes in these files under audit.
    "packages/code_understanding/dispatch/hunt_dispatch.py",
    "packages/code_understanding/dispatch/trace_dispatch.py",
    "packages/frida/cli.py",
    # Patch oracle: captured target stdio rides RuntimeError text to
    # the operator terminal; escaped at construction and at the CLI
    # print. Terminal writer — sanitise_for_terminal grade.
    "packages/frida/patch_oracle.py",
    "packages/frida/runner.py",
    "packages/ghidra/decomp_tree.py",
    "packages/llm_analysis/agent.py",
    "packages/llm_analysis/dispatch.py",
    "packages/llm_analysis/orchestrator.py",
    "packages/llm_analysis/patch_gate.py",
    "packages/llm_analysis/tasks.py",
    "packages/sca/patch_apply.py",
    "packages/static-analysis/scanner.py",
    "raptor_agentic.py",
    "libexec/raptor-audit",
    "libexec/raptor-review",
    "libexec/raptor-study-loop",
    "libexec/raptor-synthesise-checker",
    "libexec/raptor-understand",
    "libexec/raptor-validation-helper",
    "libexec/raptor-annotate",
    "libexec/raptor-coverage-summary",
    "libexec/raptor-llm-ask",
    # packages/sca operator-facing renderers / CLI printers: report.md
    # and terminal output interpolate manifest-, OSV-, and LLM-derived
    # strings.
    "packages/sca/report.py",
    "packages/sca/optimise.py",
    "packages/sca/health.py",
    "packages/sca/diff.py",
    "packages/sca/review.py",
    # sca terminal lanes on the default-scan and CI-gate paths: the
    # transitive summary quotes resolver stderr (hostile-manifest
    # bytes), the threshold gate quotes OSV advisory free text, and
    # the suppress CLI prints fields from the SCANNED target's
    # suppress YAML. Terminal writers — sanitise_for_terminal grade.
    "packages/sca/cli.py",
    "packages/sca/thresholds.py",
    "packages/sca/suppress_cli.py",
)


# Files that embed generated Mermaid diagram strings inside markdown
# fences. Interpolations inside a ```mermaid fence must be sanitiser
# calls (``_fence`` / ``sanitise_code``).
_MERMAID_FENCE_FILES = (
    "packages/diagram/renderer.py",
)


@dataclass(frozen=True)
class Violation:
    file: str        # relative path from repo root
    line: int
    kind: str        # "unsanitised_llm_value" | "unsanitised_mermaid_embed"
    detail: str      # key name or expression text
    func_name: str   # enclosing function (best-effort, dotted)


@dataclass(frozen=True)
class AllowlistEntry:
    """A pre-approved sink interpolation. Each entry MUST carry an
    ``audit_note`` explaining why this specific call site is safe.
    Content-keyed (file, func_name, kind, detail) — survives unrelated
    line churn, re-fires when the call site itself changes.
    """
    file: str
    func_name: str
    kind: str
    detail: str
    audit_note: str


# Pre-approved sink interpolations. Each entry carries an audit_note —
# a one-line explanation of why the call site is safe despite firing
# the heuristic. New entries require the same discipline (enforced by
# the test suite: empty / TODO notes are rejected).
_ALLOWLIST: tuple[AllowlistEntry, ...] = (
    AllowlistEntry(
        file="packages/cve_diff/cve_diff/cli/bench.py",
        func_name="_render_html",
        kind="unsanitised_llm_value",
        detail="detail",
        audit_note=(
            "the FAIL branch routes r.error through the module's _esc "
            "(html.escape + escape_nonprintable) before it lands in the "
            "cell; the local helper is outside the audit's sanitiser "
            "vocabulary, so the escaped assignment still reads as taint"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_rules",
        kind="unsanitised_llm_value",
        detail="path",
        audit_note=(
            "path is the Path save_rule returns — a RAPTOR-constructed "
            "rule-file location under out_dir, not LLM text; the taint "
            "is a same-assignment false positive from the description "
            "kwarg passed INTO save_rule"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_report",
        kind="unsanitised_llm_value",
        detail="summary",
        audit_note=(
            "report['summary'] is built by core/audit/report."
            "_format_summary — a registered writer that routes every "
            "free-text field through _line — so the string is "
            "sanitised at construction"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_print_map_summary",
        kind="unsanitised_llm_value",
        detail="summary",
        audit_note=(
            "payload['correlation']['summary'] is the internally-built "
            "count dict (surfaces/flows/... integers); the taint is the "
            "'summary' key name, not LLM text"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_print_investigation_summary",
        kind="unsanitised_llm_value",
        detail="summary",
        audit_note=(
            "investigation['summary'] is the internally-built count "
            "dict; only integer counters are interpolated — the "
            "name-bearing fields on the same surface go through "
            "sanitise_for_terminal"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/pipeline.py",
        func_name="_write_report",
        kind="unsanitised_llm_value",
        detail="lines",
        audit_note=(
            "'lines' is tainted only via class_summary "
            "(class_inventory['summary'] — internally-built integer "
            "counts); every name-bearing interpolation in the report "
            "goes through the _esc chokepoint"
        ),
    ),
    AllowlistEntry(
        file="packages/cve_env/cve_env/cli.py",
        func_name="_cmd_build",
        kind="unsanitised_llm_value",
        detail="cve",
        audit_note=(
            "cve.cve_id passes the argparse _validate_cve_id format "
            "validator (strict CVE-id shape); the taint chains through "
            "the record construction, not free text"
        ),
    ),
    AllowlistEntry(
        file="packages/cve_env/cve_env/cli.py",
        func_name="_cmd_build",
        kind="unsanitised_llm_value",
        detail="outcome_json",
        audit_note=(
            "machine-readable outcome document on stdout consumed by "
            "bench pipelines (sidecar parity contract) — must stay "
            "byte-exact dumps_artifact output; the human render of the "
            "same data goes through the _e escaping funnel"
        ),
    ),
    AllowlistEntry(
        file="packages/diagram/context_map.py",
        func_name="generate",
        kind="unsanitised_llm_value",
        detail="ep_ids",
        audit_note=(
            "comma-join of _sid(...) outputs — every element passes "
            "sanitize_id; the taint is the comprehension's iterable "
            "name, not the joined values"
        ),
    ),
    AllowlistEntry(
        file="packages/diagram/context_map.py",
        func_name="generate",
        kind="unsanitised_llm_value",
        detail="sink_ids",
        audit_note=(
            "comma-join of _sid(...) outputs — every element passes "
            "sanitize_id; the taint is the comprehension's iterable "
            "name, not the joined values"
        ),
    ),
    AllowlistEntry(
        file="packages/diagram/context_map.py",
        func_name="generate",
        kind="unsanitised_llm_value",
        detail="fn_ids",
        audit_note=(
            "comma-join of _sid(...) outputs — every element passes "
            "sanitize_id; the taint is the comprehension's iterable "
            "name, not the joined values"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="n_corr",
        audit_note=(
            "integer count from the internally-built correlation "
            "summary (total_correlated), not LLM text"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="n_agreed",
        audit_note=(
            "integer count from the internally-built correlation "
            "summary (agreed), not LLM text"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="n_disputed",
        audit_note=(
            "integer count from the internally-built correlation "
            "summary (disputed), not LLM text"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-study-loop",
        func_name="_synthesise_overview",
        kind="unsanitised_llm_value",
        detail="cost",
        audit_note=(
            "cost is float()-coerced LLM-call cost telemetry "
            "(getattr(response, 'cost')), rendered as $%.4f — the "
            "taint chains through the response object, not text"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-synthesise-checker",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="seed",
        audit_note=(
            "only seed.line_start/line_end (argparse ints) print via "
            "the tainted name; seed.file/seed.function are wrapped in "
            "_sft on the same line — taint chains through the SeedBug "
            "constructor's reasoning kwarg"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-synthesise-checker",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="result",
        audit_note=(
            "only result.rule_path (RAPTOR-constructed path), "
            "positive_control (bool), len(result.matches), and "
            "result.capped (bool) print via the tainted name; every "
            "text field is _sft-wrapped — taint chains through the "
            "synthesis call's seed argument"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-synthesise-checker",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="cap",
        audit_note=(
            "cap is one of two constant strings ('' / ' (capped)'); "
            "the taint is the IfExp condition reading result.capped"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-synthesise-checker",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="m",
        audit_note=(
            "only m.line (int) prints via the tainted name; m.file and "
            "the snippet lines are _sft-wrapped on the same lines"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-understand",
        func_name="_print_summary",
        kind="unsanitised_llm_value",
        detail="parts",
        audit_note=(
            "every element of parts is built from two "
            "sanitise_for_terminal calls; the taint is the "
            "comprehension's iterable (summary keys), not the "
            "rendered values"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_run",
        kind="unsanitised_llm_value",
        detail="line",
        audit_note=(
            "verbatim relay of the raptor-run-lifecycle stub's stdout "
            "— RAPTOR's own trusted child, and the OUTPUT_DIR= "
            "sentinel is parsed downstream, so the relay must stay "
            "byte-exact (EXECUTION RULES)"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_run",
        kind="unsanitised_llm_value",
        detail="out_dir",
        audit_note=(
            "out_dir is the lifecycle-resolved output directory path "
            "(RAPTOR-constructed), parsed from the trusted stub's "
            "OUTPUT_DIR= sentinel"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_run",
        kind="unsanitised_llm_value",
        detail="bo_counts",
        audit_note=(
            "binary-oracle classification counters (ints) from "
            "enrich_inventory_with_binary_oracle"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_run",
        kind="unsanitised_llm_value",
        detail="_provision",
        audit_note=(
            "CodeQL provisioning counts and detected language names — "
            "RAPTOR-authored provisioning metadata, not tool/LLM text"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_run",
        kind="unsanitised_llm_value",
        detail="_skip",
        audit_note=(
            "provisioning skip records carry code-authored reason/"
            "remedy strings and detected language names"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_run_active_phase",
        kind="unsanitised_llm_value",
        detail="stdout",
        audit_note=(
            "verbatim tool-output capture into the run's stdout.txt "
            "artifact log — raw by design, not a rendered report"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_run_active_phase",
        kind="unsanitised_llm_value",
        detail="stderr",
        audit_note=(
            "verbatim tool-output capture into the run's stderr.txt "
            "artifact log — raw by design, not a rendered report"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_run_trace_parser",
        kind="unsanitised_llm_value",
        detail="stderr",
        audit_note=(
            "phase['stderr'] is the PATH of the stderr artifact log "
            "(RAPTOR-constructed), not stream content"
        ),
    ),
    AllowlistEntry(
        file="raptor_agentic.py",
        func_name="_run_fuzz_validation_smoke",
        kind="unsanitised_llm_value",
        detail="stdout",
        audit_note=(
            "verbatim child-output capture into the validation dir's "
            "artifact log — raw by design, not a rendered report"
        ),
    ),
    AllowlistEntry(
        file="raptor_agentic.py",
        func_name="_run_fuzz_validation_smoke",
        kind="unsanitised_llm_value",
        detail="stderr",
        audit_note=(
            "verbatim child-output capture into the validation dir's "
            "artifact log — raw by design, not a rendered report"
        ),
    ),
    AllowlistEntry(
        file="raptor_agentic.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="error",
        audit_note=(
            "scan_metrics.json findings_by_severity['error'] is an "
            "integer severity counter written by RAPTOR's own scan "
            "stage — the 'Critical:' line interpolates the count"
        ),
    ),
    AllowlistEntry(
        file="core/reporting/findings.py",
        func_name="findings_summary_line",
        kind="unsanitised_llm_value",
        detail="error",
        audit_note=(
            "counts['error'] is an integer statistics counter (number of "
            "error-status findings), not LLM text — the summary line "
            "interpolates the count, never a message"
        ),
    ),
)


def _call_name(node: ast.AST) -> str | None:
    """Return the called function's short name for a Call node."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
    return None


def _key_expr(node: ast.AST) -> str | None:
    """Return the LLM-derived key name if ``node`` reads one.

    Recognises ``x.title``, ``x["title"]``, ``x.get("title", ...)``,
    and ``getattr(x, "title", ...)``.
    """
    if isinstance(node, ast.Attribute) and node.attr in _FOREIGN_KEYS:
        # ``sys.stderr`` / ``sys.stdout`` are the STREAMS, not
        # tool-output text (`print(..., file=sys.stderr)` would fire
        # on every stderr print in the tree).
        if (node.attr in _TOOL_OUTPUT_KEYS
                and isinstance(node.value, ast.Name)
                and node.value.id in ("sys", "_sys")):
            return None
        return node.attr
    if isinstance(node, ast.Subscript):
        sl = node.slice
        if (isinstance(sl, ast.Constant) and isinstance(sl.value, str)
                and sl.value in _FOREIGN_KEYS):
            return sl.value
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "get" and node.args:
            a0 = node.args[0]
            if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)
                    and a0.value in _FOREIGN_KEYS):
                return a0.value
        if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and len(node.args) >= 2):
            a1 = node.args[1]
            if (isinstance(a1, ast.Constant) and isinstance(a1.value, str)
                    and a1.value in _FOREIGN_KEYS):
                return a1.value
    return None


def _naked_keys(
    node: ast.AST,
    tainted: frozenset,
) -> list[tuple[int, str]]:
    """Return (line, key) pairs for LLM-derived reads in ``node`` that
    are NOT inside a recognised sanitiser call. ``tainted`` names count
    as LLM-derived reads too (one-level local taint)."""
    out: list[tuple[int, str]] = []

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Call) and _call_name(n) in _SANITISERS:
            return  # sanitised subtree — everything below is defanged
        key = _key_expr(n)
        if key is not None:
            out.append((getattr(n, "lineno", 0), key))
        if isinstance(n, ast.Name) and n.id in tainted:
            out.append((getattr(n, "lineno", 0), n.id))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            # A method reference (`severity.title()`, `text.strip()`) is
            # not a field read — skip the func Attribute itself but keep
            # walking the receiver and the arguments.
            walk(n.func.value)
            for child in list(n.args) + [kw.value for kw in n.keywords
                                         if kw.value is not None]:
                walk(child)
            return
        for child in ast.iter_child_nodes(n):
            walk(child)

    walk(node)
    return out


def _target_names(target: ast.AST) -> list[str]:
    """Flatten assignment / loop targets into plain names."""
    if isinstance(target, ast.Name):
        return [target.id]
    if isinstance(target, (ast.Tuple, ast.List)):
        names: list[str] = []
        for elt in target.elts:
            names.extend(_target_names(elt))
        return names
    return []


def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted source name for a receiver expression.

    ``self.lines`` → ``"self.lines"``; a non-Name/Attribute link in the
    chain (call, subscript, …) contributes nothing, so
    ``build().lines`` → ``"lines"``.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


class _Scanner(ast.NodeVisitor):
    """Walk one module, tracking function frames and one-level taint."""

    def __init__(self, rel: str) -> None:
        self.rel = rel
        self.violations: list[Violation] = []
        self._fn_stack: list[str] = []
        self._tainted_stack: list[set] = [set()]

    # -- frames -------------------------------------------------------

    @property
    def _tainted(self) -> set:
        return self._tainted_stack[-1]

    def _qualified_func_name(self) -> str:
        return ".".join(self._fn_stack) if self._fn_stack else "<module>"

    def _enter_frame(self, name: str) -> None:
        self._fn_stack.append(name)
        # Nested scopes inherit the enclosing taint view (closures read
        # outer locals); a copy keeps inner additions from leaking out.
        self._tainted_stack.append(set(self._tainted))

    def _leave_frame(self) -> None:
        self._fn_stack.pop()
        self._tainted_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_frame(node.name)
        self.generic_visit(node)
        self._leave_frame()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_frame(node.name)
        self.generic_visit(node)
        self._leave_frame()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._fn_stack.append(node.name)
        self.generic_visit(node)
        self._fn_stack.pop()

    # -- taint --------------------------------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if _naked_keys(node.value, frozenset(self._tainted)):
            for target in node.targets:
                for name in _target_names(target):
                    self._tainted.add(name)
        else:
            # A sanitised (or unrelated) re-assignment clears the taint —
            # `body = _prose(body)` makes later uses of `body` safe.
            for target in node.targets:
                for name in _target_names(target):
                    self._tainted.discard(name)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if _naked_keys(node.iter, frozenset(self._tainted)):
            for name in _target_names(node.target):
                self._tainted.add(name)
        self.generic_visit(node)

    # -- sinks --------------------------------------------------------

    def _sink_args(self, node: ast.Call) -> list[ast.AST] | None:
        """Return the argument expressions if ``node`` is a write sink."""
        func = node.func
        if isinstance(func, ast.Name):
            if func.id in _SINK_FUNCTIONS or func.id in _REPORT_CONSTRUCTORS:
                return list(node.args) + [kw.value for kw in node.keywords
                                          if kw.value is not None]
            return None
        if isinstance(func, ast.Attribute):
            if func.attr in _REPORT_CONSTRUCTORS:
                return list(node.args) + [kw.value for kw in node.keywords
                                          if kw.value is not None]
            if func.attr in ("echo", "secho"):
                # typer.echo / click.secho attribute-form terminal
                # sinks (module receivers, occasionally aliased).
                return list(node.args) + [kw.value for kw in node.keywords
                                          if kw.value is not None]
            if func.attr in _SINK_METHODS:
                return list(node.args)
            if func.attr in _ACCUMULATE_METHODS:
                # Receivers are frequently Attribute chains
                # (``self.lines.append``, ``report.rows.extend``), not
                # bare Names — match tokens across the whole dotted
                # chain so method-style report writers are not
                # invisible to the audit.
                receiver_name = _dotted_name(func.value)
                if any(tok in receiver_name.lower() for tok in _ACCUMULATOR_TOKENS):
                    return list(node.args)
            return None
        return None

    def visit_Call(self, node: ast.Call) -> None:
        args = self._sink_args(node)
        if args is not None:
            tainted = frozenset(self._tainted)
            for arg in args:
                for line, key in _naked_keys(arg, tainted):
                    self.violations.append(Violation(
                        file=self.rel,
                        line=line or node.lineno,
                        kind="unsanitised_llm_value",
                        detail=key,
                        func_name=self._qualified_func_name(),
                    ))
        self.generic_visit(node)


def _mermaid_scan(tree: ast.AST, rel: str) -> list[Violation]:
    """Flag f-string interpolations inside ```mermaid fences that are
    not sanitiser calls."""
    # First pass: collect hits without attribution. The parents map
    # used only to name the enclosing function costs O(nodes) dict
    # inserts per module — building it eagerly dominated whole-tree
    # scans (the closure gate walks every candidate file, and almost
    # all of them are fence-free) — so it is built lazily, only when
    # a violation actually needs a function name.
    hits: list[tuple[ast.FormattedValue, ast.JoinedStr]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        in_fence = False
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                text = part.value
                if in_fence and "```" in text:
                    in_fence = False
                if "```mermaid" in text:
                    in_fence = True
            elif isinstance(part, ast.FormattedValue) and in_fence:
                if _call_name(part.value) not in _SANITISERS:
                    hits.append((part, node))
    if not hits:
        return []

    # Track enclosing function names for the report.
    parents: dict = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def _func_of(node: ast.AST) -> str:
        names: list[str] = []
        cur = parents.get(node)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.append(cur.name)
            cur = parents.get(cur)
        return ".".join(reversed(names)) or "<module>"

    out: list[Violation] = []
    for part, node in hits:
        try:
            src = ast.unparse(part.value)
        except (AttributeError, ValueError):
            src = "<expr>"
        out.append(Violation(
            file=rel,
            line=part.lineno,
            kind="unsanitised_mermaid_embed",
            detail=src[:80],
            func_name=_func_of(node),
        ))
    return out


def audit_source(source: str, rel: str = "<snippet>") -> list[Violation]:
    """Audit a source string. Used by the self-tests and by
    :func:`audit_file`."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    scanner = _Scanner(rel)
    scanner.visit(tree)
    violations = scanner.violations
    violations.extend(_mermaid_scan(tree, rel))
    return violations


def audit_file(path: Path) -> list[Violation]:
    """Audit one file on disk (Python source; libexec scripts parse the
    same way despite having no ``.py`` suffix)."""
    if not path.exists():
        return []
    try:
        source = path.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        rel = str(path.relative_to(_REPO_ROOT))
    except ValueError:
        rel = str(path)
    return audit_source(source, rel)


def audit_repo(
    files: Iterable[str] = _REPORT_WRITER_FILES + _MERMAID_FENCE_FILES,
) -> list[Violation]:
    """Audit every registered writer (relative to repo root)."""
    out: list[Violation] = []
    for rel in files:
        out.extend(audit_file(_REPO_ROOT / rel))
    return out


def filter_allowlisted(
    violations: Iterable[Violation],
    allowlist: tuple[AllowlistEntry, ...] = _ALLOWLIST,
) -> list[Violation]:
    """Drop violations matching an allowlist entry (content-keyed)."""
    keys = {(e.file, e.func_name, e.kind, e.detail) for e in allowlist}
    return [
        v for v in violations
        if (v.file, v.func_name, v.kind, v.detail) not in keys
    ]


def render_violations(violations: Iterable[Violation]) -> str:
    """Pretty-print a violations list for the test failure message."""
    by_file: dict = {}
    for v in violations:
        by_file.setdefault(v.file, []).append(v)
    lines: list[str] = []
    for file in sorted(by_file):
        lines.append(f"\n  {file}:")
        lines.extend(f"    L{v.line:<5} {v.kind} detail={v.detail!r:<20} "
                f"in {v.func_name}()" for v in sorted(by_file[file], key=lambda v: v.line))
    return "\n".join(lines)


__all__ = [
    "AllowlistEntry",
    "Violation",
    "audit_file",
    "audit_repo",
    "audit_source",
    "filter_allowlisted",
    "render_violations",
]
