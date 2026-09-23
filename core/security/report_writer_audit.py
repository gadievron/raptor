"""AST-based lint rule for report-writer output sanitisation.

Companion to :mod:`core.security.prompt_envelope_audit` (input side).
Where the envelope audit stops attacker text from reaching LLM prompts
raw, this audit stops LLM-returned text from reaching rendered report /
terminal surfaces raw. The canonical defence is
:mod:`core.security.prompt_output_sanitise` (``sanitise_string`` /
``sanitise_code``), its markdown-writer projection
:mod:`core.security.markdown_render` (``md_fence`` / ``md_inline`` /
``md_prose`` — the discipline home NEW markdown writers adopt), plus
the per-module single-line helpers built on the pipeline
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
  within the enclosing function (also through ``for x in <tainted>``,
  annotated/augmented assignment, and container round-trips: storing
  into / appending to a local container taints the container name),
  so the assign-then-emit and dict→tuple-in-list→loop-print patterns
  are caught. MODULE-LOCAL helper returns get one level too: a
  function whose ``return`` carries foreign values marks its callers
  (``sys.stdout.write(render_json(report))``). Cross-MODULE dataflow
  and argument→return flow through helpers remain out of scope
  (documented limitation, same as the envelope audit). The taint tier
  is also FLOW-INSENSITIVE: a clean re-assignment clears taint
  regardless of branch structure, so the
  ``try: x = <tainted>`` / ``except: x = ""`` fallback shape reads
  its sink clean — the except-arm re-bind is indistinguishable from a
  sanitising re-assignment. A site relying on that shape must carry
  its own test pin (e.g. the sandbox child-failure diagnostic's
  source + behavioural pins in
  core/sandbox/tests/test_setup_status_integrity.py).
* **Raw-serialiser arm**: ``print(dumps_display(payload))``-shape
  whole-payload dumps at terminal-capable sinks are flagged directly
  (they read no key at all); ``json.dumps(..., ensure_ascii=True)``
  is the blessed terminal-JSON shape.
* **Exception-relay arm**: ``except Exception as e: print(f"{e}")``
  in a BROAD handler is flagged (shallow, handler-body sinks only —
  scope trade-offs recorded at ``_exception_relay_scan``). Rendered
  exception text that reaches a sink through a PRODUCING call instead
  of a bound name (``print(traceback.format_exc())``) is caught by the
  foreign-call vocabulary (:data:`_FOREIGN_TEXT_CALLS`). LOGGING
  sinks (``log.error(f"{e}")`` and every ``logger.*`` relay) are
  deliberately outside this arm: they are covered structurally at the
  console chokepoint (``core.logging.EscapingConsoleFormatter``);
  standalone CLIs wire it via ``core.logging.configure_cli_logging``,
  enforced by the console-config closure test (basicConfig,
  same-line addHandler(StreamHandler), dictConfig/fileConfig
  spellings).
* **Sanitiser name-shadow arm**: a local definition of a
  recognised-sanitiser name must build on a canonical sanitiser
  (``_sanitiser_shadow_scan``).
* **Sink-model residual**: sinks are matched by NAME — an aliased
  sink (``p = print; p(tainted)``) evades every arm. Adversarial-
  committer shape; review remains the control for deliberate
  evasion.
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
import re
from collections.abc import Callable, Iterable
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
    # Live field names report code actually uses — each was carried by
    # a writer lane the vocabulary missed (finding/journal/stage
    # fields, LLM overview output, tool-info dicts).
    "reason",
    "event_type",
    "notes",
    "technique",
    "constraints",
    "model_reliabilities",
    "target_path",
    "detail",
    "slug",
    "vuln_type",
    "instructions",
    "evidence",
    "blocked",
    "question",
    "identifiers",
    "concepts",
    "working_dir",
    # Finding free-text fields (normalised finding schema): message is
    # the scanner/LLM description (SARIF message text, OpenAnt LLM
    # output), snippet is verbatim code from the SCANNED tree, and
    # vuln_name is an LLM-authored display name. The whole-value
    # `lines.append(f.get("message"))` writer shape was already inside
    # the sink model (accumulator receivers + .get() reads) — these
    # names were simply absent from the vocabulary, so the openant
    # report writer's raw message/snippet lanes produced no findings
    # to baseline. Measured before widening: 10 finding-keys
    # tree-wide, each fixed or triaged with a note — no flooding, so
    # the widening is sound by this rule's own noise criteria.
    "message",
    "snippet",
    "vuln_name",
})


# Ubiquitous label-ish field names: matched for DICT reads
# (subscript / .get / getattr) where parsed-artifact fields live, but
# NOT for attribute access — ``.path`` / ``.status`` / ``.model`` /
# ``.errors`` attribute reads on stdlib/config/dataclass objects are
# everywhere and drowned the rule on measurement. An attribute-read
# writer lane on these names is a documented residual of this tier.
_LABEL_KEYS = frozenset({
    "model",
    "members",
    "errors",
    "path",
    "status",
    "id",
    "version",
    "file",
    "function",
    # severity/label: finding-derived display fields two live /project
    # render lanes carried raw (the SCA findings table's severity cell
    # and the diff view's changed-row label) while the detector's
    # vocabulary had neither name — the lanes produced no findings to
    # baseline. Measured before widening at this (dict-read, sink-tier)
    # level: 5 sites tree-wide, each fixed or triaged with a note —
    # no flooding. The full-propagation tier was measured too and
    # REJECTED: 85 new keys, dominated by container round-trips of
    # already-sanitised markdown rows — exactly the amplification the
    # tier split exists to avoid.
    "severity",
    "label",
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
    # raw checksec/tool-probe captures quote hostile-binary bytes.
    "raw_checksec",
    "output",
})

_FOREIGN_KEYS = _LLM_DERIVED_KEYS | _TOOL_OUTPUT_KEYS


# ---------------------------------------------------------------------------
# Schema-derived display-key tier
# ---------------------------------------------------------------------------
# The hand-maintained tiers above are curated lists — every key was
# appended after a lane was found carrying it raw, which means a
# finding field NOT yet on any list is invisible to the dict-read arm:
# ``print(f['ecosystem'])`` in a registered writer reads a real,
# target-derived findings.json field (the SCA row's OSV ecosystem
# string) and fired nothing, because no tier named it. Appending
# 'ecosystem' would fix one key and preserve the class. Instead the
# dict-read tier UNIONS in every field name the tree's own finding
# schemas declare, extracted from the schema sources' ASTs at import
# time — a new finding field joins the audit vocabulary the moment it
# joins a schema, with no list to forget to update.
#
# Sources (path -> what is read):
# * core/run/orchestrated_report_schema.py — ``_FINDING_SCHEMA``'s
#   ``properties`` key names (the orchestrated-report finding shape);
# * core/dataflow/finding.py — the ``_FINDING_KEYS`` / ``_STEP_KEYS``
#   frozenset literals (the normalised dataflow finding shape);
# * packages/sca/findings.py — ``_row_envelope``'s returned dict keys
#   plus every ``sca={...}`` block literal passed to it (the
#   findings.json row contract; per-kind blocks deliberately differ,
#   so the union is taken).
#
# Tier placement matches the label tier: dict reads (subscript / .get
# / getattr) at sinks and returns only — attribute reads on these
# ubiquitous names (``.name``, ``.line``, ``.version``) are everywhere
# on stdlib/dataclass objects and would drown the rule, and the taint
# engine keeps the pre-widening core vocabulary (the measured
# amplification trade-off documented at ``_naked_keys``). Nested
# summary sub-blocks (advisory / exploit-evidence dicts) are NOT
# walked — their parent field names are, which is the boundary a
# renderer reads through first; a lane unpacking a sub-block into
# locals is the same assign-then-print residual the label tier
# documents.
#
# Extraction failure doctrine, two-sided: a source file that is
# PRESENT but yields no keys raises at import (a restructure that
# silently stopped contributing would blind the gate exactly like the
# hand lists it replaces), while a MISSING source is skipped — the
# closure gate audits scratch trees carrying their own copy of this
# module (--root), and a minimal tree without the schema sources must
# degrade to the hand tiers, not crash the whole gate. A rename inside
# the real repo cannot hide in the skip arm: the per-source
# non-vacuity sentinels in test_report_writer_audit pin that every
# source keeps contributing there.

def _schema_keys_orchestrated(tree: ast.Module) -> set[str]:
    """``_FINDING_SCHEMA``'s ``properties`` key names."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "_FINDING_SCHEMA"
                   for t in node.targets):
            continue
        if not isinstance(node.value, ast.Dict):
            continue
        for k, v in zip(node.value.keys, node.value.values):
            if (isinstance(k, ast.Constant) and k.value == "properties"
                    and isinstance(v, ast.Dict)):
                out.update(pk.value for pk in v.keys
                           if isinstance(pk, ast.Constant)
                           and isinstance(pk.value, str))
    return out


def _schema_keys_dataflow(tree: ast.Module) -> set[str]:
    """String constants inside the ``_FINDING_KEYS`` / ``_STEP_KEYS``
    frozenset literals."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets: list[ast.expr] = list(node.targets)
            value = node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets = [node.target]
            value = node.value
        else:
            continue
        if not any(isinstance(t, ast.Name)
                   and t.id in ("_FINDING_KEYS", "_STEP_KEYS")
                   for t in targets):
            continue
        for c in ast.walk(value):
            if isinstance(c, ast.Constant) and isinstance(c.value, str):
                out.add(c.value)
    return out


def _schema_keys_sca(tree: ast.Module) -> set[str]:
    """``_row_envelope``'s returned dict keys plus every ``sca={...}``
    dict-literal keyword's keys (the per-kind block union)."""
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == "_row_envelope":
            for c in ast.walk(node):
                if isinstance(c, ast.Return) and isinstance(c.value, ast.Dict):
                    out.update(k.value for k in c.value.keys
                               if isinstance(k, ast.Constant)
                               and isinstance(k.value, str))
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "sca" and isinstance(kw.value, ast.Dict):
                    out.update(k.value for k in kw.value.keys
                               if isinstance(k, ast.Constant)
                               and isinstance(k.value, str))
    return out


_SCHEMA_KEY_SOURCES: tuple[tuple[str, Callable[[ast.Module], set[str]]], ...] = (
    ("core/run/orchestrated_report_schema.py", _schema_keys_orchestrated),
    ("core/dataflow/finding.py", _schema_keys_dataflow),
    ("packages/sca/findings.py", _schema_keys_sca),
)


def _derive_schema_keys(root: Path = _REPO_ROOT) -> frozenset[str]:
    """Union of finding-field names declared by the tree's own finding
    schemas. A missing source is skipped (scratch-tree degrade — see
    the doctrine comment above); a present source whose extraction
    yields nothing raises (an empty derivation is a blind gate, not a
    clean one)."""
    keys: set[str] = set()
    for rel, extract in _SCHEMA_KEY_SOURCES:
        path = root / rel
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            continue
        got = extract(ast.parse(text))
        if not got:
            raise RuntimeError(
                f"report_writer_audit: schema-key derivation from {rel} "
                f"yielded no keys — the source moved or was restructured; "
                f"update _SCHEMA_KEY_SOURCES (the audit must not run with "
                f"a silently-empty finding vocabulary)"
            )
        keys.update(got)
    return frozenset(keys)


_SCHEMA_KEYS = _derive_schema_keys()

# Dict-read (subscript/.get/getattr) vocabulary includes the label
# tier and the schema-derived finding-field tier; attribute reads
# match only the core vocabulary.
_SUBSCRIPT_KEYS = _FOREIGN_KEYS | _LABEL_KEYS | _SCHEMA_KEYS
# Taint-engine vocabulary: the pre-widening core names. The widened
# and label tiers match at sinks/returns only (see _naked_keys(wide)).
_CORE_KEYS = frozenset({
    "title", "claim", "body", "reasoning", "summary", "description",
    "remediation", "attack_scenario", "prediction", "rationale",
    "hypothesis", "stage_f_review", "stage_f_summary", "error",
    "details", "stderr", "stdout",
})


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
    # Conventional escape_nonprintable-based module helpers (scorecard
    # samples renderer, cve-diff bench HTML cells). The name-shadow
    # arm enforces that every local definition builds on a canonical
    # sanitiser.
    "_esc",
    # scorecard render helpers: the shared md_inline-based cell scrub
    # (core.llm.scorecard._render.scrub_cell — the converged home the
    # per-module _cell/_scrub_cell wrappers chain to) and the
    # ensure_ascii JSON terminal lane (the shadow arm accepts
    # ensure_ascii json.dumps bodies).
    "scrub_cell",
    "_scrub_cell",
    "_dumps_json_lane",
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
    # (investigation._md_escape: thin wrapper over md_inline —
    # table-cell grade for binary-derived names).
    "_md_escape",
    # investigation's render-site hardening for the string-anchor
    # surfaces: _md_escape PLUS code-span backtick and [text](url)
    # link-form neutralisation — strictly stronger than _md_escape,
    # so recognising it never weakens the gate (see its docstring
    # for why it is not folded into _md_escape).
    "_md_neutral",
    # coverage store_summary's terminal chokepoint for journal/
    # inventory-derived names (_defang: sanitise_for_terminal +
    # length bound). Recognising the name puts the gate back on
    # guard for those lanes — their baseline rows were retired once
    # the sanitisation landed, and without the vocabulary entry a
    # REVERT of the sanitisation read clean to the gate.
    "_defang",
    # packages/diagram's Mermaid chokepoints: sanitize.sanitize
    # (imported as _sanitize; Mermaid-structure neutralisation +
    # fence-break ZWSP + escape_nonprintable), the context_map _text
    # wrapper over it, and sanitize_id (imported as _sid; strips to
    # [A-Za-z0-9_-]).
    "_sanitize",
    "_text",
    "_sid",
    "sanitize_id",
    # packages/diagram's shared truncation-marker chokepoint
    # (caps.truncation_marker_lines: _sid on the node id, _sanitize on
    # the category text, int coercion on the counts).
    "truncation_marker_lines",
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
    # core.security.markdown_render — the one-home markdown-writer
    # discipline (fence / inline / prose projections of the
    # prompt_output_sanitise pipeline). New markdown writers adopt
    # these instead of minting per-module helper N+1.
    "md_fence",
    "md_inline",
    "md_prose",
    # core/threat_model's markdown-slot chokepoint (strips structural
    # markdown chars, then escape_nonprintable, byte-capped) — every
    # renderer lane in that module routes untrusted values through it.
    "_safe_for_render",
    # core/threat_model's ingest-boundary clip (escape_nonprintable +
    # byte cap — sanitise_for_terminal grade); summary-builder lanes
    # apply it per-field at construction.
    "_clip_str",
    # core/threat_model's Mermaid label chokepoint: _safe_for_render
    # (newline/pipe/backtick strip + escape) then quote-escaping, so a
    # hostile label cannot terminate the node or forge statements.
    "_mermaid_label",
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
    # Build-system detector CLI: command/working_dir/env_vars derive
    # from the scanned repo's build files. Terminal writer —
    # sanitise_for_terminal grade.
    "core/build/build_detector.py",
    "core/audit/report.py",
    # The per-function review-progress stream (format_progress_line):
    # target-derived file/function names and verbatim announcement
    # bodies printed to the operator terminal by libexec/raptor-audit.
    "core/audit/_util.py",
    "core/llm/multi_model/replay.py",
    "core/progress/__init__.py",
    "core/project/cli.py",
    # /project annotations diff — renders agent-written annotation
    # fields (file/function/status/source) to the operator terminal
    # via cli.py's print(format_diff(...)). Terminal writer,
    # sanitise_for_terminal grade at construction.
    "core/project/annotations_diff.py",
    "core/reporting/renderer.py",
    # Default-target resolution: the volatile-target refusal banner
    # interpolates the active project's name/target (adopt-inferred
    # from child-writable run metadata, or import-restored) into a
    # bare stderr print. Terminal writer — sanitise_for_terminal
    # grade. NOTE: the banner variables reach the sink as tuple-
    # unpacked locals (no vocabulary-key read), so the detector is
    # structurally blind to this lane — the render-scrub regression
    # tests are its oracle; registration keeps future keyed lanes in
    # this file under audit.
    "core/run/output.py",
    "core/run/provenance.py",
    # Threat-model store + renderers: report/prompt lanes interpolate
    # LLM-refreshed model fields; the module's _safe_for_render /
    # _clip_str chokepoints are the discipline. Registered so renderer
    # drift fails CI instead of landing in the unregistered baseline.
    "core/threat_model/__init__.py",
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
    "packages/binary_analysis/blamed_lines.py",
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
    # OpenAnt workflow: openant-report.md interpolates finding fields
    # that derive from the scanned repo (snippet = verbatim target
    # code) and from OpenAnt's LLM output (message / vuln_name).
    # Markdown writer — markdown_render (md_fence / md_inline /
    # md_prose) grade; terminal lanes use sanitise_for_terminal.
    "raptor_openant.py",
    "libexec/raptor-audit",
    "libexec/raptor-review",
    "libexec/raptor-study-loop",
    "libexec/raptor-synthesise-checker",
    "libexec/raptor-understand",
    "libexec/raptor-validation-helper",
    "libexec/raptor-annotate",
    "libexec/raptor-coverage-summary",
    # Whole-payload JSON verdict lanes (ensure_ascii json.dumps) plus
    # per-field terminal lanes. Terminal writers —
    # sanitise_for_terminal grade.
    "libexec/raptor-binary-graph-query",
    "libexec/raptor-binary-study",
    "libexec/raptor-compile-invariants",
    # cve-diff run/localize terminal lanes: pipeline/LLM exception
    # relays and cluster member names (functions from hostile-binary
    # decompilation). Terminal writer — sanitise_for_terminal grade.
    "libexec/raptor-cve-diff",
    # Enrich family: the corroborate-mismatch text is escaped at its
    # core/run/metadata chokepoint; every stage-failure relay routes
    # through the in-file _stage_failed helper, which owns the escape
    # (never rely on the transitively-imported console formatter).
    # Terminal writers — sanitise_for_terminal grade.
    "libexec/raptor-enrich-context-map",
    # Graph-store query CLI: node ids / labels / target paths come
    # from ingested run artifacts (scanned-tree names, LLM hypothesis
    # text). Terminal writer — sanitise_for_terminal grade; the
    # multi-line threat-context block uses the script's newline-
    # preserving _term_block helper.
    "libexec/raptor-graph-query",
    "libexec/raptor-render-diagrams",
    "libexec/raptor-smt-check-encoding-residual",
    "libexec/raptor-smt-check-negative-bypass",
    "libexec/raptor-smt-check-null-deref",
    "libexec/raptor-smt-check-oob",
    "libexec/raptor-smt-check-overflow",
    "libexec/raptor-smt-check-overflow-to-oob",
    "libexec/raptor-smt-validate-path",
    "libexec/raptor-study-prep",
    "libexec/raptor-validate-schema",
    "libexec/raptor-verified-outcomes",
    # Attachment fetcher: echoes the untrusted tracker URL at refusal
    # and success. Terminal writer — sanitise_for_terminal grade.
    "libexec/raptor-fetch-attachment",
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
    line churn. Granularity is per-function per-key: a REWRITTEN call
    site, or a brand-new unsanitised read of the same key added
    anywhere in the same function, still matches the old entry and
    stays silenced — only a key or function rename re-fires. Keep
    entries narrow and re-review them whenever the owning function
    changes.
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
        file="libexec/raptor-understand",
        func_name="_main_body",
        kind="unsanitised_exception_text",
        detail="e",
        audit_note=(
            "broad-handler exception relay at the top-level entry "
            "point (mechanism residual): _main_body drives the "
            "multi-model hunt/trace dispatch, so exception text can "
            "quote provider/tool content; triaged as a burn-down "
            "residual — sanitise + register on next functional touch"
        ),
    ),
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
        file="core/sage/hooks.py",
        func_name="store_study_concepts",
        kind="unsanitised_llm_value",
        detail="composite",
        audit_note=(
            "composite is stamped_evidence_composite output — a "
            "SHA-256 hexdigest or the empty string, inert by "
            "construction; the fold helper is outside the audit's "
            "sanitiser vocabulary, so its assignment from the "
            "LLM-derived row content still reads as taint"
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
    # --- container-round-trip arm: adjudicated count/label reads ----
    AllowlistEntry(
        file="core/llm/scorecard/cli.py",
        func_name="cmd_tool_evidence",
        kind="unsanitised_llm_value",
        detail="n",
        audit_note=(
            "n is the int event count the recorder returns; the taint "
            "chains through the records argument of the same call"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_critique",
        kind="unsanitised_llm_value",
        detail="count",
        audit_note=(
            "per-function sweep_count int unpacked from the stats "
            "container; the string fields on the same lines are "
            "sanitise_for_terminal-wrapped"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_critique",
        kind="unsanitised_llm_value",
        detail="untried",
        audit_note=(
            "set difference against the literal tool-name set — only "
            "constant tool names print; taint chains through the loop "
            "over the stats container"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-study-prep",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="role_summary",
        audit_note=(
            "role labels are the discover_accessor_patterns closed "
            "enum (allocator/deallocator/lock_wrapper/resource_wrapper) "
            "joined with int counts — no target/LLM content"
        ),
    ),
    AllowlistEntry(
        file="libexec/raptor-study-prep",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="api_promoted",
        audit_note="int promotion counter; taint chains through the items container",
    ),
    AllowlistEntry(
        file="libexec/raptor-study-prep",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="pd_promoted",
        audit_note="int promotion counter; taint chains through the items container",
    ),
    AllowlistEntry(
        file="libexec/raptor-study-prep",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="usage_counts",
        audit_note=(
            "int counters read at constant keys "
            "(writer/reader/passthru) from the type-reference census"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="orch",
        audit_note=(
            "int counters (findings_analysed/findings_failed) read at "
            "constant keys from the in-process orchestration summary"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="other_fails",
        audit_note="int subtraction of two counters",
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="cost_total",
        audit_note="float cost telemetry rendered as $%.2f",
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="model_str",
        audit_note=(
            "operator-configured analysis model id from the in-process "
            "summary the same function just built"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="parts",
        audit_note=(
            "list of count/elapsed/cost fragments built two lines up "
            "from int counters and formatted floats"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="thinking",
        audit_note="int thinking-token counter rendered with {:,}",
    ),
    # --- helper-return arm: adjudicated module-local helper flows ----
    AllowlistEntry(
        file="core/project/report.py",
        func_name="generate_project_report",
        kind="unsanitised_llm_value",
        detail="annotations_md",
        audit_note=(
            "render_annotations_markdown sanitise_string's every body "
            "and the annotation store validates file/function/metadata "
            "at write time; the taint enters via the renderer's "
            "ARGUMENT (gather_project_annotations returns bodies), not "
            "its output"
        ),
    ),
    AllowlistEntry(
        file="core/reporting/findings.py",
        func_name="findings_summary",
        kind="unsanitised_llm_value",
        detail="findings_summary_line",
        audit_note=(
            "helper returns a line of int statistics counters (its own "
            "counts['error'] read is the adjudicated count entry above)"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/harness.py",
        func_name="generate_binary_harness",
        kind="unsanitised_llm_value",
        detail="spec",
        audit_note=(
            "render_harness_report routes name-bearing fields through "
            "the module's escaping helpers; the taint is spec passed as "
            "the renderer's argument, not renderer output"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/investigation.py",
        func_name="write_investigation",
        kind="unsanitised_llm_value",
        detail="render_investigation_report",
        audit_note=(
            "the renderer's return-taint chains only through the "
            "internally-built count dict named 'summary' (vocabulary "
            "collision); every name-bearing field routes through "
            "_md_escape"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/orchestrator.py",
        func_name="orchestrate",
        kind="unsanitised_llm_value",
        detail="suffix",
        audit_note=(
            "aggregation['analysed_by'] is the operator-configured "
            "aggregation model id from the in-process summary"
        ),
    ),
    AllowlistEntry(
        file="packages/static-analysis/scanner.py",
        func_name="run_single_semgrep",
        kind="unsanitised_llm_value",
        detail="se",
        audit_note=(
            "verbatim semgrep stderr capture into the run's stderr log "
            "artifact — raw by design, not a rendered report"
        ),
    ),
    AllowlistEntry(
        file="packages/static-analysis/scanner.py",
        func_name="run_single_semgrep",
        kind="unsanitised_llm_value",
        detail="rc",
        audit_note="int exit code written to the exit-code artifact file",
    ),
    AllowlistEntry(
        file="libexec/raptor-validation-helper",
        func_name="prepare_A",
        kind="unsanitised_llm_value",
        detail="parts",
        audit_note=(
            "source-binary map lines: keys are the map builder's "
            "constant field names, values are _sft-wrapped in the same "
            "comprehension"
        ),
    ),
    # --- vocabulary widening: adjudicated code-authored fields ------
    AllowlistEntry(
        file="core/audit/report.py",
        func_name="_format_summary",
        kind="unsanitised_llm_value",
        detail="reason",
        audit_note=(
            "not-attempted reason is the orchestrator's own "
            "code-authored budget/coverage label"
        ),
    ),
    AllowlistEntry(
        file="core/llm/scorecard/audit.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="report",
        audit_note=(
            "render_json is ensure_ascii and render_markdown routes "
            "cells through _cell — the taint is the report argument "
            "passed INTO the renderers, not their output"
        ),
    ),
    AllowlistEntry(
        file="core/project/cli.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="notes",
        audit_note=(
            "notes edit lane writes the operator's own notes to their "
            "own $EDITOR tempfile (byte-exact by design); the display "
            "lane escapes via escape_nonprintable(preserve_newlines) — "
            "newline-preserving multi-line display for the operator's "
            "own free text, length deliberately unbounded"
        ),
    ),
    AllowlistEntry(
        file="core/project/cli.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="path",
        audit_note=(
            "export destination path constructed by export_project "
            "under the operator-chosen output root"
        ),
    ),
    AllowlistEntry(
        file="core/project/cli.py",
        func_name="_print_run_provenance",
        kind="unsanitised_llm_value",
        detail="status",
        audit_note=(
            "run status is the lifecycle enum (running/completed/"
            "failed/...), validated at write time"
        ),
    ),
    AllowlistEntry(
        file="core/project/report.py",
        func_name="export_findings_directory",
        kind="unsanitised_llm_value",
        detail="record",
        audit_note=(
            "findings.jsonl artifact-file write — byte-exact machine "
            "lane (dumps_artifact is the artifact contract)"
        ),
    ),
    AllowlistEntry(
        file="core/sandbox/triage.py",
        func_name="_cli_main",
        kind="unsanitised_llm_value",
        detail="model",
        audit_note="operator-configured model id from the deep-assessment config",
    ),
    AllowlistEntry(
        file="libexec/raptor-audit",
        func_name="cmd_run",
        kind="unsanitised_llm_value",
        detail="reason",
        audit_note=(
            "provisioning skip reason/remedy are code-authored "
            "strings (same record as the _skip entry above)"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_print_map_summary",
        kind="unsanitised_llm_value",
        detail="key",
        audit_note=(
            "count-dict key names from the internally-built "
            "correlation summary (the summary entry above)"
        ),
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_print_investigation_summary",
        kind="unsanitised_llm_value",
        detail="status",
        audit_note="investigation status is the pipeline's own enum",
    ),
    AllowlistEntry(
        file="packages/binary_analysis/cli.py",
        func_name="_run_trace_parser",
        kind="unsanitised_llm_value",
        detail="status",
        audit_note="phase/investigation status is the pipeline's own enum",
    ),
    AllowlistEntry(
        file="packages/binary_analysis/investigation.py",
        func_name="write_investigation",
        kind="unsanitised_llm_value",
        detail="investigation",
        audit_note=(
            "binary-investigation.json artifact-file save; the "
            "markdown render on the same lines routes through "
            "_md_escape"
        ),
    ),
    # --- severity/label vocabulary widening: adjudicated hits --------
    AllowlistEntry(
        file="core/project/cli.py",
        func_name="_print_sca_findings_section",
        kind="unsanitised_llm_value",
        detail="i",
        audit_note=(
            "i is the enumerate() counter over the severity-sorted "
            "findings list; the taint chains through the sort key's "
            "severity read — every string field on the same lines is "
            "sanitise_for_terminal-wrapped"
        ),
    ),
    AllowlistEntry(
        file="core/sandbox/triage.py",
        func_name="_cli_main",
        kind="unsanitised_llm_value",
        detail="severity",
        audit_note=(
            "signal severity is the triage module's own SEVERITY_* "
            "constant set (code-authored enum labels), not target/LLM "
            "text"
        ),
    ),
    AllowlistEntry(
        file="core/threat_model/__init__.py",
        func_name="prompt_context",
        kind="unsanitised_llm_value",
        detail="rendered",
        audit_note=(
            "threat-ledger lines are built from fields _clip_str-"
            "bounded at model ingest and the join is "
            "escape_nonprintable-wrapped at the sink; prompt-context "
            "lane, not a rendered report (moved from the closure "
            "baseline when the module was registered)"
        ),
    ),
    AllowlistEntry(
        file="packages/describe/report.py",
        func_name="format_text",
        kind="unsanitised_llm_value",
        detail="reason",
        audit_note=(
            "recommendation reasons are code-authored strings from the "
            "describe signal catalog"
        ),
    ),
    AllowlistEntry(
        file="packages/describe/report.py",
        func_name="format_text",
        kind="unsanitised_llm_value",
        detail="detail",
        audit_note=(
            "capability-check detail strings are code-authored; "
            "version fragments come from local trusted-tool probes "
            "(no target input on the describe surface by contract)"
        ),
    ),
    # --- schema-derived tier: adjudicated safe sites ------------------
    AllowlistEntry(
        file="core/project/cli.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="name",
        audit_note=(
            "import_project charset-validates the registered name via "
            "ProjectManager._validate_name before returning it — the "
            "rendered value cannot carry separators or control bytes"
        ),
    ),
    AllowlistEntry(
        file="core/reporting/findings.py",
        func_name="findings_summary_line",
        kind="unsanitised_llm_value",
        detail="exploitable",
        audit_note=(
            "internally-built count dict (count_findings sums ints); "
            "the rendered value is an integer bucket count, not "
            "finding text"
        ),
    ),
    AllowlistEntry(
        file="core/sandbox/triage.py",
        func_name="_cli_main",
        kind="unsanitised_llm_value",
        detail="confidence",
        audit_note=(
            "rendered under a :.2f format spec — a non-numeric value "
            "raises at format time instead of reaching the terminal; "
            "every string field on the same line is sanitised"
        ),
    ),
    AllowlistEntry(
        file="core/threat_model/__init__.py",
        func_name="render_report",
        kind="unsanitised_llm_value",
        detail="source",
        audit_note=(
            "the raw read feeds _mermaid_id, which renders a sha256 "
            "hex digest of the value — content-destroying; the label "
            "render of the same field routes through _mermaid_label"
        ),
    ),
    AllowlistEntry(
        file="core/threat_model/__init__.py",
        func_name="render_report",
        kind="unsanitised_llm_value",
        detail="sink",
        audit_note=(
            "the raw read feeds _mermaid_id, which renders a sha256 "
            "hex digest of the value — content-destroying; the label "
            "render of the same field routes through _mermaid_label"
        ),
    ),
    AllowlistEntry(
        file="core/threat_model/__init__.py",
        func_name="_derive_domain_packs",
        kind="unsanitised_llm_value",
        detail="name",
        audit_note=(
            "lowercased text is substring-matched against constant "
            "pack markers; the function returns constant pack names "
            "and renders nothing"
        ),
    ),
    AllowlistEntry(
        file="packages/ghidra/decomp_tree.py",
        func_name="_render_types",
        kind="unsanitised_llm_value",
        detail="name",
        audit_note=(
            "field names route through the module's _clip at the site "
            "(match._CONTROL control/bidi scrub + length cap — the "
            "shared decomp-emission chokepoint); _clip cannot join "
            "_SANITISERS because it builds on the regex, not a "
            "canonical primitive, and the shadow arm would refuse it"
        ),
    ),
    AllowlistEntry(
        file="packages/llm_analysis/agent.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="exploitable",
        audit_note=(
            "pipeline-built report counter (int of exploitable "
            "verdicts), not finding text"
        ),
    ),
    AllowlistEntry(
        file="raptor_agentic.py",
        func_name="main",
        kind="unsanitised_llm_value",
        detail="exploitable",
        audit_note=(
            "pipeline-built analysis counter rendered with an int "
            "default (.get(..., 0)), not finding text"
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


def _key_expr(node: ast.AST,
              attr_keys: frozenset,
              sub_keys: frozenset) -> str | None:
    """Return the LLM-derived key name if ``node`` reads one.

    Recognises ``x.title``, ``x["title"]``, ``x.get("title", ...)``,
    and ``getattr(x, "title", ...)``. ``attr_keys``/``sub_keys``
    select the vocabulary tier (see ``_naked_keys``).
    """
    if isinstance(node, ast.Attribute) and node.attr in attr_keys:
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
                and sl.value in sub_keys):
            return sl.value
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "get" and node.args:
            a0 = node.args[0]
            if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)
                    and a0.value in sub_keys):
                return a0.value
        if (isinstance(node.func, ast.Name) and node.func.id == "getattr"
                and len(node.args) >= 2):
            a1 = node.args[1]
            if (isinstance(a1, ast.Constant) and isinstance(a1.value, str)
                    and a1.value in sub_keys):
                return a1.value
    return None


def _is_raw_serialiser(node: ast.AST) -> str | None:
    """Name of a raw-serialiser call whose output passes C1 controls.

    ``dumps_display`` is ensure_ascii=False by contract;
    ``dumps_artifact`` defaults to ensure_ascii=False (safe only with
    an explicit ``ensure_ascii=True``); bare ``dumps`` defaults to
    ensure_ascii=True and is flagged only when explicitly disabled.
    A whole-payload dump at a sink reads no key at all, so the
    key-vocabulary arm can never see it.
    """
    if not isinstance(node, ast.Call):
        return None
    name = _call_name(node)
    if name == "dumps_display":
        return name
    if name == "dumps_artifact" and not any(
            kw.arg == "ensure_ascii"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is True
            for kw in node.keywords):
        return name
    if name == "dumps" and any(
            kw.arg == "ensure_ascii"
            and isinstance(kw.value, ast.Constant)
            and kw.value.value is False
            for kw in node.keywords):
        return name
    return None


def _raw_serialiser_calls(node: ast.AST) -> list[tuple[int, str]]:
    """(line, serialiser-name) pairs for raw-serialiser calls in
    ``node`` that are not wrapped by a recognised sanitiser."""
    out: list[tuple[int, str]] = []

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Call) and _call_name(n) in _SANITISERS:
            return
        name = _is_raw_serialiser(n)
        if name is not None:
            out.append((getattr(n, "lineno", 0), name))
        for child in ast.iter_child_nodes(n):
            walk(child)

    walk(node)
    return out


# Primitives a sanitiser-named local helper must (transitively, one
# module-local level) build on. A same-named local helper that
# references NONE of these satisfies the recognised-sanitiser
# vocabulary while sanitising nothing — the name-shadow escape the
# registry review alone cannot hold shut.
_CANONICAL_SANITISER_NAMES = frozenset({
    "sanitise_string", "sanitise_code", "sanitise_inline",
    "sanitise_for_terminal", "escape_nonprintable",
    "sanitize", "sanitize_id",
}) | _SANITISERS


# Modules whose job IS defining a canonical sanitiser from first
# principles (regex strip / character-class rebuild) — their defs
# legitimately reference no other sanitiser.
_SANITISER_DEFINITION_MODULES = frozenset({
    "core/security/log_sanitisation.py",
    "core/security/prompt_output_sanitise.py",
    "packages/diagram/sanitize.py",
})


def _sanitiser_shadow_scan(tree: ast.AST, rel: str) -> list[Violation]:
    """Flag local function definitions that SHADOW a recognised
    sanitiser name without building on any canonical sanitiser.

    Chained helpers (``_cell`` calling ``_line``) pass via the
    ``_SANITISERS`` union; ``html.escape`` passes via the attribute
    check. Residuals (documented): mutually-recursive no-op pairs;
    aliasing a non-sanitising callable via import-as (import aliases
    are the established convention for the real sanitisers and are
    not distinguishable by name alone); and MENTION-only bodies —
    the check is reference-based, not dataflow, so a body that names
    a canonical sanitiser without applying it on the return path
    passes (adversarial-committer shape; the review checkpoint at
    registry/allowlist time is the control for deliberate evasion).
    """
    if rel in _SANITISER_DEFINITION_MODULES:
        return []
    out: list[Violation] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name not in _SANITISERS:
            continue
        ok = False
        for n in ast.walk(node):
            if (isinstance(n, ast.Name)
                    and n.id in _CANONICAL_SANITISER_NAMES
                    and n.id != node.name):
                ok = True
                break
            if isinstance(n, ast.Call) and _is_ascii_json_dumps(n):
                # json.dumps(..., ensure_ascii=True) helpers (the
                # blessed terminal-JSON lane) sanitise by construction.
                ok = True
                break
            if isinstance(n, ast.Attribute) and (
                    n.attr in _CANONICAL_SANITISER_NAMES
                    or (n.attr == "escape"
                        and isinstance(n.value, ast.Name)
                        and n.value.id in ("html", "markupsafe"))):
                # Mirror the Name branch's self-reference exclusion:
                # `self.<own name>` / `cls.<own name>` inside the def
                # is recursion, not building on a canonical sanitiser
                # (a module-qualified `mod.<same name>` IS canonical —
                # the aliasing-wrapper shape). The previous guard
                # compared the Attribute to the FunctionDef (`n is
                # node`, always False), making the wrapper dead and
                # accepting bare self-recursion as canonical.
                is_self_recursion = (
                    n.attr == node.name
                    and isinstance(n.value, ast.Name)
                    and n.value.id in ("self", "cls")
                )
                if not is_self_recursion:
                    ok = True
                    break
        if not ok:
            out.append(Violation(
                file=rel,
                line=node.lineno,
                kind="sanitiser_shadow",
                detail=node.name,
                func_name=node.name,
            ))
    return out


def _exception_relay_scan(tree: ast.AST, rel: str,
                          parents: dict | None = None) -> list[Violation]:
    """Mechanism arm: exception-text indirection.

    ``except Exception as e: print(f"...{e}")`` relays whatever the
    raising layer embedded — tool stderr, target bytes, LLM text —
    and exception OBJECTS are outside the key model entirely.

    Deliberately SHALLOW and BROAD-handler-only, both directions
    measured: (i) full taint integration marked whole ``main()``
    functions through handler-side container stores (168 registered +
    116 unregistered hits, dominated by count summaries); (ii)
    narrow-typed handlers (OSError on an operator path, ValueError
    from int()) carry far less attacker content than a broad catch
    that relays arbitrary lower layers — every unit-filed member of
    this mechanism was a broad catch. Residuals (documented): the
    one-hop ``msg = f"{e}"; print(msg)`` spelling and narrow-handler
    relays. ``logging`` sinks (``log.error(f"{e}")``) are excluded
    HERE and covered at a different layer: the console-handler
    chokepoint (``EscapingConsoleFormatter``; standalone CLIs wire it
    via ``core.logging.configure_cli_logging``, enforced by the
    console-config closure test) escapes every logger-routed
    line, so a per-site arm would double-cover with heavy noise.
    """
    out: list[Violation] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ExceptHandler) and node.name
                and _is_broad_handler(node)):
            continue
        bound = frozenset({node.name})
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            func = inner.func
            is_sink = (
                (isinstance(func, ast.Name) and func.id in _SINK_FUNCTIONS)
                or (isinstance(func, ast.Attribute)
                    and func.attr in ("echo", "secho", "write"))
            )
            if not is_sink:
                continue
            args = list(inner.args) + [kw.value for kw in inner.keywords
                                       if kw.value is not None]
            for arg in args:
                for line, _key in _naked_keys(arg, bound):
                    out.append(Violation(
                        file=rel,
                        line=line or inner.lineno,
                        kind="unsanitised_exception_text",
                        detail=node.name,
                        func_name=_enclosing_func_name(node, tree, parents),
                    ))
    return out


def _enclosing_func_name(node: ast.AST, tree: ast.AST,
                         parents: dict | None) -> str:
    """Dotted enclosing-function name (builds the parents map once,
    lazily, shared via the caller's dict)."""
    if parents is None:
        parents = {}
    if not parents:
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent
    names: list[str] = []
    cur = parents.get(node)
    while cur is not None:
        if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef,
                            ast.ClassDef)):
            names.append(cur.name)
        cur = parents.get(cur)
    return ".".join(reversed(names)) or "<module>"


def _terminal_capable_sink(node: ast.Call) -> bool:
    """True when the sink call can reach a terminal: ``print``/
    ``echo``/``secho`` (any form), or ``.write`` on a receiver whose
    dotted name mentions stdout/stderr/buffer. ``.write_text`` and
    plain file-handle writes are file-artifact lanes."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id in _SINK_FUNCTIONS
    if isinstance(func, ast.Attribute):
        if func.attr in ("echo", "secho"):
            return True
        if func.attr == "write":
            recv = _dotted_name(func.value).lower()
            return any(tok in recv for tok in ("stdout", "stderr", "buffer"))
    return False


def _is_ascii_json_dumps(node: ast.Call) -> bool:
    """True for ASCII-safe ``dumps`` calls (any module alias —
    ``json.dumps`` / ``_json.dumps``). JSON escapes C0 always and
    ensure_ascii escapes everything non-ASCII including C1, so the
    output is terminal-safe by construction. stdlib ``ensure_ascii``
    DEFAULTS to True, so a bare ``json.dumps(x)`` is safe too — only
    an explicit ``ensure_ascii=False`` (or a non-constant value, which
    could be False at runtime) disqualifies. The repo's raw
    serialisers have their own names (``dumps_display`` /
    ``dumps_artifact``) and are handled by :func:`_is_raw_serialiser`.
    """
    if _call_name(node) != "dumps":
        return False
    for kw in node.keywords:
        if kw.arg == "ensure_ascii":
            return (isinstance(kw.value, ast.Constant)
                    and kw.value.value is True)
        if kw.arg is None:
            return False  # **kwargs could smuggle ensure_ascii=False
    return True


# Builtins whose return value carries no content from their argument
# (counts, predicates, numeric coercions). ``len(tainted)`` is an int
# — walking into the argument minted count-line false positives on
# every "N item(s)" summary. min/max/sorted/join are deliberately NOT
# here: they return (or contain) their elements.
_TAINT_NEUTRAL_CALLS = frozenset({
    "len", "int", "float", "bool", "round", "ord", "hash",
    "isinstance", "hasattr", "callable", "abs",
    # sum() on strings raises by design; the count idiom
    # (``sum(1 for ...)``) dominated the false positives. Residual:
    # ``sum(list_of_lists, [])`` concatenation can carry content —
    # rare and lint-discouraged, accepted.
    "sum",
    # type(x) yields the class (its __name__ is code-authored);
    # repr(x) escapes non-printables in strings, same grounds as the
    # {x!r} conversion.
    "type",
    "repr",
})


# Foreign-text-PRODUCING calls: their return value is rendered
# exception text — the same content class the exception-relay arm
# exists for — while reading no bound name and no vocabulary key, so
# without this vocabulary they are invisible to every arm. Matched by
# short call name (``traceback.format_exc()`` and a bare imported
# ``format_exc()`` both count).
_FOREIGN_TEXT_CALLS = frozenset({
    "format_exc",
    "format_exception",
    "format_exception_only",
})


def _naked_keys(
    node: ast.AST,
    tainted: frozenset,
    tainted_calls: frozenset = frozenset(),
    *,
    wide: bool = False,
) -> list[tuple[int, str]]:
    """Return (line, key) pairs for LLM-derived reads in ``node`` that
    are NOT inside a recognised sanitiser call. ``tainted`` names count
    as LLM-derived reads too (one-level local taint), and calls to
    ``tainted_calls`` (module-local helpers whose RETURN value is
    tainted — the ``sys.stdout.write(render_json(report))`` shape)
    count as foreign reads in BOTH spellings: simple-name
    (``render(x)``) and attribute-form (``self.render(x)`` /
    ``obj.render(x)`` — helper names are registered by short name, so
    the method spelling of the same module-local helper matches on
    ``func.attr``; over-taint is bounded because the names are
    function-local to the audited module).

    ``wide=True`` (sink arguments and return expressions) matches the
    FULL vocabulary including the widened and label tiers;
    ``wide=False`` (taint-engine decisions: assignments, loop iters,
    container stores) matches only the pre-widening core vocabulary.
    Measured trade-off: letting the widened names drive the taint
    engine marked hundreds of sanitise-at-construction table rows and
    count summaries through container round-trips (322 registered
    hits tree-wide); direct-read coverage keeps the mechanism-1 lanes
    visible at their sinks without the amplification. The
    local-variable round-trip for WIDENED names is therefore a
    documented residual (the core names keep full propagation).
    """
    attr_keys = _FOREIGN_KEYS if wide else _CORE_KEYS
    sub_keys = _SUBSCRIPT_KEYS if wide else _CORE_KEYS
    out: list[tuple[int, str]] = []

    def walk(n: ast.AST) -> None:
        if isinstance(n, ast.Call) and _call_name(n) in _SANITISERS:
            return  # sanitised subtree — everything below is defanged
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id in _TAINT_NEUTRAL_CALLS):
            return  # content-destroying builtin — nothing flows through
        if isinstance(n, ast.Call) and _call_name(n) in _FOREIGN_TEXT_CALLS:
            # traceback.format_exc() / format_exception(...): the call
            # RESULT is exception text — flag the read itself; the
            # arguments (an exception object, limits) add nothing.
            out.append((getattr(n, "lineno", 0), _call_name(n)))
            return
        if isinstance(n, ast.Call) and _is_ascii_json_dumps(n):
            # json.dumps(..., ensure_ascii=True): C0 escaped by JSON,
            # C1 escaped by ensure_ascii — the blessed terminal-JSON
            # shape (still walk keyword values other than the data,
            # via the ensure_ascii check being on the CALL only).
            return
        if isinstance(n, ast.IfExp):
            # Only the branch VALUES flow into the expression; the
            # test picks a branch but contributes no content
            # (``x = _sft(v) if v else None`` is fully sanitised).
            walk(n.body)
            walk(n.orelse)
            return
        if isinstance(n, (ast.ListComp, ast.GeneratorExp, ast.SetComp)):
            # Comprehensions: only the ELEMENT flows to the consumer.
            # A foreign/tainted ITER taints the comprehension targets
            # for the element walk (``f(x) for x in d["notes"]`` is
            # clean when f sanitises, fires when x is used raw).
            iter_tainted = False
            for gen in n.generators:
                if _naked_keys(gen.iter, tainted, tainted_calls,
                               wide=wide):
                    iter_tainted = True
            if iter_tainted:
                extra = set()
                for gen in n.generators:
                    extra.update(_target_names(gen.target))
                out.extend(_naked_keys(
                    n.elt, tainted | frozenset(extra), tainted_calls,
                    wide=wide))
            else:
                walk(n.elt)
            return
        if (isinstance(n, ast.FormattedValue)
                and n.conversion == ord("r")):
            # ``{value!r}`` renders through repr(), which escapes
            # non-printables in strings — control-byte-safe (though
            # unbounded; length abuse is out of this rule's scope).
            return
        key = _key_expr(n, attr_keys, sub_keys)
        if key is not None:
            out.append((getattr(n, "lineno", 0), key))
        if (isinstance(n, ast.Subscript)
                and isinstance(n.slice, ast.Constant)
                and isinstance(n.slice.value, str)
                and n.slice.value not in sub_keys):
            # Field-scoped read from a (possibly tainted) container:
            # ``sca_result["deps_scanned"]`` reads a NON-vocabulary
            # key — the container taint was deposited under vocabulary
            # keys, so other constant keys read clean. Whole-container
            # reads (print(d), joins, loops) and vocabulary-key reads
            # stay tainted. Without this, one foreign store into a
            # summary dict marked every count print in the function.
            return
        if isinstance(n, ast.Call) and _call_name(n) == "get" and n.args:
            a0 = n.args[0]
            if (isinstance(a0, ast.Constant) and isinstance(a0.value, str)
                    and a0.value not in sub_keys
                    and isinstance(n.func, ast.Attribute)):
                # ``d.get("count")`` — same field-scoped rule; still
                # walk the DEFAULT argument (it flows into the value).
                for extra in n.args[1:]:
                    walk(extra)
                return
        if isinstance(n, ast.Name) and n.id in tainted:
            out.append((getattr(n, "lineno", 0), n.id))
        if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id in tainted_calls):
            out.append((getattr(n, "lineno", 0), n.func.id))
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute):
            # Attribute-form call to a tainted-return helper
            # (`self.render()` / `obj.as_row()`): same module-local
            # helper as the bare-Name arm above, spelled as a method.
            # Pre-fix this arm skipped the func Attribute entirely,
            # so method-spelled tainted returns were invisible
            # end-to-end (the service-health `as_row` relay class).
            # Scope mirrors the widened-name trade-off documented in
            # the docstring: SINK positions (wide=True) match any
            # receiver; taint-engine positions match only self/cls
            # receivers (unambiguously module-local method calls).
            # Helper names registered by short name collide with
            # common method spellings (`gate.to_dict()`,
            # `drain.collect()`) — letting those drive assignments
            # cascaded taint through whole-function Path/report
            # plumbing (measured: 5 phantom sink flags in one main()).
            # The un-matched assignment-position round-trip is a
            # documented residual, same shape as the widened-name one.
            recv = n.func.value
            if n.func.attr in tainted_calls and (
                wide
                or (isinstance(recv, ast.Name)
                    and recv.id in ("self", "cls"))
            ):
                out.append((getattr(n, "lineno", 0), n.func.attr))
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


def _container_base(target: ast.AST) -> str | None:
    """Base local name of a container-store target, or None.

    ``stats["k"] = v`` / ``rec.note = v`` store INTO ``stats`` /
    ``rec`` — the container name is what later whole-container reads
    launder taint through. Chains resolve to their root Name
    (``self.rows[i] = v`` → ``self`` is not a local; return None for
    non-Name roots).
    """
    node = target
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    if isinstance(node, ast.Name) and node is not target:
        return node.id
    return None


def _is_broad_handler(node: ast.excepthandler) -> bool:
    """True when the handler catches Exception/BaseException (alone or
    inside a tuple). Bare ``except:`` binds no name, so it never
    reaches the taint arm."""
    def _broad(t: ast.AST) -> bool:
        return (isinstance(t, ast.Name)
                and t.id in ("Exception", "BaseException"))
    t = node.type
    if t is None:
        return True
    if _broad(t):
        return True
    return isinstance(t, ast.Tuple) and any(_broad(elt) for elt in t.elts)


# Mutating container methods: ``recv.append(tainted)`` puts the value
# INSIDE ``recv`` — the receiver's base name becomes tainted so a
# later ``for k, v in recv: print(v)`` round-trip is visible. This is
# taint PROPAGATION, independent of whether the receiver also matches
# the accumulator-sink tokens.
_CONTAINER_MUTATORS = frozenset({
    "append", "extend", "insert", "add", "update", "setdefault",
    "appendleft",
})


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
    """Walk one module, tracking function frames and one-level taint.

    ``tainted_calls`` carries the module-local helper names whose
    return values were found tainted on a first pass (see
    :func:`audit_source`) — calls to them count as foreign reads on
    the second pass. ``tainted_return_funcs`` collects those names:
    a function whose ``return`` expression carries naked keys, tainted
    names, or a raw-serialiser call. One module-local level only —
    helper-of-helper chains and cross-module helpers stay out of
    scope (documented walk-scope limit).
    """

    def __init__(self, rel: str,
                 tainted_calls: frozenset = frozenset()) -> None:
        self.rel = rel
        self.violations: list[Violation] = []
        self.tainted_return_funcs: set[str] = set()
        self._tainted_calls = tainted_calls
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
        if _naked_keys(node.value, frozenset(self._tainted),
                       self._tainted_calls):
            for target in node.targets:
                for name in _target_names(target):
                    self._tainted.add(name)
                # Container round-trip, store side: a tainted value
                # stored INTO a container (``stats["hyp"] = e["hyp"]``,
                # ``rec.note = f["title"]``) taints the container name
                # — later whole-container reads (tuple-in-list, loop
                # unpack) would otherwise launder the value.
                base = _container_base(target)
                if base is not None:
                    self._tainted.add(base)
        else:
            # A sanitised (or unrelated) re-assignment clears the taint —
            # `body = _prose(body)` makes later uses of `body` safe.
            # Container stores never clear: one clean store into a dict
            # does not clean the tainted values already inside it.
            # FLOW-INSENSITIVE (documented residual, module docstring):
            # an except-arm fallback re-bind (`except: x = ""`) also
            # clears — such sites need their own test pin.
            for target in node.targets:
                if _container_base(target) is not None:
                    continue
                for name in _target_names(target):
                    self._tainted.discard(name)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        # Annotated assignment (``x: str = e["title"]``) is a distinct
        # AST node — and the repo's standing type-annotation practice
        # makes it the LIKELY spelling of new writer code, so skipping
        # it made annotated writers invisible to the audit.
        if node.value is None:
            self.generic_visit(node)
            return
        if _naked_keys(node.value, frozenset(self._tainted),
                       self._tainted_calls):
            for name in _target_names(node.target):
                self._tainted.add(name)
            base = _container_base(node.target)
            if base is not None:
                self._tainted.add(base)
        else:
            if _container_base(node.target) is None:
                for name in _target_names(node.target):
                    self._tainted.discard(name)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        # Walrus (``if (t := e["title"]): print(t)``) is an
        # Assign-class binding in expression position — skipping it
        # left walrus-spelled writers invisible, the same gap class as
        # the fixed AnnAssign blindness. Mirrors plain-Assign
        # semantics: a foreign value taints the target, a sanitised /
        # unrelated re-bind clears it (the target is always a plain
        # Name, so there is no container-store side).
        if _naked_keys(node.value, frozenset(self._tainted),
                       self._tainted_calls):
            for name in _target_names(node.target):
                self._tainted.add(name)
        else:
            for name in _target_names(node.target):
                self._tainted.discard(name)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        # ``x = ""; x += e["title"]`` — augmented assignment taints
        # the target when the value is foreign. It never CLEARS taint:
        # ``x += clean`` keeps whatever was already in ``x``.
        if _naked_keys(node.value, frozenset(self._tainted),
                       self._tainted_calls):
            for name in _target_names(node.target):
                self._tainted.add(name)
            base = _container_base(node.target)
            if base is not None:
                self._tainted.add(base)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        if _naked_keys(node.iter, frozenset(self._tainted),
                       self._tainted_calls):
            for name in _target_names(node.target):
                self._tainted.add(name)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None and self._fn_stack:
            if (_naked_keys(node.value, frozenset(self._tainted),
                            self._tainted_calls, wide=True)
                    or _raw_serialiser_calls(node.value)):
                # Short name — helper calls are matched by bare Name.
                self.tainted_return_funcs.add(self._fn_stack[-1])
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
                for line, key in _naked_keys(arg, tainted,
                                             self._tainted_calls,
                                             wide=True):
                    self.violations.append(Violation(
                        file=self.rel,
                        line=line or node.lineno,
                        kind="unsanitised_llm_value",
                        detail=key,
                        func_name=self._qualified_func_name(),
                    ))
                # Whole-payload dumps read no key at all — flag the
                # serialiser call itself when its output reaches a
                # TERMINAL-capable sink with C1 passthrough. File
                # sinks (.write_text, plain handle .write) are the
                # artifact lane where dumps_artifact is the contract.
                if _terminal_capable_sink(node):
                    for line, name in _raw_serialiser_calls(arg):
                        self.violations.append(Violation(
                            file=self.rel,
                            line=line or node.lineno,
                            kind="raw_serialiser_at_sink",
                            detail=name,
                            func_name=self._qualified_func_name(),
                        ))
        # Container round-trip, mutate side: `recv.append(tainted)` /
        # `recv.update(tainted)` puts a foreign value INSIDE recv;
        # taint the receiver's base local name.
        func = node.func
        if (isinstance(func, ast.Attribute)
                and func.attr in _CONTAINER_MUTATORS
                and node.args):
            tainted = frozenset(self._tainted)
            if any(_naked_keys(a, tainted, self._tainted_calls)
                   for a in node.args):
                base = func.value
                while isinstance(base, (ast.Subscript, ast.Attribute)):
                    base = base.value
                if isinstance(base, ast.Name):
                    self._tainted.add(base.id)
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


# Fence-lane sanitisers: correct ONLY where a wrapping ``` fence
# isolates rendering. In a heading / table-row / bold-label slot they
# preserve newlines, line-leading `#`, and live links — structure
# forgery sails through while the gate sees "a recognised sanitiser"
# (the flat _SANITISERS short-circuit has no slot model). The
# wrong-slot arm below is the syntactic slot model for the highest-
# signal shape: an f-string whose constant text puts the
# interpolation in a single-line markdown structure slot.
_FENCE_LANE_SANITISERS = frozenset({"md_fence", "sanitise_code"})

# Constant-prefix shapes that mark a single-line markdown slot. The
# prefix is the LAST LINE of constant text immediately before the
# interpolation: a heading lead (`### `), a table-row cell (`| ` /
# `x |`), or a bold-label opener (`**`).
_HEADING_SLOT_RE = re.compile(r"[ \t]*#{1,6}[ \t]+\Z")
_TABLE_SLOT_RE = re.compile(r".*\|[ \t]*\Z")
_BOLD_SLOT_RE = re.compile(r".*\*\*\Z")


def _wrong_slot_scan(tree: ast.AST, rel: str) -> list[Violation]:
    """Flag fence-lane sanitiser calls interpolated into heading /
    table-cell / bold-label f-string slots (``f"### {md_fence(x)}"``).

    The next-writer failure mode after the one-home landed: adopting
    the WRONG helper is indistinguishable from the right one to the
    flat sanitiser vocabulary, and ``md_fence`` in a heading slot
    passes the gate while preserving newlines, line-leading ``#`` and
    live links. Allowlistable like every other kind.
    """
    hits: list[tuple[ast.FormattedValue, ast.JoinedStr, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        before: list[str] = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                before.append(part.value)
                continue
            if isinstance(part, ast.FormattedValue):
                call_name = (_call_name(part.value)
                             if isinstance(part.value, ast.Call) else None)
                if call_name in _FENCE_LANE_SANITISERS:
                    last_line = "".join(before).rsplit("\n", 1)[-1]
                    slot = None
                    if _HEADING_SLOT_RE.fullmatch(last_line):
                        slot = "heading"
                    elif _TABLE_SLOT_RE.fullmatch(last_line):
                        slot = "table-cell"
                    elif _BOLD_SLOT_RE.fullmatch(last_line):
                        slot = "bold-label"
                    if slot is not None:
                        hits.append((part, node, call_name, slot))
                # Any interpolation makes the running prefix
                # non-constant — reset so a later call on the same
                # line is only judged against text we can SEE.
                before = []
    if not hits:
        return []

    parents: dict = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def _func_of(node: ast.AST) -> str:
        names: list[str] = []
        cur = parents.get(node)
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef,
                                ast.ClassDef)):
                names.append(cur.name)
            cur = parents.get(cur)
        return ".".join(reversed(names)) or "<module>"

    return [
        Violation(
            file=rel,
            line=part.lineno,
            kind="wrong_slot_sanitiser",
            detail=f"{call_name} in {slot} slot",
            func_name=_func_of(node),
        )
        for part, node, call_name, slot in hits
    ]


def audit_source(source: str, rel: str = "<snippet>") -> list[Violation]:
    """Audit a source string. Used by the self-tests and by
    :func:`audit_file`."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    # Pass 1 collects module-local helpers whose return value is
    # tainted (render_json-style); pass 2 reports with calls to them
    # treated as foreign reads. Pass-1 violations are discarded — the
    # second pass re-derives them with the fuller call knowledge.
    pre = _Scanner(rel)
    pre.visit(tree)
    scanner = _Scanner(rel, frozenset(pre.tainted_return_funcs))
    scanner.visit(tree)
    violations = scanner.violations
    violations.extend(_mermaid_scan(tree, rel))
    violations.extend(_sanitiser_shadow_scan(tree, rel))
    violations.extend(_wrong_slot_scan(tree, rel))
    _parents: dict = {}
    violations.extend(_exception_relay_scan(tree, rel, _parents))
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
