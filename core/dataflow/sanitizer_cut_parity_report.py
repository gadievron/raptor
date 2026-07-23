"""First-window parity report generator — Phase 15 of the
sanitizer-cut arc.

Produces the committed baseline parity report from a small *labelled*
fixture set spanning the three proposal shapes:

* ``charset`` — a whole-string allowlist guarded by an ``if not …:
  return`` block. The lexical validator-dominance check is designed
  for this shape.
* ``charset_sub`` — an assignment-form sanitizer (``x = re.sub(…, x)``)
  with no later rebind. The lexical substitution check targets this.
* ``sanitizer_cut`` — a catalog sanitizer transforms a value that
  then flows to the sink (``y = html.escape(x); render(y)``). The
  value-bound gate targets this; the lexical checks don't fire.

Each fixture is labelled ``should_suppress`` (genuinely safe) or
``should_not_suppress`` (a real or unproven issue). For each, we
compute the pure lexical decision and the value-bound verdict, build
a :class:`core.dataflow.sanitizer_cut_parity.ParityRecord`, aggregate,
and render the markdown report.

This is a *baseline* on a synthetic, deliberately-balanced fixture
set — NOT the gating window. The real Phase 16 gate is collected
from `/agentic` runs via the shadow log (see the horizon doc). The
baseline's job is to (a) prove the machinery end-to-end and (b) make
the value-bound gate's current coverage gap on validator/substitution
shapes visible.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import List, NamedTuple, Optional

from core.dataflow.sanitizer_cut_parity import (
    LABEL_SHOULD_NOT_SUPPRESS,
    LABEL_SHOULD_SUPPRESS,
    ParityRecord,
    ParitySummary,
    aggregate_parity,
    build_parity_record,
    render_parity_report,
    value_bound_verdict_for,
)


class _Fixture(NamedTuple):
    name: str
    kind: str                  # "charset" | "charset_sub" | "sanitizer_cut"
    source: str
    source_line: int
    sink_line: int
    cwe: str
    label: str
    var_name: Optional[str] = None   # for charset_sub lexical check


# Labelled baseline fixtures. Line numbers are 1-indexed into ``source``.
_FIXTURES: List[_Fixture] = [
    # --- charset validator shape — lexical fires, value-bound doesn't ---
    _Fixture(
        name="validator_guard_safe",
        kind="charset",
        source=(
            "def handle(x):\n"
            "    if not re.match('^[a-z]+$', x):\n"
            "        return\n"
            "    render(x)\n"
        ),
        source_line=2, sink_line=4, cwe="CWE-79",
        label=LABEL_SHOULD_SUPPRESS,
    ),
    _Fixture(
        name="validator_guard_no_exit",
        kind="charset",
        source=(
            "def handle(x):\n"
            "    if not re.match('^[a-z]+$', x):\n"
            "        log('bad')\n"
            "    render(x)\n"
        ),
        # Validator doesn't exit on failure → the value still reaches
        # the sink. Real issue; neither method should suppress.
        source_line=2, sink_line=4, cwe="CWE-79",
        label=LABEL_SHOULD_NOT_SUPPRESS,
    ),
    # --- substitution shape — lexical fires, value-bound doesn't ---
    _Fixture(
        name="substitution_safe",
        kind="charset_sub",
        source=(
            "def handle(x):\n"
            "    x = re.sub('[<>]', '', x)\n"
            "    render(x)\n"
        ),
        source_line=2, sink_line=3, cwe="CWE-79",
        label=LABEL_SHOULD_SUPPRESS, var_name="x",
    ),
    _Fixture(
        name="substitution_overwritten",
        kind="charset_sub",
        source=(
            "def handle(x):\n"
            "    x = re.sub('[<>]', '', x)\n"
            "    x = raw_input()\n"
            "    render(x)\n"
        ),
        # Sanitized value is rebound before the sink. Real issue.
        source_line=2, sink_line=4, cwe="CWE-79",
        label=LABEL_SHOULD_NOT_SUPPRESS, var_name="x",
    ),
    # --- sanitizer-cut shape — value-bound fires, lexical doesn't ---
    _Fixture(
        name="sanitizer_cut_safe",
        kind="sanitizer_cut",
        source=(
            "def handle(x):\n"
            "    y = html.escape(x)\n"
            "    render(y)\n"
        ),
        source_line=1, sink_line=3, cwe="CWE-79",
        label=LABEL_SHOULD_SUPPRESS,
    ),
    _Fixture(
        name="sanitizer_cut_wrong_variable",
        kind="sanitizer_cut",
        source=(
            "def handle(user, other):\n"
            "    safe = html.escape(other)\n"
            "    render(user)\n"
        ),
        # Sanitizer cleans the wrong symbol; sink reads user. Real bug.
        source_line=1, sink_line=3, cwe="CWE-79",
        label=LABEL_SHOULD_NOT_SUPPRESS,
    ),
    _Fixture(
        name="sanitizer_cut_helper",
        kind="sanitizer_cut",
        source=(
            "def _sanitize(s):\n"
            "    return html.escape(s)\n"
            "def handle(x):\n"
            "    y = _sanitize(x)\n"
            "    render(y)\n"
        ),
        # Sanitization in a callee — Phase 14 inter-proc suppresses.
        source_line=3, sink_line=5, cwe="CWE-79",
        label=LABEL_SHOULD_SUPPRESS,
    ),
]


def _lexical_decision(fx: _Fixture, path: str) -> bool:
    """Pure lexical decision for the fixture's shape. Calls the
    smt_barrier lexical helpers directly (no value-bound kwargs, so
    no recursion into the gate)."""
    from core.dataflow.smt_barrier import (
        _lexical_substitution_dominates,
        _lexical_validator_dominates,
    )
    if fx.kind == "charset":
        return _lexical_validator_dominates(
            fx.source, fx.source_line, fx.sink_line,
        )
    if fx.kind == "charset_sub":
        return _lexical_substitution_dominates(
            fx.source, fx.source_line, fx.sink_line, fx.var_name or "",
        )
    # sanitizer_cut shapes have no lexical-validator form → False.
    return False


def build_baseline_records() -> List[ParityRecord]:
    """Compute a :class:`ParityRecord` for each labelled fixture."""
    records: List[ParityRecord] = []
    with tempfile.TemporaryDirectory() as tmp:
        for fx in _FIXTURES:
            path = str(Path(tmp) / f"{fx.name}.py")
            Path(path).write_text(fx.source, encoding="utf-8")
            lexical = _lexical_decision(fx, path)
            finding = {
                "cwe": fx.cwe,
                "file_path": path,
                "source_line": fx.source_line,
                "sink_line": fx.sink_line,
                "language": "python",
            }
            verdict = value_bound_verdict_for(finding)
            records.append(build_parity_record(
                finding_id=fx.name,
                file=f"{fx.name}.py",
                cwe=fx.cwe,
                language="python",
                source_line=fx.source_line,
                sink_line=fx.sink_line,
                kind=fx.kind,
                lexical_suppressed=lexical,
                value_bound_verdict=verdict,
                label=fx.label,
            ))
    return records


def build_baseline_summary() -> ParitySummary:
    return aggregate_parity(build_baseline_records())


def render_baseline_report() -> str:
    summary = build_baseline_summary()
    body = render_parity_report(
        summary, title="Sanitizer-cut parity — first baseline report",
    )
    note = (
        "\n> **Baseline, not the gating window.** This report is "
        "generated from a small synthetic fixture set "
        "(`core/dataflow/sanitizer_cut_parity_report.py`) to prove the "
        "telemetry machinery end-to-end and expose the value-bound "
        "gate's current coverage. The Phase 16 gate is decided on the "
        "real horizon window collected from `/agentic` runs via the "
        "shadow log — see `docs/sanitizer-cut-parity/HORIZON.md`.\n"
    )
    return body + note


__all__ = [
    "build_baseline_records",
    "build_baseline_summary",
    "render_baseline_report",
]
