"""Regression test: LLM-derived values in registered report-writer
modules must pass through a recognised output sanitiser before reaching
a write sink (print / lines.append / .write_text / ReportSection), and
f-string interpolations inside ```mermaid fences must be sanitiser
calls.

Operates on the heuristic AST rule in
:mod:`core.security.report_writer_audit` — the output-side companion of
``prompt_envelope_audit``. The rule catches:

  * f-string / call-argument reads of known LLM-derived free-text
    fields (``title``, ``claim``, ``body``, ``reasoning``, ...) via
    attribute, string subscript, ``.get()``, or ``getattr()``
  * one-level local taint (``x = f.get("title")`` then ``print(x)``)
  * unsanitised interpolations inside ```mermaid fences

It does NOT catch:

  * cross-function dataflow (a helper returning raw LLM text)
  * fields not registered in ``_LLM_DERIVED_KEYS``
  * writers not registered in ``_REPORT_WRITER_FILES``

When this test fails, the options are:

  1. **Fix the call site**: route the value through
     ``core.security.prompt_output_sanitise`` (``sanitise_string`` for
     free text, ``sanitise_code`` for fenced code) or a single-line
     helper (``_line`` / ``_cell`` / ``_md_heading`` / ``_fence``).
  2. **Allowlist with audit note**: if the call site is genuinely safe
     (integer counter, RAPTOR-internal string), add an
     :class:`AllowlistEntry` to ``_ALLOWLIST`` with a one-line
     explanation. Reviewers verify the note before merge.

Adding a new report writer? Append it to ``_REPORT_WRITER_FILES`` in
the audit module — that registers the file for inspection at every CI
run, forcing a security-review checkpoint at file-add time.
"""

from __future__ import annotations

from core.security.report_writer_audit import (
    audit_repo,
    audit_source,
    filter_allowlisted,
    render_violations,
)


def test_no_unallowlisted_raw_llm_values_in_report_writers():
    """Every LLM-derived value reaching a write sink in the registered
    report writers must be sanitised at the call site OR carry an
    explicit allowlist entry with an audit note."""
    violations = audit_repo()
    remaining = filter_allowlisted(violations)
    assert not remaining, (
        "Unsanitised LLM-derived value reaching a report/terminal write "
        "sink. Route it through core.security.prompt_output_sanitise "
        "(sanitise_string / sanitise_code or a _line/_cell/_md_heading "
        "helper) or add an AllowlistEntry to "
        "core/security/report_writer_audit.py with an audit_note "
        "explaining why this site is safe.\n"
        + render_violations(remaining)
    )


def test_allowlist_entries_carry_audit_notes():
    """Empty / TODO audit notes would silently grandfather violations."""
    from core.security.report_writer_audit import _ALLOWLIST
    for entry in _ALLOWLIST:
        assert entry.audit_note.strip(), (
            f"AllowlistEntry for {entry.file} func={entry.func_name!r} "
            f"detail={entry.detail!r} has empty audit_note."
        )
        assert "TODO" not in entry.audit_note, (
            f"AllowlistEntry for {entry.file} func={entry.func_name!r} "
            f"detail={entry.detail!r} carries a TODO audit_note — fill "
            "it in before merging."
        )


def test_registered_files_exist():
    """Catches typos / renames in the registry."""
    from core.security.report_writer_audit import (
        _MERMAID_FENCE_FILES,
        _REPO_ROOT,
        _REPORT_WRITER_FILES,
    )
    for rel in _REPORT_WRITER_FILES + _MERMAID_FENCE_FILES:
        assert (_REPO_ROOT / rel).exists(), (
            f"report_writer_audit registry references missing file: "
            f"{rel}. Either rename in the registry or remove."
        )


# ---------------------------------------------------------------------------
# Self-tests on the rule itself — deliberately-bad snippets pin that a
# revert of any batch fix re-fires the audit, WITHOUT actually reverting.
# ---------------------------------------------------------------------------


def test_rule_catches_raw_title_in_heading_append():
    """The core/audit/report.py fix shape: `title = f.get("title")`
    into a markdown heading line. Reverting the `_line(...)` wrap must
    fire."""
    src = (
        "def write_markdown_report(findings, lines):\n"
        "    for f in findings:\n"
        '        lines.append(f"### {f.get(\'id\')}: {f.get(\'title\')}")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "title" for v in vs)


def test_rule_catches_raw_body_print():
    """The raptor-review / raptor-annotate fix shape: annotation body
    printed to the terminal."""
    src = (
        "def cmd_show(ann):\n"
        "    print(ann.body)\n"
    )
    vs = audit_source(src)
    assert any(v.detail == "body" for v in vs)


def test_rule_catches_tainted_local_into_report_section():
    """The validation-report fix shape: `stage_f_notes =
    findings_data.get("stage_f_review")` flowing into a ReportSection."""
    src = (
        "def generate(findings_data, extra_sections):\n"
        '    stage_f_notes = findings_data.get("stage_f_review")\n'
        "    if stage_f_notes:\n"
        '        extra_sections.append(ReportSection("Stage F Review", stage_f_notes))\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "stage_f_notes" for v in vs)


def test_rule_catches_taint_through_for_loop():
    """`for line in body.splitlines(): print(line)` — taint propagates
    through loop targets."""
    src = (
        "def show(ann):\n"
        '    body = getattr(ann, "body", "")\n'
        "    for line in body.splitlines():\n"
        '        print(f"    {line}")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "line" for v in vs)


def test_rule_catches_unsanitised_mermaid_embed():
    """The diagram-renderer fix shape: a raw diagram string inside a
    ```mermaid fence. Reverting the `_fence(...)` wrap must fire."""
    src = (
        "def render(diagram):\n"
        '    return f"```mermaid\\n{diagram}\\n```"\n'
    )
    vs = audit_source(src)
    assert any(v.kind == "unsanitised_mermaid_embed" for v in vs)


def test_rule_passes_sanitised_variants():
    """The fixed shapes must NOT fire: sanitiser-wrapped values, a
    sanitised re-assignment clearing taint, and a fenced embed through
    `_fence`."""
    src = (
        "def write(f, lines, extra_sections, diagram):\n"
        '    lines.append(f"### {sanitise_string(f.get(\'title\'))}")\n'
        '    notes = sanitise_string(f.get("stage_f_review") or "")\n'
        '    extra_sections.append(ReportSection("Stage F Review", notes))\n'
        '    body = _prose(f.get("body"))\n'
        "    for line in body.splitlines():\n"
        '        print(f"    {line}")\n'
        '    fenced = f"```mermaid\\n{_fence(diagram)}\\n```"\n'
        "    lines.append(fenced)\n"
    )
    assert audit_source(src) == []


def test_rule_ignores_non_sink_reads():
    """Reading an LLM-derived field without emitting it (JSON dumps,
    conditionals, dict construction) is not a violation — the rule is
    about write sinks, not all uses."""
    src = (
        "def collect(f, records):\n"
        '    if f.get("title"):\n'
        '        records.append({"title": f.get("title")})\n'
        '    return f["body"]\n'
    )
    assert audit_source(src) == []


def test_rule_ignores_string_method_calls():
    """`severity.title()` is a str method, not a field read."""
    src = (
        "def group(severity, lines):\n"
        '    lines.append(f"## {severity.title()}")\n'
    )
    assert audit_source(src) == []
