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

import pytest

from core.security.report_writer_audit import (
    audit_repo,
    audit_source,
    filter_allowlisted,
    render_violations,
)


# Runs the full AST taint rule over every registered report writer —
# genuinely heavy; over the fast tier's budget. The registry and rule
# fixtures below keep the audit machinery pinned in the default tier.
@pytest.mark.slow
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


def test_both_validation_report_generators_registered():
    """validation-report.md has TWO generators (report.py's pipeline
    renderer and the orchestrator's inline _generate_report). Both
    interpolate finding-derived text into the same operator-facing
    artifact — losing either from the registry ships its future edits
    unaudited."""
    from core.security.report_writer_audit import _REPORT_WRITER_FILES
    for rel in (
        "packages/exploitability_validation/report.py",
        "packages/exploitability_validation/orchestrator.py",
    ):
        assert rel in _REPORT_WRITER_FILES, (
            f"validation-report.md generator missing from the "
            f"report-writer audit registry: {rel}"
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


def test_rule_catches_attribute_receiver_accumulator():
    """Method-style writers accumulate through Attribute-chain
    receivers (``self.lines.append``) — a bare-Name-only receiver
    match left them invisible to the audit."""
    src = (
        "class Writer:\n"
        "    def add(self, f):\n"
        '        self.lines.append(f"### {f.get(\'title\')}")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "title" for v in vs)


def test_rule_ignores_attribute_receiver_without_accumulator_token():
    # Two-direction guard: an Attribute receiver whose chain carries
    # no accumulator token is still not a sink.
    src = (
        "class Writer:\n"
        "    def add(self, f):\n"
        '        self.records.append({"title": f.get("title")})\n'
    )
    assert audit_source(src) == []


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


def test_rule_accepts_sanitise_for_terminal():
    """Terminal-only writers route foreign-derived fields through
    ``sanitise_for_terminal`` (escape + length bound); the rule must
    recognise it, or every registered terminal writer needs a
    per-site allowlist entry."""
    src = (
        "def show(f):\n"
        '    print(f"finding: {sanitise_for_terminal(f.get(\'title\'))}")\n'
    )
    assert audit_source(src) == []


def test_rule_still_rejects_escape_nonprintable():
    # Two-direction guard: escape_nonprintable alone (no length bound,
    # no markdown defang) stays outside the recognised sanitiser set.
    src = (
        "def show(f):\n"
        '    print(f"finding: {escape_nonprintable(f.get(\'title\'))}")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "title" for v in vs)


def test_rule_ignores_string_method_calls():
    """`severity.title()` is a str method, not a field read."""
    src = (
        "def group(severity, lines):\n"
        '    lines.append(f"## {severity.title()}")\n'
    )
    assert audit_source(src) == []


def test_rule_catches_bullets_receiver_accumulator():
    """packages/sca/report.py's per-finding renderer accumulates its
    markdown through a ``bullets`` list. Without the receiver token
    the file's registration was vacuous — reverting its summary
    sanitiser never fired the audit."""
    src = (
        "def render(f, primary):\n"
        "    bullets = []\n"
        '    bullets.append(f"- Summary: {primary.summary}")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "summary" for v in vs)


def test_rule_catches_advisory_details_taint_into_bullets():
    """OSV advisory ``details`` is attacker-writable free text; a
    tainted local reaching the accumulator without the sanitiser must
    fire (the <details>-embed revert shape in packages/sca/report.py)."""
    src = (
        "def render(primary, bullets):\n"
        "    detail = primary.details or ''\n"
        "    clipped = detail.strip()\n"
        '    bullets.append(f"<details>{clipped}</details>")\n'
    )
    vs = audit_source(src)
    assert any(v.detail in ("details", "clipped") for v in vs)


def test_rule_passes_sanitised_bullets_append():
    # Two-direction guard: the sanitised shape the fixed writer
    # actually uses stays clean under the new receiver token.
    src = (
        "def render(f, primary, bullets):\n"
        '    bullets.append(f"- Summary: {sanitise_string(primary.summary)}")\n'
    )
    assert audit_source(src) == []


def test_rule_catches_raw_subprocess_stderr_print():
    """Tool output is foreign-derived: `git apply` failures quote the
    target's context lines, compiler diagnostics quote hostile source.
    A raw proc.stderr print must fire."""
    src = (
        "def run(proc):\n"
        "    print(proc.stderr)\n"
    )
    vs = audit_source(src)
    assert any(v.detail == "stderr" for v in vs)


def test_rule_catches_tainted_stdout_local():
    src = (
        "def run(proc, lines):\n"
        "    out = proc.stdout\n"
        '    lines.append(f"tool said: {out}")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "out" for v in vs)


def test_rule_ignores_sys_stderr_stream():
    # Two-direction guard: the STREAM objects are not tool output.
    src = (
        "def warn():\n"
        '    print("careful", file=sys.stderr)\n'
        "    _sys.stderr.write('x')\n"
    )
    assert audit_source(src) == []


def test_rule_passes_sanitised_stderr():
    src = (
        "def run(proc):\n"
        "    print(sanitise_for_terminal(proc.stderr, max_len=500))\n"
    )
    assert audit_source(src) == []


def test_rule_catches_typer_echo_attribute_sink():
    """typer.echo is a terminal sink like print — a CLI built on typer
    must not relay foreign text invisibly to this audit."""
    src = (
        "def show(r):\n"
        '    typer.echo(f"FAIL — {r.error}", err=True)\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "error" for v in vs)


def test_rule_catches_echo_name_form_sink():
    src = (
        "from typer import echo\n"
        "def show(r):\n"
        "    echo(r.stderr)\n"
    )
    vs = audit_source(src)
    assert any(v.detail == "stderr" for v in vs)


def test_rule_catches_secho_sink():
    src = (
        "def show(r):\n"
        '    click.secho(r.reasoning, fg="red")\n'
    )
    vs = audit_source(src)
    assert any(v.detail == "reasoning" for v in vs)


def test_rule_passes_sanitised_typer_echo():
    src = (
        "def show(r):\n"
        "    typer.echo(sanitise_for_terminal(r.error, max_len=512))\n"
    )
    assert audit_source(src) == []


def test_registered_files_have_no_dumps_display_terminal_lane():
    """dumps_display leaves C1 terminal controls raw (ensure_ascii is
    off by contract) — a registered writer's --json terminal lane must
    ASCII-encode via json.dumps(..., ensure_ascii=True) instead.
    File-writer/report-content uses of dumps_display (markdown
    artifacts, prompt embeds) are out of this pin's scope: only
    direct-to-terminal shapes are matched."""
    from core.security.report_writer_audit import (
        _REPO_ROOT,
        _REPORT_WRITER_FILES,
    )
    terminal_shapes = (
        "print(dumps_display(",
        "stdout.write(dumps_display(",
        "buffer.write(dumps_display(",
        "echo(dumps_display(",
    )
    offenders = []
    for rel in _REPORT_WRITER_FILES:
        path = _REPO_ROOT / rel
        if not path.is_file():
            continue
        src = path.read_text(encoding="utf-8")
        offenders.extend(
            (rel, shape) for shape in terminal_shapes if shape in src
        )
    assert not offenders, (
        f"dumps_display terminal lane(s) in registered writers "
        f"(use json.dumps(..., ensure_ascii=True)): {offenders}"
    )


# ---------------------------------------------------------------------------
# Taint-propagation arms: annotated/augmented assignment and container
# round-trips. Each planted writer FAILS without its arm (mutation
# oracle for the closure claim).
# ---------------------------------------------------------------------------


def test_rule_catches_annassign_taint():
    """``x: str = e["title"]`` — AnnAssign is a distinct AST node and
    the repo's annotation practice makes it the likely spelling of new
    writer code."""
    src = (
        "def render(e):\n"
        "    x: str = e['title']\n"
        "    print(x)\n"
    )
    assert any(v.detail == "x" for v in audit_source(src))


def test_rule_catches_augassign_taint():
    """``x = ''; x += e['title']`` — AugAssign taints its target."""
    src = (
        "def render(e):\n"
        "    x = ''\n"
        "    x += e['title']\n"
        "    print(x)\n"
    )
    assert any(v.detail == "x" for v in audit_source(src))


def test_augassign_never_clears_taint():
    """``x += clean`` keeps whatever taint x already carried."""
    src = (
        "def render(e):\n"
        "    x = e['title']\n"
        "    x += ' suffix'\n"
        "    print(x)\n"
    )
    assert any(v.detail == "x" for v in audit_source(src))


def test_rule_catches_walrus_taint():
    """``if (t := e['title']): print(t)`` — NamedExpr is an
    Assign-class binding in expression position; skipping it made
    walrus-spelled writers invisible (same gap class as the fixed
    AnnAssign blindness)."""
    src = (
        "def render(e):\n"
        "    if (t := e['title']):\n"
        "        print(t)\n"
    )
    assert any(v.detail == "t" for v in audit_source(src))


def test_walrus_sanitised_value_reads_clean():
    """``(t := sanitise_string(...))`` is a sanitising re-bind — no
    taint, mirroring plain-Assign clearing semantics."""
    src = (
        "def render(e):\n"
        "    t = e['title']\n"
        "    if (t := sanitise_string(e['title'])):\n"
        "        print(t)\n"
    )
    assert not audit_source(src)


def test_rule_catches_format_exc_at_sink():
    """``print(f'...{traceback.format_exc()}')`` relays the same
    exception text the exception-relay arm exists for, while reading
    no bound name and no vocabulary key — foreign-call vocabulary."""
    src = (
        "import traceback\n"
        "def render():\n"
        "    try:\n"
        "        work()\n"
        "    except Exception:\n"
        "        print(f'failed: {traceback.format_exc()}')\n"
    )
    assert any(v.detail == "format_exc" for v in audit_source(src))


def test_rule_catches_format_exc_through_assignment():
    """``tb = traceback.format_exc(); print(tb)`` — the foreign call
    drives the taint engine like any vocabulary read."""
    src = (
        "import traceback\n"
        "def render():\n"
        "    tb = traceback.format_exc()\n"
        "    print(tb)\n"
    )
    assert any(v.detail == "tb" for v in audit_source(src))


def test_format_exc_sanitised_reads_clean():
    src = (
        "import traceback\n"
        "def render():\n"
        "    print(sanitise_string(traceback.format_exc()))\n"
    )
    assert not audit_source(src)


def test_rule_catches_container_round_trip():
    """The raptor-audit cmd_critique shape: dict-store, tuple-in-list,
    loop-unpack print — no foreign key name visible at the sink."""
    src = (
        "def critique(log):\n"
        "    gaps = []\n"
        "    for entry in log:\n"
        "        stats = {}\n"
        "        stats['hyp'] = entry['hypothesis']\n"
        "        gaps.append((entry['key'], stats))\n"
        "    for key, st in gaps:\n"
        "        print(f'  {key} - {st}')\n"
    )
    vs = audit_source(src)
    assert any(v.detail in ("key", "st") for v in vs), vs


def test_rule_catches_local_var_interpolation_round_trip():
    """Mechanism-5 shape: a vocabulary read split into a local list,
    printed one loop variable at a time — no foreign name at the
    sink."""
    src = (
        "def show(res):\n"
        "    msg = res.get('description')\n"
        "    seg_list = msg.splitlines()\n"
        "    for seg in seg_list:\n"
        "        print(f'  {seg}')\n"
    )
    assert any(v.detail == "seg" for v in audit_source(src))


def test_container_store_does_not_clear_on_clean_write():
    """One clean store into a dict does not clean the tainted values
    already inside it."""
    src = (
        "def render(e):\n"
        "    d = {}\n"
        "    d['a'] = e['title']\n"
        "    d['b'] = 'clean'\n"
        "    print(d)\n"
    )
    assert any(v.detail == "d" for v in audit_source(src))


# ---------------------------------------------------------------------------
# FP tunings — the negative direction (both-direction pins for the
# churn-prone taint heuristics).
# ---------------------------------------------------------------------------


def test_len_of_tainted_container_is_clean():
    """``print(f"{len(rows)} rows")`` is a count, not content —
    len() destroys content, so the summary-count idiom stays clean."""
    src = (
        "def render(e):\n"
        "    rows = [e['title']]\n"
        "    print(f'{len(rows)} row(s)')\n"
    )
    assert audit_source(src) == []


def test_ifexp_condition_does_not_taint_sanitised_value():
    """``x = _sft(v) if v else None`` — the test picks a branch but
    contributes no content; both branch values are safe."""
    src = (
        "def render(e):\n"
        "    v = e.get('hypothesis')\n"
        "    x = _sft(v) if v else None\n"
        "    print(x)\n"
    )
    assert audit_source(src) == []


def test_ifexp_tainted_branch_still_fires():
    src = (
        "def render(e):\n"
        "    v = e.get('hypothesis')\n"
        "    x = v if v else 'none'\n"
        "    print(x)\n"
    )
    assert any(v.detail == "x" for v in audit_source(src))


def test_repr_conversion_is_clean():
    """``{value!r}`` renders through repr(), which escapes
    non-printables in strings."""
    src = (
        "def render(e):\n"
        "    name = e['title']\n"
        "    print(f'bad name {name!r}')\n"
    )
    assert audit_source(src) == []


def test_ascii_json_dumps_is_clean_and_nonascii_fires():
    """json.dumps(..., ensure_ascii=True) is the blessed terminal-JSON
    shape; without the keyword the read still fires."""
    safe = (
        "def render(e):\n"
        "    import json\n"
        "    print(json.dumps(e['details'], ensure_ascii=True))\n"
    )
    assert audit_source(safe) == []
    unsafe = (
        "def render(e):\n"
        "    import json\n"
        "    print(json.dumps(e['details'], ensure_ascii=False))\n"
    )
    assert any(v.detail == "details" for v in audit_source(unsafe))


# ---------------------------------------------------------------------------
# Helper-return and raw-serialiser arms.
# ---------------------------------------------------------------------------


def test_rule_catches_helper_return_at_sink():
    """The render_json shape: taint dies at a module-local helper
    return and reaches the sink as an opaque call."""
    src = (
        "def render_json(report):\n"
        "    return dumps_artifact(asdict(report), sort_keys=True)\n"
        "\n"
        "def main(report):\n"
        "    sys.stdout.write(render_json(report))\n"
    )
    vs = audit_source(src)
    assert any(v.detail == "render_json" for v in vs), vs


def test_rule_catches_helper_returning_foreign_key():
    src = (
        "def summary(e):\n"
        "    return e['title']\n"
        "\n"
        "def main(e):\n"
        "    print(summary(e))\n"
    )
    assert any(v.detail == "summary" for v in audit_source(src))


def test_rule_catches_attribute_form_helper_return_at_sink():
    """Method-spelled module-local helper (`self.render()`): same
    tainted return as the bare-Name shape, previously invisible —
    the service-health `as_row` relay class."""
    src = (
        "class T:\n"
        "    def render(self):\n"
        "        return self.data['title']\n"
        "    def show(self):\n"
        "        print(self.render())\n"
    )
    assert any(v.detail == "render" for v in audit_source(src))


def test_rule_catches_object_receiver_helper_at_sink():
    """Any-receiver method call at a SINK position: `r.as_row()`
    accumulated into the printed table."""
    src = (
        "class R:\n"
        "    def as_row(self):\n"
        "        return self.data['detail']\n"
        "\n"
        "def table(rows):\n"
        "    lines = []\n"
        "    for r in rows:\n"
        "        lines.append(r.as_row())\n"
        "    print('\\n'.join(lines))\n"
    )
    assert any(v.detail == "as_row" for v in audit_source(src))


def test_attribute_form_sanitised_helper_stays_clean():
    src = (
        "class T:\n"
        "    def render(self):\n"
        "        return sanitise_for_terminal(self.data['title'])\n"
        "    def show(self):\n"
        "        print(self.render())\n"
    )
    assert audit_source(src) == []


def test_object_receiver_assignment_position_is_documented_residual():
    """Assignment-position matching for NON-self receivers is
    deliberately out (documented residual, same shape as the
    widened-name round-trip): short helper names collide with common
    method spellings (`gate.to_dict()`, `drain.collect()`) and
    letting them drive the taint engine cascaded taint through
    whole-function plumbing. Pin the boundary so a change is a
    decision, not drift."""
    src = (
        "class G:\n"
        "    def to_dict(self):\n"
        "        return self.data['raw']\n"
        "\n"
        "def main(gate):\n"
        "    meta = gate.to_dict()\n"
        "    print(meta)\n"
    )
    # Known-direction pin: the local round-trip through a non-self
    # receiver is NOT caught. If this starts firing, the boundary
    # moved — re-run the tree-wide amplification measurement before
    # accepting.
    assert audit_source(src) == []


def test_clean_helper_call_stays_clean():
    """A module-local helper whose return is sanitised does not mark
    its callers."""
    src = (
        "def summary(e):\n"
        "    return _line(e['title'])\n"
        "\n"
        "def main(e):\n"
        "    print(summary(e))\n"
    )
    assert audit_source(src) == []


def test_rule_catches_dumps_display_at_print():
    """Whole-dict dumps read no key at all — the key-vocabulary arm
    can never see them (mechanism 6)."""
    src = (
        "def show(payload):\n"
        "    print(dumps_display(payload))\n"
    )
    vs = audit_source(src)
    assert any(v.kind == "raw_serialiser_at_sink"
               and v.detail == "dumps_display" for v in vs)


def test_rule_catches_dumps_artifact_at_stdout_write():
    src = (
        "def show(payload):\n"
        "    sys.stdout.write(dumps_artifact(payload))\n"
    )
    vs = audit_source(src)
    assert any(v.kind == "raw_serialiser_at_sink" for v in vs)


def test_dumps_artifact_ensure_ascii_at_terminal_is_clean():
    src = (
        "def show(payload):\n"
        "    sys.stdout.write(dumps_artifact(payload, ensure_ascii=True))\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "raw_serialiser_at_sink"]


def test_dumps_artifact_to_file_write_text_is_clean():
    """File artifacts are dumps_artifact's contract — only
    terminal-capable sinks fire the raw-serialiser arm."""
    src = (
        "def save(payload, path):\n"
        "    path.write_text(dumps_artifact(payload))\n"
        "    with open(path) as fh:\n"
        "        fh.write(dumps_artifact(payload))\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "raw_serialiser_at_sink"]


def test_sanitised_dumps_display_is_clean():
    src = (
        "def show(payload):\n"
        "    print(_sft(dumps_display(payload)))\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "raw_serialiser_at_sink"]


# ---------------------------------------------------------------------------
# Sanitiser name-shadow arm.
# ---------------------------------------------------------------------------


def test_rule_catches_sanitiser_name_shadow():
    """A same-named local helper that sanitises nothing satisfies the
    recognised-sanitiser vocabulary — registry review alone cannot
    hold that shut."""
    src = (
        "def _line(s):\n"
        "    return s\n"
        "\n"
        "def render(e, lines):\n"
        "    lines.append(_line(e['title']))\n"
    )
    vs = audit_source(src)
    assert any(v.kind == "sanitiser_shadow" and v.detail == "_line"
               for v in vs), vs


def test_chained_local_sanitiser_is_clean():
    """``_cell`` building on ``_line`` building on sanitise_string is
    the sanctioned helper-chain shape."""
    src = (
        "def _line(s):\n"
        "    return sanitise_string(str(s), max_chars=300)\n"
        "\n"
        "def _cell(s):\n"
        "    return _line(s).replace('|', '\\\\|')\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "sanitiser_shadow"]


def test_html_escape_based_helper_is_clean():
    src = (
        "import html\n"
        "def _cell(s):\n"
        "    return html.escape(str(s))\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "sanitiser_shadow"]


# ---------------------------------------------------------------------------
# Exception-text indirection arm.
# ---------------------------------------------------------------------------


def test_rule_catches_broad_exception_relay():
    """``except Exception as e: print(f"{e}")`` relays whatever the
    raising layer embedded; exception objects are outside the key
    model entirely."""
    src = (
        "def run(cmd):\n"
        "    try:\n"
        "        go(cmd)\n"
        "    except Exception as e:\n"
        "        print(f'failed: {e}')\n"
    )
    vs = audit_source(src)
    assert any(v.kind == "unsanitised_exception_text" and v.detail == "e"
               for v in vs), vs


def test_broad_exception_tuple_form_fires():
    src = (
        "def run(cmd):\n"
        "    try:\n"
        "        go(cmd)\n"
        "    except (ValueError, Exception) as exc:\n"
        "        sys.stderr.write(str(exc))\n"
    )
    assert any(v.kind == "unsanitised_exception_text"
               for v in audit_source(src))


def test_sanitised_exception_relay_is_clean():
    src = (
        "def run(cmd):\n"
        "    try:\n"
        "        go(cmd)\n"
        "    except Exception as e:\n"
        "        print(f'failed: {_sft(str(e), max_len=300)}')\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "unsanitised_exception_text"]


def test_narrow_exception_relay_is_documented_residual():
    """Narrow-typed handlers are OUT of the arm's scope by measured
    trade-off (the arm's docstring records the direction); this pin
    keeps the boundary deliberate."""
    src = (
        "def run(path):\n"
        "    try:\n"
        "        go(path)\n"
        "    except OSError as e:\n"
        "        print(f'failed: {e}')\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "unsanitised_exception_text"]


def test_type_name_of_exception_is_clean():
    src = (
        "def run(cmd):\n"
        "    try:\n"
        "        go(cmd)\n"
        "    except Exception as e:\n"
        "        print(f'failed: {type(e).__name__}')\n"
    )
    assert not [v for v in audit_source(src)
                if v.kind == "unsanitised_exception_text"]


# ---------------------------------------------------------------------------
# Vocabulary widening (mechanism 1) + tiers.
# ---------------------------------------------------------------------------


def test_widened_names_fire_on_attribute_reads():
    """`s.reason` — the attribute-read shape that made three sca
    writers invisible (the name, not the attribute arm, was the gap)."""
    src = (
        "def render(s):\n"
        "    print(f'skipped: {s.reason}')\n"
    )
    assert any(v.detail == "reason" for v in audit_source(src))


def test_widened_names_fire_on_dict_reads():
    src = (
        "def render(f, lines):\n"
        "    lines.append(f\"note: {f['notes']} q: {f.get('question')}\")\n"
    )
    details = {v.detail for v in audit_source(src)}
    assert {"notes", "question"} <= details


def test_label_tier_fires_on_dict_read_not_attribute():
    """Label-ish names (id/status/path/model/...) match parsed-artifact
    DICT reads; attribute reads on them are a documented residual
    (``.path``/``.status`` on stdlib objects are everywhere)."""
    dict_read = (
        "def render(finding):\n"
        "    print(f\"{finding['vuln_type']}: {finding['id']}\")\n"
    )
    details = {v.detail for v in audit_source(dict_read)}
    assert {"vuln_type", "id"} <= details

    attr_read = (
        "def render(url):\n"
        "    print(f'{url.path} {url.version}')\n"
    )
    assert audit_source(attr_read) == []


def test_widened_name_local_var_at_sink_only():
    """Widened names cover DIRECT sink reads; their local-variable
    round-trip is the documented residual (core names keep full
    propagation — see the mechanism-5 fixture)."""
    direct = (
        "def render(f):\n"
        "    print(f['reason'])\n"
    )
    assert any(v.detail == "reason" for v in audit_source(direct))


def test_core_name_comprehension_round_trip_fires():
    """Mechanism-5 comprehension shape for core names: raw loop
    element from a vocabulary iterable fires; a sanitised element
    stays clean."""
    raw = (
        "def render(self, lines):\n"
        "    lines.extend(f'- {r}' for r in self.reasoning[:3])\n"
    )
    assert audit_source(raw), "raw comprehension element must fire"
    clean = (
        "def render(self, lines):\n"
        "    lines.extend(f'- {_line(r)}' for r in self.reasoning[:3])\n"
    )
    assert audit_source(clean) == []


def test_field_scoped_container_read_is_clean():
    """A non-vocabulary constant key read from a tainted container is
    clean (the taint was deposited under vocabulary keys); vocabulary
    keys and whole-container reads still fire."""
    scoped = (
        "def render(res):\n"
        "    res['error'] = res.get('error')\n"
        "    print(f\"{res['deps_scanned']} deps\")\n"
    )
    assert audit_source(scoped) == []
    whole = (
        "def render(res):\n"
        "    res['error'] = res.get('error')\n"
        "    print(res)\n"
    )
    assert any(v.detail == "res" for v in audit_source(whole))


def test_tool_output_raw_checksec_fires():
    src = (
        "def render(info):\n"
        "    print(info['raw_checksec'])\n"
    )
    assert any(v.detail == "raw_checksec" for v in audit_source(src))


def test_rule_catches_comprehension_filtered_join_at_print():
    """Release-matrix shape: names filtered out of a foreign container
    by comprehension, joined at a print — no vocabulary name at the
    sink."""
    src = (
        "def report(resp):\n"
        "    rows = []\n"
        "    for rel in resp:\n"
        "        rows.append((rel['title'], rel))\n"
        "    failed = [tag for tag, r in rows if not r.get('pass')]\n"
        "    print(f\"FAILURES: {', '.join(failed)}\")\n"
    )
    vs = audit_source(src)
    assert any(v.detail == "failed" for v in vs), vs


def test_default_true_json_dumps_is_clean_nonconstant_fires():
    """stdlib json.dumps defaults ensure_ascii=True — a bare
    ``json.dumps(x)`` at a terminal sink is safe; a non-constant
    ensure_ascii (could be False at runtime) still fires."""
    bare = (
        "def show(e):\n"
        "    import json\n"
        "    print(json.dumps(e['details']))\n"
    )
    assert audit_source(bare) == []
    nonconst = (
        "def show(e, flag):\n"
        "    import json\n"
        "    print(json.dumps(e['details'], ensure_ascii=flag))\n"
    )
    assert any(v.detail == "details" for v in audit_source(nonconst))


# ---------------------------------------------------------------------------
# Finding-schema vocabulary: message / snippet / vuln_name
# ---------------------------------------------------------------------------

def test_rule_catches_whole_value_message_append():
    """``lines.append(f.get("message"))`` — the whole-value append of a
    finding's free text into a joined markdown write. The accumulator
    sink model always saw this shape; the finding-schema field names
    were missing from the vocabulary, so the flow produced no
    violation at all."""
    src = (
        "def render(findings):\n"
        "    lines = []\n"
        "    for f in findings:\n"
        "        lines.append(f.get('message', ''))\n"
        "    return '\\n'.join(lines)\n"
    )
    assert any(v.detail == "message" for v in audit_source(src))


def test_rule_catches_snippet_between_fences():
    src = (
        "def render(f, lines):\n"
        "    lines.append('```')\n"
        "    lines.append(f.get('snippet', ''))\n"
        "    lines.append('```')\n"
    )
    assert any(v.detail == "snippet" for v in audit_source(src))


def test_rule_catches_vuln_name_in_heading():
    src = (
        "def render(meta, lines):\n"
        "    lines.append(f\"### {meta.get('vuln_name', '')}\")\n"
    )
    assert any(v.detail == "vuln_name" for v in audit_source(src))


def test_rule_passes_md_helper_wrapped_finding_fields():
    src = (
        "def render(f, lines):\n"
        "    lines.append(md_prose(f.get('message', '')))\n"
        "    lines.append(md_fence(f.get('snippet', '')))\n"
    )
    assert audit_source(src) == []


def test_rule_accepts_safe_for_render_helper():
    """core/threat_model's _safe_for_render chokepoint is a recognised
    sanitiser (it builds on escape_nonprintable, satisfying the
    name-shadow arm)."""
    src = (
        "def render(issue, lines):\n"
        "    lines.append(_safe_for_render(issue.get('message', '')))\n"
    )
    assert audit_source(src) == []


# ---------------------------------------------------------------------------
# defensive-return contracts: every scan entry point yields a LIST
# ---------------------------------------------------------------------------


def test_audit_source_returns_empty_list_on_syntax_error():
    # Callers iterate/extend the result unconditionally (audit_file,
    # the registry closure gate) — a None here crashes the whole gate
    # on the first unparseable file instead of skipping it.
    out = audit_source("def broken(:\n")
    assert out == []
    assert isinstance(out, list)


def test_audit_source_on_sanitiser_definition_module_returns_list():
    # The shadow arm exempts the modules that DEFINE the canonical
    # sanitisers; the exemption must yield an empty list, not None —
    # audit_source extends violations with it unconditionally.
    src = "def sanitise_string(s):\n    return s\n"
    out = audit_source(src, rel="core/security/log_sanitisation.py")
    assert out == []
    # The same definition outside the exempted modules IS a shadow.
    assert any(v.kind == "sanitiser_shadow" for v in audit_source(src))


# ---------------------------------------------------------------------------
# json.dumps ensure_ascii adjudication — the **kwargs smuggle arm
# ---------------------------------------------------------------------------


def test_dumps_with_kwargs_splat_is_not_blessed():
    # `json.dumps(x, **kw)` can smuggle ensure_ascii=False at runtime;
    # the ASCII-JSON exemption must refuse it so the naked read is
    # still reported.
    src = (
        "def w(f, kw):\n"
        "    print(json.dumps(f['title'], **kw))\n"
    )
    vs = audit_source(src)
    assert any(v.detail == "title" for v in vs)


def test_dumps_with_explicit_ensure_ascii_false_is_not_blessed():
    src = (
        "def w(f):\n"
        "    print(json.dumps(f['title'], ensure_ascii=False))\n"
    )
    assert any(v.detail == "title" for v in audit_source(src))


def test_dumps_with_ensure_ascii_true_is_blessed():
    src = (
        "def w(f):\n"
        "    print(json.dumps(f['title'], ensure_ascii=True))\n"
    )
    assert audit_source(src) == []


# ---------------------------------------------------------------------------
# sink argument extraction covers KEYWORD arguments on every sink form
# ---------------------------------------------------------------------------


def test_name_sink_keyword_argument_carries_taint():
    src = (
        "def w(f):\n"
        "    print('finding', desc=f['title'])\n"
    )
    assert any(v.detail == "title" for v in audit_source(src))


def test_report_constructor_keyword_argument_carries_taint():
    src = (
        "def w(f):\n"
        "    return ReportSection(body=f['title'])\n"
    )
    assert any(v.detail == "title" for v in audit_source(src))


def test_attribute_report_constructor_keyword_argument_carries_taint():
    src = (
        "def w(f, sections):\n"
        "    return sections.ReportSection(body=f['title'])\n"
    )
    assert any(v.detail == "title" for v in audit_source(src))


# ---------------------------------------------------------------------------
# terminal-capable sink classification — echo/secho attribute forms
# ---------------------------------------------------------------------------


def test_attribute_echo_is_terminal_capable_for_raw_serialisers():
    # typer.echo/click.echo reach the terminal exactly like print; a
    # dumps_display payload there is the C1-passthrough lane the
    # raw-serialiser arm exists for.
    src = (
        "def w(report):\n"
        "    typer.echo(dumps_display(report))\n"
    )
    vs = audit_source(src)
    assert any(v.kind == "raw_serialiser_at_sink"
               and v.detail == "dumps_display" for v in vs)


# ---------------------------------------------------------------------------
# tainted-return helpers are recognised on the WIDENED vocabulary
# ---------------------------------------------------------------------------


def test_helper_returning_widened_key_taints_its_callers():
    # "message" is a widened (sink/return tier) name, not a core taint
    # name — a helper returning it is a render_json-shape lane and its
    # call sites must light up at sinks.
    src = (
        "def render(f):\n"
        "    return f['message']\n"
        "def w(f, lines):\n"
        "    lines.append(render(f))\n"
    )
    assert any(v.detail == "render" for v in audit_source(src))


# ---------------------------------------------------------------------------
# annotated-assignment container stores taint the container base
# ---------------------------------------------------------------------------


def test_annassign_attribute_store_taints_receiver_base():
    # `rec.note: str = f["title"]` stores a foreign value INSIDE rec —
    # a later whole-object write of rec must not launder it. Annotated
    # spelling is the repo's standing practice for new writer code.
    src = (
        "def w(f, lines, rec):\n"
        "    rec.note: str = f['title']\n"
        "    lines.append(rec)\n"
    )
    assert any(v.detail == "rec" for v in audit_source(src))


def test_annassign_plain_rebind_still_clears_taint():
    # Two-direction guard: a sanitised annotated re-bind clears.
    src = (
        "def w(f, lines):\n"
        "    body: str = f['title']\n"
        "    body = sanitise_string(body)\n"
        "    lines.append(body)\n"
    )
    assert audit_source(src) == []


# ---------------------------------------------------------------------------
# exception-relay arm: keyword-carried exception text + attribution
# ---------------------------------------------------------------------------


def test_relay_scan_flags_keyword_carried_exception_text():
    src = (
        "def f():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        typer.secho(message=f'boom {e}')\n"
    )
    vs = audit_source(src)
    assert any(v.kind == "unsanitised_exception_text" for v in vs)


def test_relay_scan_default_parents_builds_attribution():
    # _exception_relay_scan's parents map defaults to None (direct
    # callers) and audit_source shares a prebuilt dict — both paths
    # must attribute the violation to its enclosing function.
    import ast as _ast

    from core.security.report_writer_audit import _exception_relay_scan

    src = (
        "def outer():\n"
        "    try:\n"
        "        pass\n"
        "    except Exception as e:\n"
        "        print(f'x {e}')\n"
    )
    vs = _exception_relay_scan(_ast.parse(src), "x.py")
    assert vs and vs[0].func_name == "outer"
    vs2 = [v for v in audit_source(src)
           if v.kind == "unsanitised_exception_text"]
    assert vs2 and vs2[0].func_name == "outer"


import core.security.report_writer_audit as rwa  # noqa: E402


class TestWrongSlotSanitiser:
    """Fence-lane sanitisers (md_fence / sanitise_code) in a heading,
    table-cell, or bold-label slot pass the flat sanitiser vocabulary
    while preserving newlines, line-leading '#', and live links —
    structure forgery through a 'sanitised' interpolation."""

    def test_md_fence_in_heading_slot_flagged(self):
        src = 'lines.append(f"### {md_fence(f.get(\'title\'))}")'
        v = rwa.audit_source(src)
        assert [x.kind for x in v] == ["wrong_slot_sanitiser"]
        assert "md_fence in heading slot" in v[0].detail

    def test_sanitise_code_in_table_cell_flagged(self):
        v = rwa.audit_source('row = f"| {sanitise_code(x)} | ok |"')
        assert any(x.kind == "wrong_slot_sanitiser"
                   and "table-cell" in x.detail for x in v)

    def test_md_fence_in_bold_label_flagged(self):
        v = rwa.audit_source('s = f"**{md_fence(x)}**"')
        assert any(x.kind == "wrong_slot_sanitiser"
                   and "bold-label" in x.detail for x in v)

    def test_md_fence_inside_fence_not_flagged(self):
        v = rwa.audit_source('s = f"```\\n{md_fence(x)}\\n```"')
        assert not any(x.kind == "wrong_slot_sanitiser" for x in v)

    def test_md_inline_in_heading_slot_not_flagged(self):
        v = rwa.audit_source('s = f"### {md_inline(x)}"')
        assert not any(x.kind == "wrong_slot_sanitiser" for x in v)

    def test_md_fence_mid_prose_not_flagged(self):
        v = rwa.audit_source('s = f"see {md_fence(x)} above"')
        assert not any(x.kind == "wrong_slot_sanitiser" for x in v)

    def test_interpolation_resets_prefix(self):
        # A prior interpolation makes the line prefix non-constant;
        # only judge against text the scan can see.
        v = rwa.audit_source('s = f"{a} {md_fence(x)}"')
        assert not any(x.kind == "wrong_slot_sanitiser" for x in v)

    def test_allowlistable(self):
        src = 'lines.append(f"### {md_fence(x)}")'
        v = rwa.audit_source(src)
        entry = rwa.AllowlistEntry(
            file="<snippet>", func_name="<module>",
            kind="wrong_slot_sanitiser",
            detail="md_fence in heading slot",
            audit_note="test entry",
        )
        assert rwa.filter_allowlisted(v, (entry,)) == []


class TestShadowScanSelfReference:
    """The Attribute branch's self-reference exclusion was dead
    (`n is node` compared an Attribute to a FunctionDef — always
    False), so a shadowing method whose ONLY 'canonical' reference is
    its own recursive self-call passed the name-shadow arm."""

    def test_self_recursive_shadow_flagged(self):
        src = (
            "class W:\n"
            "    def sanitise_string(self, s, depth=0):\n"
            "        if depth:\n"
            "            return self.sanitise_string(s, 0)\n"
            "        return s\n"
        )
        v = rwa.audit_source(src)
        assert any(x.kind == "sanitiser_shadow" for x in v) or any(
            "shadow" in x.kind for x in v), [x.kind for x in v]

    def test_module_qualified_reference_passes(self):
        src = (
            "import core.security.prompt_output_sanitise as pos\n"
            "def sanitise_string(s):\n"
            "    return pos.sanitise_string(s)\n"
        )
        v = rwa.audit_source(src)
        assert not any("shadow" in x.kind for x in v), [x.kind for x in v]


def test_rule_catches_severity_dict_read_at_sink():
    """severity is a finding-derived display field — the SCA table
    lane rendered it raw while the vocabulary had no such name, so
    the lane produced nothing to baseline."""
    src = (
        "def render(f, rows):\n"
        "    rows.append(f\"{f.get('severity')}\")\n"
        "    print(f['severity'])\n"
    )
    vs = audit_source(src)
    assert sum(1 for v in vs if v.detail == "severity") == 2


def test_rule_catches_label_read_at_sink():
    """label is the diff view's rendered display string (built raw for
    the JSON payload) — a print of it must fire."""
    src = (
        "def show(c):\n"
        "    print(f\"~ {c['label']}\")\n"
    )
    assert any(v.detail == "label" for v in audit_source(src))


def test_rule_passes_sanitised_severity_and_label():
    # Two-direction guard for the widened names.
    src = (
        "def render(f, c, rows):\n"
        "    rows.append(sanitise_for_terminal(str(f.get('severity'))))\n"
        "    print(sanitise_for_terminal(str(c['label'])))\n"
    )
    assert audit_source(src) == []


def test_rule_accepts_clip_str_helper():
    """core/threat_model's _clip_str ingest-boundary clip builds on
    escape_nonprintable — recognised, so the module's summary-builder
    lanes read clean when every field routes through it."""
    src = (
        "def summarise(entry, out):\n"
        "    out.append(f\"{_clip_str(entry.get('severity'))}\")\n"
    )
    assert audit_source(src) == []


def test_render_lane_writer_files_registered():
    """The volatile-banner and threat-model renderer files print
    attacker-influenced text — they must stay under audit (a hit
    fails CI instead of landing in the unregistered baseline)."""
    from core.security.report_writer_audit import _REPORT_WRITER_FILES
    for rel in ("core/run/output.py", "core/threat_model/__init__.py"):
        assert rel in _REPORT_WRITER_FILES


# ---------------------------------------------------------------------------
# schema-derived display-key tier
# ---------------------------------------------------------------------------


def test_schema_derived_key_read_fires_at_sink():
    """A finding field named by a tree schema but by NO hand tier
    (ecosystem: the SCA row's OSV ecosystem string) must fire on a
    keyed read at a sink — a planted print(f['ecosystem']) in a
    registered writer previously escaped both the gate and the render
    regression file because the hand-curated tiers never named it."""
    src = (
        "def show(f):\n"
        "    print(f['ecosystem'])\n"
        "    print(f.get('ecosystem', ''))\n"
    )
    vs = [v for v in audit_source(src) if v.detail == "ecosystem"]
    assert len(vs) == 2


def test_schema_derived_tier_passes_sanitised_read():
    # Two-direction guard for the derived tier.
    src = (
        "def show(f):\n"
        "    print(sanitise_for_terminal(str(f['ecosystem'])))\n"
    )
    assert audit_source(src) == []


def test_schema_key_derivation_nonvacuous_per_source():
    """Every schema source must contribute its sentinel field names —
    a restructured source that silently stopped yielding keys would
    re-open the below-vocabulary blind spot this tier closes."""
    from core.security.report_writer_audit import _SCHEMA_KEYS

    # packages/sca/findings.py (row envelope + sca blocks)
    assert {"ecosystem", "purl", "fixed_version"} <= _SCHEMA_KEYS
    # core/run/orchestrated_report_schema.py (_FINDING_SCHEMA)
    assert {"skip_reason", "cc_debug_file"} <= _SCHEMA_KEYS
    # core/dataflow/finding.py (_FINDING_KEYS / _STEP_KEYS)
    assert {"producer", "intermediate_steps"} <= _SCHEMA_KEYS


def test_schema_key_derivation_failure_doctrine(tmp_path):
    """MISSING sources are skipped (the closure gate audits scratch
    trees carrying their own module copy, which may lack the schema
    sources), but a PRESENT source that parses and yields no keys
    raises — an empty derivation is a blind gate, not a clean one.
    Renames in the real repo are pinned by the non-vacuity sentinels
    above."""
    from core.security.report_writer_audit import (
        _SCHEMA_KEY_SOURCES,
        _derive_schema_keys,
    )

    assert _derive_schema_keys(root=tmp_path) == frozenset()

    for rel, _extract in _SCHEMA_KEY_SOURCES:
        stub = tmp_path / rel
        stub.parent.mkdir(parents=True, exist_ok=True)
        stub.write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="yielded no keys"):
        _derive_schema_keys(root=tmp_path)
