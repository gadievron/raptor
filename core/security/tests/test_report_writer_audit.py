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
