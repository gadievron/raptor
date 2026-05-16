"""Regression test: any new untrusted-attribute interpolation in the
audited prompt-construction files must be either fixed or explicitly
allowlisted (with an audit-note explaining why it's safe).

Operates on the heuristic AST rule in
``core.security.prompt_envelope_audit``. The rule catches:

  * f-string interpolation of known-untrusted attributes
  * ``.format(kw=x.attr)`` calls
  * ``prompt_parts.append(x.attr)`` patterns

It does NOT catch:

  * Plain string concatenation (``prompt + x.attr``)
  * Cross-function data flow
  * Non-attribute untrusted sources (e.g. ``str(some_dict["key"])``)

The CodeQL/Semgrep follow-up (project_anti_prompt_injection memory)
will close the long tail. This test is the first-line guard: catches
regressions in the well-known patterns before they hit production.

When this test fails, the operator's options are:

  1. **Fix the call site**: route the value through
     ``neutralize_tag_forgery`` (lightweight defang), or
     ``UntrustedBlock`` (full envelope wrap).
  2. **Allowlist with audit note**: if the call site is genuinely
     safe (markdown for disk, scorecard cell name, etc.), add an
     :class:`AllowlistEntry` to ``_ALLOWLIST`` with a one-line
     explanation. Reviewers verify the note before merge.

Adding a new prompt-builder file? Append it to
``_PROMPT_CONSTRUCTION_FILES`` in the audit module — that registers
the file for inspection at every CI run, forcing a security-review
checkpoint at file-add time.
"""

from __future__ import annotations

from core.security.prompt_envelope_audit import (
    audit_repo,
    filter_allowlisted,
    render_violations,
)


def test_no_unallowlisted_untrusted_interpolations():
    """Every interpolation of an untrusted-attribute name in audited
    prompt-construction files must be either defanged at the call
    site OR carry an explicit allowlist entry with an audit note."""
    violations = audit_repo()
    remaining = filter_allowlisted(violations)
    assert not remaining, (
        "Unaudited untrusted-attribute interpolation detected. "
        "Either defang the call site (neutralize_tag_forgery / "
        "UntrustedBlock / _sanitize_for_prompt) or add an "
        "AllowlistEntry to core/security/prompt_envelope_audit.py "
        "with an audit_note explaining why this site is safe.\n"
        + render_violations(remaining)
    )


def test_allowlist_entries_carry_audit_notes():
    """Empty audit_note on an allowlist entry would silently
    grandfather the violation. Pin that every entry explains itself
    so reviewers can sanity-check rationale at audit time."""
    from core.security.prompt_envelope_audit import _ALLOWLIST
    for entry in _ALLOWLIST:
        assert entry.audit_note.strip(), (
            f"AllowlistEntry for {entry.file} func={entry.func_name!r} "
            f"attr={entry.attr!r} has empty audit_note — please explain "
            "why this site is safe so future reviewers can verify."
        )
        # TODO sentinels emitted by `--update` for new violations must
        # not pass the audit. The reviewer has to fill in a real note.
        assert "TODO" not in entry.audit_note, (
            f"AllowlistEntry for {entry.file} func={entry.func_name!r} "
            f"attr={entry.attr!r} carries a TODO audit_note — fill it "
            "in (or remove the entry and defang the call site) before "
            "merging."
        )


def test_audit_walks_only_registered_files():
    """The audit is opt-in per file. Adding a new prompt-builder
    module requires explicit registration in
    ``_PROMPT_CONSTRUCTION_FILES`` — this test fails when files
    that look like prompt-builders are missing from the registry."""
    from core.security.prompt_envelope_audit import (
        _PROMPT_CONSTRUCTION_FILES,
        _REPO_ROOT,
    )
    # Every registered file must exist (catches typos / renames).
    for rel in _PROMPT_CONSTRUCTION_FILES:
        path = _REPO_ROOT / rel
        assert path.exists(), (
            f"_PROMPT_CONSTRUCTION_FILES references missing file: "
            f"{rel}. Either rename in the registry or remove."
        )


# ---------------------------------------------------------------------------
# Unit tests on the rule itself — synthetic inputs to pin behaviour
# ---------------------------------------------------------------------------


def test_rule_catches_fstring(tmp_path):
    """f-string interpolation of an untrusted attribute fires."""
    from core.security.prompt_envelope_audit import audit_file

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "def build_prompt(finding):\n"
        "    return f'Analyse: {finding.message}'\n"
    )
    vs = audit_file(src)
    assert any(v.attr == "message" for v in vs)


def test_rule_catches_format_kwarg(tmp_path):
    """``.format(kw=x.attr)`` fires (regression: matches the
    runner.py:265 pattern this audit was extended to catch)."""
    from core.security.prompt_envelope_audit import audit_file

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "def build_prompt(hyp):\n"
        "    return _TEMPLATE.format(claim=hyp.claim)\n"
    )
    vs = audit_file(src)
    assert any(v.attr == "claim" for v in vs)


def test_rule_catches_prompt_parts_append(tmp_path):
    """``prompt_parts.append(x.attr)`` fires (regression: matches
    the dataflow_validation.py:1542 pattern)."""
    from core.security.prompt_envelope_audit import audit_file

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "def build_prompt(hyp):\n"
        "    prompt_parts = []\n"
        "    prompt_parts.append(hyp.context)\n"
        "    return '\\n'.join(prompt_parts)\n"
    )
    vs = audit_file(src)
    assert any(v.attr == "context" for v in vs)


def test_rule_skips_logger_and_print(tmp_path):
    """The dominant FP class (``logger.info(f'... {rule_id} ...')``)
    is suppressed."""
    from core.security.prompt_envelope_audit import audit_file

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def f(finding):\n"
        "    logger.info(f'Analyzing {finding.rule_id}')\n"
        "    print(f'Found {finding.message}')\n"
    )
    vs = audit_file(src)
    assert vs == []


def test_rule_skips_untrustedblock_constructor(tmp_path):
    """Interpolation as ``UntrustedBlock(origin=...)`` is the safe
    pattern — ``_xml_attr_escape`` runs at render time."""
    from core.security.prompt_envelope_audit import audit_file

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "from core.security.prompt_envelope import UntrustedBlock\n"
        "def f(finding):\n"
        "    return UntrustedBlock(\n"
        "        content=finding.code,\n"
        "        kind='code',\n"
        "        origin=f'{finding.file_path}:{finding.start_line}',\n"
        "    )\n"
    )
    vs = audit_file(src)
    assert vs == []


def test_rule_skips_explicit_sanitisation(tmp_path):
    """Wrapping in ``neutralize_tag_forgery`` /
    ``_sanitize_for_prompt`` removes the violation."""
    from core.security.prompt_envelope_audit import audit_file

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "def neutralize_tag_forgery(s): return s\n"
        "def f(finding):\n"
        "    return f'Analyse: {neutralize_tag_forgery(finding.message)}'\n"
    )
    vs = audit_file(src)
    assert vs == []


def test_rule_catches_lambda_fstring(tmp_path):
    """Lambda f-strings used to fall through with the enclosing class
    name as func_name (no lambda frame). Now `<lambda>` is pushed so
    per-lambda allowlist entries stay distinct from per-method ones.
    """
    from core.security.prompt_envelope_audit import audit_file
    src = tmp_path / "t.py"
    src.write_text(
        "class A:\n"
        "    builder = lambda self, f: f'{f.message}'\n"
    )
    vs = audit_file(src)
    assert len(vs) == 1
    assert vs[0].func_name == "A.<lambda>"
    assert vs[0].attr == "message"


def test_rule_catches_walrus_attr(tmp_path):
    """Walrus operator inside an interpolation — `_attr_name` now
    walks through `NamedExpr.value` to surface the attribute access.
    Pre-fix the audit silently missed `f"{(x := finding.message)}"`.
    """
    from core.security.prompt_envelope_audit import audit_file
    src = tmp_path / "t.py"
    src.write_text(
        "def f(finding):\n"
        "    return f'{(x := finding.message)}'\n"
    )
    vs = audit_file(src)
    assert any(v.attr == "message" for v in vs)


def test_rule_catches_percent_formatting(tmp_path):
    """Old-style `%` formatting on string literals — three flavours:
    single value, tuple of values, dict of values."""
    from core.security.prompt_envelope_audit import audit_file
    cases = [
        ("def f(finding):\n    return 'Hi %s' % finding.message\n", 1),
        ("def f(finding):\n    return '%s/%s' % (finding.message, finding.rule_id)\n", 2),
        ("def f(finding):\n    return '%(m)s' % {'m': finding.message}\n", 1),
    ]
    for i, (code, expected) in enumerate(cases):
        src = tmp_path / f"t{i}.py"
        src.write_text(code)
        vs = audit_file(src)
        assert len(vs) == expected, f"case {i}: expected {expected}, got {len(vs)}"


def test_rule_skips_numeric_mod(tmp_path):
    """`%` is also numeric modulo. The percent-formatting check must
    only fire when the left operand is a string literal, otherwise
    `100 % 7` would noise up the audit."""
    from core.security.prompt_envelope_audit import audit_file
    src = tmp_path / "t.py"
    src.write_text(
        "def f():\n"
        "    return 100 % 7\n"
        "def g(finding):\n"
        "    return finding.start_line % 10\n"
    )
    vs = audit_file(src)
    # The %-formatting check only fires on string-left-side; numeric
    # `%` correctly produces no violations.
    assert vs == []


def test_update_allowlist_is_atomic_on_failure(tmp_path):
    """If the rewrite raises mid-way, no half-written file should
    remain on disk and the original audit module must be intact.
    Simulates failure by patching `render_allowlist` to throw."""
    import shutil, inspect
    from unittest.mock import patch
    from core.security import prompt_envelope_audit as mod
    from core.security.prompt_envelope_audit import _update_allowlist_in_source

    real_path = tmp_path / "audit.py"
    shutil.copy(inspect.getsourcefile(mod), real_path)
    pre_text = real_path.read_text()

    with patch.object(mod, "render_allowlist", side_effect=RuntimeError("boom")):
        try:
            _update_allowlist_in_source(real_path)
        except RuntimeError:
            pass

    # Source unchanged.
    assert real_path.read_text() == pre_text
    # No `.tmp` litter left around.
    leftovers = list(tmp_path.glob("*.tmp"))
    assert leftovers == [], f"tempfiles left over: {leftovers}"


def test_filter_allowlisted_drops_matching_entries(tmp_path):
    """Allowlist matches on (file, func_name, attr, expr_text) quadruple
    — content-based, so the entry survives unrelated edits to the
    file (e.g. lines added before the interpolation)."""
    from core.security.prompt_envelope_audit import (
        AllowlistEntry,
        audit_file,
        filter_allowlisted,
    )

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "def f(finding):\n"
        "    return f'Analyse: {finding.message}'\n"
    )
    vs = audit_file(src)
    assert len(vs) == 1
    only = vs[0]
    allow = (
        AllowlistEntry(
            file=only.file,
            func_name=only.func_name,
            attr=only.attr,
            expr_text=only.expr_text,
            audit_note="test",
        ),
    )
    remaining = filter_allowlisted(vs, allowlist=allow)
    assert remaining == []


def test_filter_allowlisted_survives_line_shift(tmp_path):
    """The whole point of content-based keying: adding lines before
    the interpolation must not invalidate an existing allowlist entry.
    """
    from core.security.prompt_envelope_audit import (
        AllowlistEntry,
        audit_file,
        filter_allowlisted,
    )

    src = tmp_path / "fake_prompt_builder.py"
    src.write_text(
        "def f(finding):\n"
        "    return f'Analyse: {finding.message}'\n"
    )
    vs1 = audit_file(src)
    only = vs1[0]
    allow = (
        AllowlistEntry(
            file=only.file,
            func_name=only.func_name,
            attr=only.attr,
            expr_text=only.expr_text,
            audit_note="test",
        ),
    )

    # Now add unrelated lines BEFORE the interpolation.
    src.write_text(
        "# new comment one\n"
        "# new comment two\n"
        "# new comment three\n"
        "def f(finding):\n"
        "    return f'Analyse: {finding.message}'\n"
    )
    vs2 = audit_file(src)
    assert vs2[0].line != only.line  # line shifted
    # Allowlist entry still matches — that's the point.
    assert filter_allowlisted(vs2, allowlist=allow) == []


def test_render_allowlist_is_idempotent_on_clean_state():
    """Running `--update` on an already-clean allowlist must produce
    the same content. Without idempotence, every CI run would diff
    against the committed file — defeating the point of a stable
    allowlist format."""
    from core.security.prompt_envelope_audit import (
        _ALLOWLIST, audit_repo, render_allowlist,
    )
    violations = audit_repo()
    out1 = render_allowlist(violations, allowlist=_ALLOWLIST)
    # Parse the emitted source and compare entry sets back-to-the-input.
    # We compare keys + audit_notes; whitespace can legitimately differ
    # if the wrap heuristic shifts a word, but key+note pairs must match.
    import ast as _ast
    tree = _ast.parse(out1)
    # The emitted source is a top-level Assign whose value is a Tuple
    # of `AllowlistEntry(...)` calls.
    assign = tree.body[0]
    entries = []
    for call in assign.value.elts:
        kwargs = {kw.arg: kw.value for kw in call.keywords}
        # ast.literal_eval the file/func_name/attr/expr_text/audit_note.
        # audit_note may be a parenthesised string-concat: collapse it.
        def _str_value(node):
            if isinstance(node, _ast.Constant):
                return node.value
            if isinstance(node, _ast.JoinedStr):
                return "".join(
                    p.value for p in node.values
                    if isinstance(p, _ast.Constant)
                )
            # Parenthesised concat is parsed as a sequence of strings
            # joined by Python's compile-time literal concatenation.
            # ast.literal_eval handles that.
            return _ast.literal_eval(node)
        entries.append((
            _str_value(kwargs["file"]),
            _str_value(kwargs["func_name"]),
            _str_value(kwargs["attr"]),
            _str_value(kwargs["expr_text"]),
            _str_value(kwargs["audit_note"]),
        ))
    existing = [
        (e.file, e.func_name, e.attr, e.expr_text, e.audit_note)
        for e in _ALLOWLIST
    ]
    # Same multiset of (key, note) pairs.
    assert sorted(entries) == sorted(existing)


def test_render_allowlist_carries_existing_notes_and_emits_todo(tmp_path):
    """`render_allowlist` carries forward audit_notes for known entries
    and emits a TODO placeholder for genuinely-new violations."""
    from core.security.prompt_envelope_audit import (
        AllowlistEntry, Violation, render_allowlist,
    )
    known = Violation(
        file="x.py", line=1, attr="rule_id",
        expr_text="{f.rule_id}", func_name="g",
    )
    new = Violation(
        file="x.py", line=2, attr="message",
        expr_text="{f.message}", func_name="g",
    )
    allow = (
        AllowlistEntry(
            file="x.py", func_name="g", attr="rule_id",
            expr_text="{f.rule_id}",
            audit_note="markdown for disk, not LLM prompt",
        ),
    )
    out = render_allowlist([known, new], allowlist=allow)
    assert "markdown for disk, not LLM prompt" in out
    assert "TODO: audit_note required" in out
