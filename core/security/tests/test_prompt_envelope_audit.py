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
            f"AllowlistEntry for {entry.file}:{entry.line} attr="
            f"{entry.attr!r} has empty audit_note — please explain "
            "why this site is safe so future reviewers can verify."
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


def test_filter_allowlisted_drops_matching_entries(tmp_path):
    """Allowlist matches on (file, line, attr) triple."""
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
    # Use the actual file/line for the allowlist
    only = vs[0]
    allow = (
        AllowlistEntry(
            file=only.file, line=only.line, attr=only.attr,
            audit_note="test",
        ),
    )
    remaining = filter_allowlisted(vs, allowlist=allow)
    assert remaining == []
