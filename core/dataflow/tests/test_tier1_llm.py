"""Tests for the Tier 1B LLM-assisted sanitizer characterization.

LLM is mocked via a callable that returns canned JSON, so tests are
deterministic.  Real-LLM end-to-end coverage is corpus-level, not
unit-level.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.dataflow import tier1_llm as t1


def _fake_complete(reply: str):
    """Return a (system_prompt, user_prompt) -> str completer that
    always returns ``reply``."""
    def complete(_sys, _user):
        return reply
    return complete


# ---------------------------------------------------------------------------
# JSON parsing tolerance
# ---------------------------------------------------------------------------

def test_parse_strict_json():
    spec = t1._parse_llm_output('{"kind":"other","validator_source_line":"",'
                                 '"variable_name":"","charset":"",'
                                 '"forbidden":"","library_call":""}')
    assert spec is not None and spec.kind == "other"


def test_parse_strips_markdown_fence():
    spec = t1._parse_llm_output(
        '```json\n{"kind":"other","validator_source_line":"x",'
        '"variable_name":"","charset":"","forbidden":"",'
        '"library_call":""}\n```'
    )
    assert spec is not None and spec.kind == "other"


def test_parse_returns_none_on_garbage():
    assert t1._parse_llm_output("not json") is None
    assert t1._parse_llm_output("") is None
    assert t1._parse_llm_output("[1,2,3]") is None      # not a dict


# ---------------------------------------------------------------------------
# Hallucination gates
# ---------------------------------------------------------------------------

def test_decline_when_llm_claims_line_not_in_diff(tmp_path: Path):
    """LLM names a validator line that doesn't appear in the diff —
    hallucination, must DECLINE."""
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line": "if not re.match(r'^[a-z]+$', x): return",
        "variable_name": "x",
        "charset": "a-z", "forbidden": "", "library_call": "",
    })
    # Diff doesn't contain that line
    diff = "+ unrelated line\n+ another unrelated line\n"
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "not found as a + line" in r.reasoning


def test_decline_on_unparseable_llm_output(tmp_path: Path):
    r = t1.try_tier1b(
        fix_diff="+something\n", repo_root=tmp_path,
        sink_uri="x.py", sink_line=1, sink_class="pathtrav",
        language="python", complete=_fake_complete("not json at all"),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "not parseable" in r.reasoning


def test_decline_when_llm_says_other(tmp_path: Path):
    reply = json.dumps({
        "kind": "other", "validator_source_line": "",
        "variable_name": "", "charset": "", "forbidden": "",
        "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff="+x = 1\n", repo_root=tmp_path,
        sink_uri="x.py", sink_line=1, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "'other'" in r.reasoning


# ---------------------------------------------------------------------------
# Mechanical re-extract cross-check
# ---------------------------------------------------------------------------

def test_decline_when_mechanical_recheck_disagrees_on_charset(tmp_path: Path):
    """LLM claims charset=[a-z] but the source line is actually [A-Z];
    the mechanical extractor's charset will be [A-Z], not [a-z] —
    disagreement -> DECLINE."""
    (tmp_path / "app.py").write_text(
        "def f(x):\n"
        '    if not re.match(r"^[A-Z]+$", x): return\n'
        "    open(x)\n"
    )
    diff = '+    if not re.match(r"^[A-Z]+$", x): return\n'
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line": 'if not re.match(r"^[A-Z]+$", x): return',
        "variable_name": "x",
        "charset": "a-z",      # WRONG — actual is A-Z
        "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=3, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "mechanical re-extract disagrees" in r.reasoning


# ---------------------------------------------------------------------------
# Whitespace symmetry: the mechanical recheck sees the same
# whitespace-normalized rendering of the LLM's claimed line as the
# anti-fabrication diff check
# ---------------------------------------------------------------------------

_RECHECK_LINE = "if not re.match(r'^[A-Za-z0-9_.+-]+$', name):"


def _charset_spec(line: str) -> t1._LLMSpec:
    return t1._LLMSpec(
        kind="charset",
        validator_source_line=line,
        variable_name="name",
        charset="A-Za-z0-9_.+-",
        forbidden="",
        library_call="",
    )


def test_recheck_accepts_indented_claim():
    mech = t1._mechanical_recheck_charset_kind(
        _charset_spec("    " + _RECHECK_LINE), "python")
    assert mech is not None
    assert mech.charset == "A-Za-z0-9_.+-"


def test_recheck_matches_diff_check_normalization():
    # The diff carries the line indented; the LLM echoes it without
    # indentation. The anti-fabrication check accepts it, and the
    # recheck must reach the same verdict for both renderings.
    fix_diff = "+    " + _RECHECK_LINE + "\n"
    for claimed in (_RECHECK_LINE, "  " + _RECHECK_LINE, "\t" + _RECHECK_LINE + "  "):
        assert t1._validator_line_in_diff(fix_diff, claimed)
        mech = t1._mechanical_recheck_charset_kind(
            _charset_spec(claimed), "python")
        assert mech is not None
        assert mech.kind == "charset"
        assert mech.charset == "A-Za-z0-9_.+-"
        # source_line stored from the normalized rendering.
        assert mech.source_line == _RECHECK_LINE


def test_whitespace_only_claim_rejected_everywhere():
    assert not t1._validator_line_in_diff("+   \n", "   ")
    assert t1._mechanical_recheck_charset_kind(
        _charset_spec("   "), "python") is None


# ---------------------------------------------------------------------------
# Curated-table dispatch (known_safe_call)
# ---------------------------------------------------------------------------

def test_sound_via_known_safe_call_table(tmp_path: Path):
    """werkzeug.security.safe_join — in the curated table — assigned
    to abs_path which then reaches the sink.  Tier 1B SOUND."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"        # line 1
        "def f(path):\n"                                    # line 2
        "    abs_path = safe_join(BASE, path)\n"            # line 3 — safe call
        "    return open(abs_path)\n"                       # line 4 = sink
    )
    diff = (
        "+from werkzeug.security import safe_join\n"
        "+    abs_path = safe_join(BASE, path)\n"
    )
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND
    assert "werkzeug.security.safe_join" in r.artifact
    assert r.artifact.startswith("library:")


def test_known_safe_call_refuses_on_unparseable_python(tmp_path: Path):
    """One syntax error anywhere in a Python file must REFUSE the
    known-safe-call certification, not silently drop every dominance
    gate. Pre-fix ``tree = None`` fell through and this branch-wrapped
    safe call (live flow when the branch is skipped) certified SOUND
    with the same-function, binding-target, and branch gates all
    conditioned away — a plantable false-suppression primitive."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"        # line 1
        "def f(path, flag):\n"                              # line 2
        "    if flag:\n"                                    # line 3
        "        abs_path = safe_join(BASE, path)\n"        # line 4
        "    return open(abs_path)\n"                       # line 5 = sink
        "def broken(:\n"                                    # line 6 — SyntaxError
    )
    diff = "+        abs_path = safe_join(BASE, path)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "syntax errors" in r.reasoning


def test_decline_when_library_not_in_curated_table(tmp_path: Path):
    """LLM claims a library is safe but it's not in the curated table
    — DECLINE.  This is the trust-surface gate."""
    (tmp_path / "app.py").write_text(
        "def f(x):\n"
        "    safe = some_random_helper(x)\n"
        "    return open(safe)\n"
    )
    diff = "+    safe = some_random_helper(x)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe = some_random_helper(x)",
        "variable_name": "safe", "charset": "", "forbidden": "",
        "library_call": "some_random_helper",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=3, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "not in curated known-safe table" in r.reasoning


def test_decline_when_known_safe_var_doesnt_reach_sink(tmp_path: Path):
    """``safe_join`` was called and assigned to ``a``, but the sink
    uses an unrelated variable ``b`` — variable mismatch → DECLINE."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(path):\n"
        "    a = safe_join(BASE, path)\n"
        "    b = req()\n"
        "    return open(b)\n"                              # sink uses b, not a
    )
    diff = "+    a = safe_join(BASE, path)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "a = safe_join(BASE, path)",
        "variable_name": "a", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "does not reach the sink" in r.reasoning


def test_find_best_validator_line_picks_same_function_match(tmp_path: Path):
    """Regression: when the LLM-named line appears multiple times across
    different functions, pick the one in the same function as the sink.
    Pre-fix this took the first occurrence (often in an unrelated helper)
    and falsely failed the dominance check."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"                     # line 1
        "def other_handler(path):\n"                                    # line 2
        "    abs_path = safe_join(BASE, path)\n"                        # line 3 — first occurrence
        "    return open(abs_path).read()\n"                            # line 4
        "def main_handler(path):\n"                                     # line 5
        "    abs_path = safe_join(BASE, path)\n"                        # line 6 — second occurrence
        "    return open(abs_path)\n"                                   # line 7 = sink
    )
    diff = "+    abs_path = safe_join(BASE, path)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND, r.reasoning
    # Validator picked from line 6 (same function as sink), not line 3
    assert r.extras.get("validator_line") == 6


def test_find_best_validator_line_returns_none_when_all_after_sink(tmp_path: Path):
    """All occurrences appear AFTER the sink — no usable validator."""
    (tmp_path / "app.py").write_text(
        "def f(path):\n"
        "    return open(path)\n"                                       # line 2 = sink
        "def g(path):\n"
        "    abs_path = safe_join(BASE, path)\n"                        # line 4 — after sink
        "    return abs_path\n"
    )
    diff = "+    abs_path = safe_join(BASE, path)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=2, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "no occurrence" in r.reasoning


def test_sound_via_charset_with_llm_pointing_at_line(tmp_path: Path):
    """LLM correctly identifies a charset validator on a line that
    Tier 0's mechanical extractor wouldn't have parsed as a guard-
    and-exit (different shape) — but mechanical re-extract agrees on
    the kind+charset, and the existing Z3 path produces SOUND."""
    (tmp_path / "app.py").write_text(
        "def f(name):\n"
        '    if not re.match(r"^[A-Za-z0-9_+-]+$", name):\n'
        "        return error()\n"
        "    return open(name)\n"
    )
    diff = '+    if not re.match(r"^[A-Za-z0-9_+-]+$", name):\n'
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line": 'if not re.match(r"^[A-Za-z0-9_+-]+$", name):',
        "variable_name": "name",
        "charset": "A-Za-z0-9_+-",
        "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND
    # Charset path produces the same artifact prefix as Tier 0 mechanical
    # extraction — the proof mechanism is identical (Z3).
    assert r.artifact.startswith("smt:charset")
    # The extras flag records that the LLM was involved in extraction,
    # for audit / scorecard purposes (proof itself is mechanical).
    assert r.extras.get("llm_extracted") is True


# ---------------------------------------------------------------------------
# Regression: dominance check between chain_ok and SOUND return
# ---------------------------------------------------------------------------

def test_not_applicable_when_validator_does_not_dominate_sink(tmp_path: Path):
    """When the validator is inside an if-branch that doesn't always
    execute (e.g., guarded by an unrelated condition), it does NOT
    dominate the sink. The result must be NOT_APPLICABLE, not SOUND.

    Pre-fix: no dominance check was performed between the chain_ok
    confirmation and the SOUND return — any validator that textually
    appeared before the sink and whose variable reached the sink was
    declared SOUND, even when the validator only ran conditionally."""
    # The validator (safe_join) is inside an if-branch that doesn't
    # always execute; the sink at line 6 is reachable without passing
    # through the validator.
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"       # line 1
        "def f(path, flag):\n"                             # line 2
        "    if flag:\n"                                   # line 3
        "        abs_path = safe_join(BASE, path)\n"       # line 4 — conditional
        "    else:\n"                                       # line 5
        "        abs_path = path\n"                        # line 6 — unsanitized
        "    return open(abs_path)\n"                       # line 7 = sink
    )
    diff = "+        abs_path = safe_join(BASE, path)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    # The validator at line 4 is inside a branch — it doesn't dominate
    # line 7. Must NOT be SOUND.
    assert r.status is t1.Tier0Status.NOT_APPLICABLE, (
        f"expected NOT_APPLICABLE but got {r.status}: {r.reasoning}"
    )


# ---------------------------------------------------------------------------
# Claimed-call-on-claimed-line gate (hallucinated sanitizer)
# ---------------------------------------------------------------------------

def test_decline_when_claimed_call_not_on_claimed_line(tmp_path: Path):
    """The LLM points at a REAL diff line (an unrelated log
    assignment) and claims it is shlex.quote applied to the sink
    variable.  All previous gates passed — the line exists, the sink
    variable appears at the sink — so the curated-table verdict was
    stamped SOUND for a call that never happens.  Must DECLINE."""
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text(
        "import subprocess\n"
        "def run(request):\n"
        "    cmd = request.args.get(\"cmd\")\n"
        "    audit_log = \"invoked\"\n"
        "    subprocess.call(cmd + \" --safe\", shell=True)\n"
    )
    diff = (
        "--- a/app/views.py\n"
        "+++ b/app/views.py\n"
        "@@\n"
        "     cmd = request.args.get(\"cmd\")\n"
        "+    audit_log = \"invoked\"\n"
        "     subprocess.call(cmd + \" --safe\", shell=True)\n"
    )
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "    audit_log = \"invoked\"",
        "variable_name": "cmd",
        "charset": "", "forbidden": "",
        "library_call": "shlex.quote",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app/views.py", sink_line=5, sink_class="cmdi",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is not t1.Tier0Status.SOUND
    assert "does not appear on the claimed source line" in r.reasoning


def test_line_invokes_library_call_accepts_real_shapes():
    fn = t1._line_invokes_library_call
    assert fn("    cmd = shlex.quote(cmd)", "shlex.quote", "cmd")
    assert fn("    safe = quote(cmd)", "shlex.quote", "cmd")
    assert fn("    abs_path = safe_join(BASE, path)",
              "werkzeug.security.safe_join", "abs_path")
    # Wrong module prefix on the line: not the claimed call.
    assert not fn("    cmd = pipes.quote(cmd)", "shlex.quote", "cmd")
    # Call absent entirely.
    assert not fn("    audit_log = \"invoked\"", "shlex.quote", "cmd")
    # Call present but neither applied to nor assigned from the var.
    assert not fn("    other = shlex.quote(x)", "shlex.quote", "cmd")


# ---------------------------------------------------------------------------
# Non-Python function-boundary gate (charset + known-safe-call paths)
# ---------------------------------------------------------------------------

def test_charset_declines_across_function_boundary_js(tmp_path: Path):
    """Validator in helper A, sink in helper B (same JS file): the
    Python path has AST dominance, but the non-Python path used only
    the var-at-sink-line regex — a cross-function 'validator' was
    stamped SOUND.  Must apply the same function-boundary gate
    try_tier0 uses."""
    (tmp_path / "app.js").write_text(
        "function validateOnly(name) {\n"                       # 1
        "    if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }\n"  # 2
        "}\n"                                                    # 3
        "function serve(name) {\n"                               # 4
        "    return fs.readFile(\"/data/\" + name);\n"           # 5
        "}\n"
    )
    diff = "+    if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }\n"
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line":
            "if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }",
        "variable_name": "name",
        "charset": "A-Za-z0-9_", "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=5, sink_class="pathtrav",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is not t1.Tier0Status.SOUND
    assert "function boundary" in r.reasoning


def test_known_safe_call_branch_wrapped_declines_js(tmp_path: Path):
    """A branch-wrapped sanitizer must never certify SOUND for a
    non-Python language: ``validator.escape`` is in the curated table,
    but the flow is live whenever ``opts.clean`` is false — the sound
    tier's zero-false-suppression guarantee requires unconditional
    execution."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res, opts) {\n"                    # 1
        "    let name = req.query.name;\n"                       # 2
        "    if (opts.clean) {\n"                                # 3
        "        name = validator.escape(name);\n"               # 4 — wrapped
        "    }\n"                                                # 5
        "    res.send('<b>' + name + '</b>');\n"                 # 6 — sink
        "}\n"
    )
    diff = "+        name = validator.escape(name);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "name = validator.escape(name);",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "validator.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=6, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "unconditionally" in r.reasoning


def test_known_safe_call_unconditional_still_sound_js(tmp_path: Path):
    """Two-direction: the same curated call executed unconditionally
    in the sink's function keeps its SOUND verdict."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res) {\n"                           # 1
        "    let name = req.query.name;\n"                        # 2
        "    name = validator.escape(name);\n"                    # 3 — safe call
        "    res.send('<b>' + name + '</b>');\n"                  # 4 — sink
        "}\n"
    )
    diff = "+    name = validator.escape(name);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "name = validator.escape(name);",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "validator.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_known_safe_call_braceless_multiline_if_declines_js(tmp_path: Path):
    """Java/JS-legal braceless MULTI-LINE if: the guard opens no block,
    so the brace tracker sees nothing and the same-line keyword check
    misses it — the dangling-guard check must catch the validator
    hanging off the previous line's `if (cond)`."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res, opts) {\n"                    # 1
        "    let y = req.query.name;\n"                           # 2
        "    if (opts.clean)\n"                                   # 3 — dangling guard
        "        y = validator.escape(y);\n"                      # 4 — guarded stmt
        "    res.send('<b>' + y + '</b>');\n"                     # 5 — sink
        "}\n"
    )
    diff = "+        y = validator.escape(y);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "y = validator.escape(y);",
        "variable_name": "y", "charset": "", "forbidden": "",
        "library_call": "validator.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=5, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "unconditionally" in r.reasoning


def test_known_safe_call_blank_line_before_sanitizer_still_sound_js(tmp_path: Path):
    """Two-direction for the dangling-guard check: an unconditional
    sanitizer whose nearest preceding NON-BLANK line is a plain
    statement (blank line skipped) must keep its SOUND verdict."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res) {\n"                           # 1
        "    let name = req.query.name;\n"                        # 2
        "\n"                                                      # 3 — blank
        "    name = validator.escape(name);\n"                    # 4 — safe call
        "    res.send('<b>' + name + '</b>');\n"                  # 5 — sink
        "}\n"
    )
    diff = "+    name = validator.escape(name);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "name = validator.escape(name);",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "validator.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=5, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_known_safe_call_branch_wrapped_declines_python_in_with(tmp_path: Path):
    """Python direction of the same gate: a conditional nested inside a
    ``with`` block (which the top-level-only scan skipped) must still
    read as branch-wrapped."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"              # 1
        "def f(path, opts):\n"                                    # 2
        "    abs_path = req()\n"                                  # 3
        "    with lock:\n"                                        # 4
        "        if opts.clean:\n"                                # 5
        "            abs_path = safe_join(BASE, path)\n"          # 6 — wrapped
        "    return open(abs_path)\n"                             # 7 — sink
    )
    diff = "+            abs_path = safe_join(BASE, path)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=7, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Post-fix source read containment
# ---------------------------------------------------------------------------

def test_sink_uri_escaping_repo_root_declined(tmp_path: Path):
    """A ``..`` sink_uri from a hostile/corrupted finding record must
    not walk the post-fix read outside repo_root — pre-fix Tier 1B
    read the out-of-root file and could mint a SOUND receipt against
    it.  Same containment as ``finding_resolver._read_finding_source``
    / ``injection_prescreen._read_source``."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    # Out-of-root file that WOULD adjudicate SOUND if it were read.
    (tmp_path / "outside_secret.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(path):\n"
        "    abs_path = safe_join(BASE, path)\n"
        "    return open(abs_path)\n"
    )
    diff = (
        "+from werkzeug.security import safe_join\n"
        "+    abs_path = safe_join(BASE, path)\n"
    )
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=repo_root,
        sink_uri="../outside_secret.py", sink_line=4,
        sink_class="pathtrav", language="python",
        complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "outside the repo root" in r.reasoning


def test_sink_uri_symlink_escape_declined(tmp_path: Path):
    """A symlink inside the repo pointing outside it must not defeat
    the containment check (resolve() collapses it)."""
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    (tmp_path / "outside_secret.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(path):\n"
        "    abs_path = safe_join(BASE, path)\n"
        "    return open(abs_path)\n"
    )
    (repo_root / "app.py").symlink_to(tmp_path / "outside_secret.py")
    diff = (
        "+from werkzeug.security import safe_join\n"
        "+    abs_path = safe_join(BASE, path)\n"
    )
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=repo_root,
        sink_uri="app.py", sink_line=4,
        sink_class="pathtrav", language="python",
        complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "outside the repo root" in r.reasoning


def test_sink_uri_inner_dotdot_resolving_inside_still_reads(tmp_path: Path):
    """A path with an inner ``..`` that still RESOLVES inside the repo
    root is legitimate (finding tools emit these) — containment must
    not reject it."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(path):\n"
        "    abs_path = safe_join(BASE, path)\n"
        "    return open(abs_path)\n"
    )
    diff = (
        "+from werkzeug.security import safe_join\n"
        "+    abs_path = safe_join(BASE, path)\n"
    )
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "abs_path = safe_join(BASE, path)",
        "variable_name": "abs_path",
        "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="sub/../app.py", sink_line=4,
        sink_class="pathtrav", language="python",
        complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_charset_branch_wrapped_declines_js(tmp_path: Path):
    """Tier 1B charset (guard) kind, non-Python: the guard-and-exit
    line sits inside an ``if (opts.strict) { ... }`` block that closes
    before the sink — the flow is live whenever the branch is skipped,
    so the same conditional-execution gate the known_safe_call kind
    carries must decline."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res, opts) {\n"                          # 1
        "    let name = req.query.name;\n"                             # 2
        "    if (opts.strict) {\n"                                     # 3
        "        if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }\n"     # 4 — wrapped guard
        "    }\n"                                                      # 5
        "    return fs.readFile('/data/' + name);\n"                   # 6 — sink
        "}\n"
    )
    diff = "+        if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }\n"
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line":
            "if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }",
        "variable_name": "name",
        "charset": "A-Za-z0-9_", "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=6, sink_class="pathtrav",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "unconditionally" in r.reasoning


def test_charset_unconditional_guard_still_sound_js(tmp_path: Path):
    """Two-direction: the same guard executed unconditionally in the
    sink's function keeps its SOUND verdict (the guard's own
    exit-on-fail block is not an enclosing conditional)."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res) {\n"                                 # 1
        "    let name = req.query.name;\n"                              # 2
        "    if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }\n"          # 3 — guard
        "    return fs.readFile('/data/' + name);\n"                    # 4 — sink
        "}\n"
    )
    diff = "+    if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }\n"
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line":
            "if (!/^[A-Za-z0-9_]+$/.test(name)) { return; }",
        "variable_name": "name",
        "charset": "A-Za-z0-9_", "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=4, sink_class="pathtrav",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_charset_branch_wrapped_declines_python_tier1b(tmp_path: Path):
    """Tier 1B charset kind, Python: dominance flows through
    validator_dominates_sink, which now carries the enclosing-
    conditional gate."""
    (tmp_path / "app.py").write_text(
        "def serve(request):\n"                                        # 1
        "    name = request.args.get('name')\n"                        # 2
        "    if request.strict:\n"                                     # 3
        "        if not re.fullmatch(r'[A-Za-z0-9_]+', name):\n"       # 4 — wrapped guard
        "            raise ValueError()\n"                             # 5
        "    return open('/data/' + name)\n"                           # 6 — sink
    )
    diff = "+        if not re.fullmatch(r'[A-Za-z0-9_]+', name):\n"
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line":
            "if not re.fullmatch(r'[A-Za-z0-9_]+', name):",
        "variable_name": "name",
        "charset": "A-Za-z0-9_", "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=6, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "dominate" in r.reasoning


def test_transform_result_discarded_declines(tmp_path: Path):
    """Bare ``html.escape(name)`` — result discarded — sanitizes
    nothing; raw ``name`` reaches the sink. Pre-fix the chain started
    at the INPUT variable, which trivially reaches the sink, and Tier
    1B certified SOUND for exactly the incomplete-fix class gate 3
    exists to catch."""
    (tmp_path / "app.py").write_text(
        "import html\n"                       # line 1
        "def f(name):\n"                      # line 2
        "    html.escape(name)\n"             # line 3 — discarded
        "    return render(name)\n"           # line 4 — sink
    )
    diff = "+    html.escape(name)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "html.escape(name)",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "not bound" in r.reasoning


def test_transform_result_misbound_declines(tmp_path: Path):
    """``safe = html.escape(name)`` but the sink renders raw ``name``
    — the transform's OUTPUT never reaches the sink."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    safe = html.escape(name)\n"      # line 3 — bound to safe
        "    return render(name)\n"           # line 4 — sink uses name
    )
    diff = "+    safe = html.escape(name)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe = html.escape(name)",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "does not reach the sink" in r.reasoning


def test_transform_bound_output_reaching_sink_is_sound(tmp_path: Path):
    """Two-direction: the correctly-bound transform whose output
    reaches the sink still certifies — even when the LLM names the
    INPUT variable (the natural reading of the prompt)."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    safe = html.escape(name)\n"      # line 3
        "    return render(safe)\n"           # line 4 — sink uses safe
    )
    diff = "+    safe = html.escape(name)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe = html.escape(name)",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_transform_walrus_conditional_value_declines(tmp_path: Path):
    """A walrus binding whose value is CONDITIONAL
    (``log(safe := clean(x) if flag else x)``) binds the sanitized
    value only on some paths — the fall-through arm sends raw ``name``
    into the sink.  Pre-fix ``_binds_conditional_value`` walked only
    Assign-family statements while the transform gate accepts NamedExpr
    bindings, so the conditional value slipped through inside a call
    argument and certified SOUND.  Two layered gates refuse it now:
    the binding gate (the walrus value is an IfExp, not the call
    result, so ``safe`` never joins the chain) and the conditional-
    value dominance gate behind it — either refusal is correct."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name, flag):\n"
        "    log(safe := (html.escape(name) if flag else name))\n"  # line 3
        "    return render(safe)\n"                                 # line 4
    )
    diff = "+    log(safe := (html.escape(name) if flag else name))\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "log(safe := (html.escape(name) if flag else name))",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert ("not bound to a variable" in r.reasoning
            or "does not dominate" in r.reasoning)


def test_transform_walrus_unconditional_value_still_sound(tmp_path: Path):
    """Two-direction: an UNconditional walrus binding of the transform
    result keeps certifying."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    log(safe := html.escape(name))\n"   # line 3
        "    return render(safe)\n"              # line 4
    )
    diff = "+    log(safe := html.escape(name))\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "log(safe := html.escape(name))",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_transform_tuple_coassignment_raw_cotarget_declines(tmp_path: Path):
    """``escaped, raw_copy = html.escape(name), name`` binds the second
    target to the RAW input.  Pre-fix every target name of the
    statement joined the chain, so a sink consuming ``raw_copy``
    certified SOUND — the "keep both escaped and original" incomplete
    fix slipped past the transform gate."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    escaped, raw_copy = html.escape(name), name\n"   # line 3
        "    return render(raw_copy)\n"                       # line 4
    )
    diff = "+    escaped, raw_copy = html.escape(name), name\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "escaped, raw_copy = html.escape(name), name",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "does not reach the sink" in r.reasoning


def test_transform_tuple_coassignment_escaped_element_still_sound(
    tmp_path: Path,
):
    """Two-direction: the element PAIRED with the transform call keeps
    certifying when the sink consumes it."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    escaped, raw_copy = html.escape(name), name\n"   # line 3
        "    return render(escaped)\n"                        # line 4
    )
    diff = "+    escaped, raw_copy = html.escape(name), name\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "escaped, raw_copy = html.escape(name), name",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_transform_starred_target_refuses(tmp_path: Path):
    """Starred unpacking has no establishable element pairing — the
    binding contributes nothing (refuse, the sound direction)."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    first, *rest = html.escape(name), name, name\n"  # line 3
        "    return render(first)\n"                          # line 4
    )
    diff = "+    first, *rest = html.escape(name), name, name\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "first, *rest = html.escape(name), name, name",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_transform_tuple_unpack_of_call_result_refuses(tmp_path: Path):
    """Tuple target with a NON-tuple RHS (unpacking the call's own
    return) has no element pairing — refuse rather than guess."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    a, b = html.escape(name)\n"      # line 3
        "    return render(a)\n"              # line 4
    )
    diff = "+    a, b = html.escape(name)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "a, b = html.escape(name)",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_transform_chained_assign_both_targets_join(tmp_path: Path):
    """``a = b = html.escape(name)`` binds BOTH names to the transform
    result — each pairs with the whole value and certifies."""
    (tmp_path / "app.py").write_text(
        "import html\n"
        "def f(name):\n"
        "    a = b = html.escape(name)\n"     # line 3
        "    return render(b)\n"              # line 4
    )
    diff = "+    a = b = html.escape(name)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "a = b = html.escape(name)",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_safe_join_raw_input_at_sink_declines(tmp_path: Path):
    """werkzeug.security.safe_join returns None on traversal — it does
    not raise — so the call never constrains its INPUT variable.
    Pre-fix the entry was classed validate-kind and the input stayed
    the chain start, certifying `p = safe_join(base, fn)` with raw
    ``fn`` at the sink as SOUND while `open(fn)` with
    fn='../../etc/passwd' is live."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(base, fn):\n"
        "    p = safe_join(base, fn)\n"   # line 3
        "    return open(fn)\n"           # line 4 — RAW input at sink
    )
    diff = "+    p = safe_join(base, fn)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "p = safe_join(base, fn)",
        "variable_name": "fn", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_safe_join_discarded_result_declines(tmp_path: Path):
    """Bare ``safe_join(base, fn)`` with the result discarded sanitizes
    nothing — same transform-gate rule as the escapers."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(base, fn):\n"
        "    safe_join(base, fn)\n"       # line 3 — discarded
        "    return open(fn)\n"           # line 4
    )
    diff = "+    safe_join(base, fn)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe_join(base, fn)",
        "variable_name": "fn", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "not bound" in r.reasoning


def test_safe_join_bound_result_at_sink_still_sound(tmp_path: Path):
    """Two-direction: the canonical correct fix — sink consumes the
    safe_join RETURN value — keeps certifying."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"
        "def f(base, fn):\n"
        "    p = safe_join(base, fn)\n"   # line 3
        "    return open(p)\n"            # line 4 — return value at sink
    )
    diff = "+    p = safe_join(base, fn)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "p = safe_join(base, fn)",
        "variable_name": "fn", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_lexical_transform_semicolon_joined_first_target_declines(
    tmp_path: Path,
):
    """On a semicolon-joined line the transform call must sit in the
    SAME statement as the captured binding target.  Pre-fix the lexical
    arm captured the line's FIRST target (``safe``, bound to raw ``x``)
    because ``sanitize(`` appeared anywhere later on the line — a sink
    consuming ``safe`` certified SOUND with the raw value live."""
    (tmp_path / "app.js").write_text(
        "function f(req, res) {\n"
        "  var safe = x; var y = DOMPurify.sanitize(x);\n"  # line 2
        "  res.send(safe);\n"                                # line 3
        "}\n"
    )
    diff = "+  var safe = x; var y = DOMPurify.sanitize(x);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "var safe = x; var y = DOMPurify.sanitize(x);",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "DOMPurify.sanitize",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=3, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_lexical_transform_semicolon_joined_correct_target_sound(
    tmp_path: Path,
):
    """Two-direction: the target in the SAME segment as the call keeps
    certifying when the sink consumes it."""
    (tmp_path / "app.js").write_text(
        "function f(req, res) {\n"
        "  var raw = x; var y = DOMPurify.sanitize(x);\n"   # line 2
        "  res.send(y);\n"                                   # line 3
        "}\n"
    )
    diff = "+  var raw = x; var y = DOMPurify.sanitize(x);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "var raw = x; var y = DOMPurify.sanitize(x);",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "DOMPurify.sanitize",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=3, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


# ---------------------------------------------------------------------------
# Binding-escape closure (e2e): any binding that carries a raw
# pre-sanitizer value forward escapes the validated chain — same-line
# rebinds after the sanitizing binding, tuple co-assignment growth,
# container/select bindings, JS multi-declarator lists.
# ---------------------------------------------------------------------------

def test_rebind_after_sanitizer_same_line_declines(tmp_path: Path):
    """``p = safe_join(BASE, fn); p = fn``: runtime ``p`` is the raw
    file name at the sink.  The whole-LINE validator exemption
    certified this SOUND."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"          # line 1
        "def f(fn):\n"                                        # line 2
        "    p = safe_join(BASE, fn); p = fn\n"               # line 3
        "    return open(p)\n"                                # line 4
    )
    diff = "+    p = safe_join(BASE, fn); p = fn\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "p = safe_join(BASE, fn); p = fn",
        "variable_name": "p", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_augassign_after_sanitizer_same_line_declines(tmp_path: Path):
    """``p = safe_join(BASE, fn); p += fn`` mixes raw data into the
    sanitized value on the validator's own line."""
    (tmp_path / "app.py").write_text(
        "from werkzeug.security import safe_join\n"          # line 1
        "def f(fn):\n"                                        # line 2
        "    p = safe_join(BASE, fn); p += fn\n"              # line 3
        "    return open(p)\n"                                # line 4
    )
    diff = "+    p = safe_join(BASE, fn); p += fn\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "p = safe_join(BASE, fn); p += fn",
        "variable_name": "p", "charset": "", "forbidden": "",
        "library_call": "werkzeug.security.safe_join",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="pathtrav",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_tuple_co_assignment_growth_raw_target_declines(tmp_path: Path):
    """Chain-GROW twin of the chain-START pairing: ``a, b = safe, x``
    binds ``b`` to raw ``x``; the sink consuming ``b`` must refuse."""
    (tmp_path / "app.py").write_text(
        "import html\n"                                       # line 1
        "def f(x):\n"                                         # line 2
        "    safe = html.escape(x)\n"                         # line 3
        "    a, b = safe, x\n"                                # line 4
        "    return render(b)\n"                              # line 5
    )
    diff = "+    safe = html.escape(x)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe = html.escape(x)",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_tuple_co_assignment_growth_safe_target_sound(tmp_path: Path):
    """Two-direction: the co-assigned element paired WITH the chain
    member keeps certifying."""
    (tmp_path / "app.py").write_text(
        "import html\n"                                       # line 1
        "def f(x):\n"                                         # line 2
        "    safe = html.escape(x)\n"                         # line 3
        "    a, b = safe, x\n"                                # line 4
        "    return render(a)\n"                              # line 5
    )
    diff = "+    safe = html.escape(x)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe = html.escape(x)",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


def test_swap_idiom_after_sanitizer_declines(tmp_path: Path):
    """``safe, x = x, safe`` rebinds the member ``safe`` to raw ``x``;
    a sink consuming ``safe`` must refuse."""
    (tmp_path / "app.py").write_text(
        "import html\n"                                       # line 1
        "def f(x):\n"                                         # line 2
        "    safe = html.escape(x)\n"                         # line 3
        "    safe, x = x, safe\n"                             # line 4
        "    return render(safe)\n"                           # line 5
    )
    diff = "+    safe = html.escape(x)\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "safe = html.escape(x)",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=5, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_container_binding_with_raw_element_declines(tmp_path: Path):
    """``p = [html.escape(x), x]`` binds a container that CONTAINS the
    call but also carries raw ``x`` verbatim — ``p`` must never seed
    the chain (the Name arm's subtree search credited it)."""
    (tmp_path / "app.py").write_text(
        "import html\n"                                       # line 1
        "def f(x):\n"                                         # line 2
        "    p = [html.escape(x), x]\n"                       # line 3
        "    return render(''.join(p))\n"                     # line 4
    )
    diff = "+    p = [html.escape(x), x]\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "p = [html.escape(x), x]",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_chained_targets_tuple_value_name_target_declines(tmp_path: Path):
    """``p = q, r2 = html.escape(x), x``: ``p`` is bound to the WHOLE
    tuple (raw ``x`` included) while ``q`` gets the sanitized element.
    A sink consuming ``p`` must refuse; ``q`` keeps certifying."""
    src = (
        "import html\n"                                       # line 1
        "def f(x):\n"                                         # line 2
        "    p = q, r2 = html.escape(x), x\n"                 # line 3
        "    return render(p)\n"                              # line 4
    )
    (tmp_path / "app.py").write_text(src)
    diff = "+    p = q, r2 = html.escape(x), x\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "p = q, r2 = html.escape(x), x",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    # Two-direction: the element-paired target q IS the call result.
    (tmp_path / "app.py").write_text(src.replace(
        "return render(p)", "return render(q)"))
    r2 = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r2.status is t1.Tier0Status.SOUND


def test_dict_select_binding_declines(tmp_path: Path):
    """``safe = {True: html.escape(x), False: x}[flag]`` may BE the
    raw member — a conditional select with no IfExp/BoolOp.  The
    binding gate must refuse (the subtree search credited it)."""
    (tmp_path / "app.py").write_text(
        "import html\n"                                            # line 1
        "def f(x, flag):\n"                                        # line 2
        "    safe = {True: html.escape(x), False: x}[flag]\n"      # line 3
        "    return render(safe)\n"                                # line 4
    )
    diff = "+    safe = {True: html.escape(x), False: x}[flag]\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "safe = {True: html.escape(x), False: x}[flag]",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "html.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.py", sink_line=4, sink_class="xss",
        language="python", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_lexical_multi_declarator_first_target_declines(tmp_path: Path):
    """``var safe = x, y = DOMPurify.sanitize(x);`` binds ``safe`` to
    the RAW value — the ``,`` declarator list is the same class as the
    ``;`` join, one delimiter over."""
    (tmp_path / "app.js").write_text(
        "function f(req, res) {\n"
        "  var safe = x, y = DOMPurify.sanitize(x);\n"       # line 2
        "  res.send(safe);\n"                                 # line 3
        "}\n"
    )
    diff = "+  var safe = x, y = DOMPurify.sanitize(x);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "var safe = x, y = DOMPurify.sanitize(x);",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "DOMPurify.sanitize",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=3, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE


def test_lexical_multi_declarator_correct_target_sound(tmp_path: Path):
    """Two-direction: the declarator that IS the call keeps
    certifying when the sink consumes it."""
    (tmp_path / "app.js").write_text(
        "function f(req, res) {\n"
        "  var safe = x, y = DOMPurify.sanitize(x);\n"       # line 2
        "  res.send(y);\n"                                    # line 3
        "}\n"
    )
    diff = "+  var safe = x, y = DOMPurify.sanitize(x);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line":
            "var safe = x, y = DOMPurify.sanitize(x);",
        "variable_name": "x", "charset": "", "forbidden": "",
        "library_call": "DOMPurify.sanitize",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=3, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.SOUND


# ---------------------------------------------------------------------------
# Comment/string decoy binding (tier1b lanes)
# ---------------------------------------------------------------------------

def test_known_safe_call_comment_decoy_declines_js(tmp_path: Path):
    """The only occurrence of the claimed safe call lives inside a
    block comment while raw ``name`` flows to the sink. Pre-fix
    ``_find_best_validator_line`` matched raw stripped text with no
    code-view anchor and the lane certified SOUND off the prose —
    a false barrier witness from a commented-out sanitizer line
    (prime decoy material: CVE fix commits routinely carry old
    sanitizer lines as ``+`` lines in comments/migration notes)."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res) {\n"                           # 1
        "    let name = req.query.name;\n"                        # 2
        "    /*\n"                                                # 3
        "    name = validator.escape(name);\n"                    # 4 — decoy
        "    */\n"                                                # 5
        "    res.send('<b>' + name + '</b>');\n"                  # 6 — sink
        "}\n"
    )
    diff = "+    name = validator.escape(name);\n"
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "name = validator.escape(name);",
        "variable_name": "name", "charset": "", "forbidden": "",
        "library_call": "validator.escape",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=6, sink_class="xss",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "no occurrence" in r.reasoning


def test_charset_comment_decoy_declines_js(tmp_path: Path):
    """Charset lane through the full try_tier1b path: the guard exists
    only inside a block comment, the claimed line is supplied as a
    ``+`` diff line, mechanical re-extract agrees and Z3 is satisfied
    — pre-fix the verdict was SOUND with the Z3 proof bound to the
    comment line."""
    (tmp_path / "app.js").write_text(
        "function serve(req, res) {\n"                                # 1
        "    let name = req.query.name;\n"                             # 2
        "    /*\n"                                                     # 3
        "    if (!/^[a-z]+$/.test(name)) { return; }\n"                # 4 — decoy
        "    */\n"                                                     # 5
        "    return fs.readFile('/data/' + name);\n"                   # 6 — sink
        "}\n"
    )
    diff = "+    if (!/^[a-z]+$/.test(name)) { return; }\n"
    reply = json.dumps({
        "kind": "charset",
        "validator_source_line":
            "if (!/^[a-z]+$/.test(name)) { return; }",
        "variable_name": "name",
        "charset": "a-z", "forbidden": "", "library_call": "",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app.js", sink_line=6, sink_class="pathtrav",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "no occurrence" in r.reasoning


def test_find_best_validator_line_skips_string_decoy_python(tmp_path: Path):
    """A string-literal copy of the claimed line CLOSER to the sink
    must not shadow the real code occurrence — pre-fix the
    closest-before-sink rule picked the decoy (Python lanes were only
    incidentally backstopped by the AST binding gates; a
    validate-kind curated entry has no such backstop)."""
    source = (
        "def f(path):\n"                                # 1
        "    abs_path = safe_join(BASE, path)\n"        # 2 — real
        "    note = '''\n"                              # 3
        "    abs_path = safe_join(BASE, path)\n"        # 4 — decoy
        "    '''\n"                                     # 5
        "    return open(abs_path)\n"                   # 6 — sink
    )
    line = t1._find_best_validator_line(
        source, "abs_path = safe_join(BASE, path)", 6, "python",
    )
    assert line == 2


def test_find_best_validator_line_all_decoys_returns_none(tmp_path: Path):
    """When every occurrence is prose the binding must refuse, not
    fall back to a comment line."""
    source = (
        "function serve(req, res) {\n"
        "    /*\n"
        "    name = validator.escape(name);\n"
        "    */\n"
        "    res.send(name);\n"
        "}\n"
    )
    line = t1._find_best_validator_line(
        source, "name = validator.escape(name);", 5, "javascript",
    )
    assert line is None


# ---------------------------------------------------------------------------
# Validate-kind argument binding (pinned BEFORE any validate entry lands)
# ---------------------------------------------------------------------------

def test_line_invokes_call_validate_kind_requires_argument():
    """Validate-kind chains start DIRECTLY from the claimed variable,
    so the assigned-from fallback must not bind a variable that is
    never an argument of the call: ``safe = raw; ok = ipcheck(z)``
    binds ``safe`` on the line, but ipcheck never constrained it."""
    fn = t1._line_invokes_library_call
    line = "safe = raw; ok = ipcheck(z)"
    # Transform-kind (default) keeps the fallback — harmless there,
    # the chain re-derives its start from real binding targets.
    assert fn(line, "ipcheck", "safe") is True
    assert fn(line, "ipcheck", "safe",
              require_variable_in_args=True) is False
    # The variable as a real argument still passes.
    assert fn("ok = ipcheck(safe)", "ipcheck", "safe",
              require_variable_in_args=True) is True


def test_first_validate_entry_cannot_bind_non_argument(
        tmp_path: Path, monkeypatch):
    """End-to-end pin: with a validate-kind curated entry (none exist
    yet — whoever lands the first one gets this guard for free), an
    LLM claim binding a variable the call never took as an argument
    must DECLINE, not certify SOUND.

    The live lane is non-Python: the lexical chain check only asks
    whether the variable appears at the sink line, so nothing behind
    gate 1 re-checks that the validator ever saw the value (the
    Python AST chain walker refuses these shapes on the rebind)."""
    from core.dataflow import known_safe_calls as ksc

    fake_entry = ksc.KnownSafeCall(
        library_call="net.isIP",
        sink_class="cmdi",
        languages=("javascript",),
        input_arg_kind="validate",
        soundness_note="test-only fake validate entry",
    )
    monkeypatch.setattr(
        t1.known_safe_calls, "find",
        lambda call, sink_class, language: fake_entry,
    )
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.js").write_text(
        "function run(req, other) {\n"
        "  const raw = req.query.host;\n"
        "  safe = raw; ok = net.isIP(other);\n"
        "  exec(safe);\n"
        "}\n"
    )
    diff = (
        "--- a/app/views.js\n"
        "+++ b/app/views.js\n"
        "@@\n"
        "+  safe = raw; ok = net.isIP(other);\n"
        "   exec(safe);\n"
    )
    reply = json.dumps({
        "kind": "known_safe_call",
        "validator_source_line": "  safe = raw; ok = net.isIP(other);",
        "variable_name": "safe",
        "charset": "", "forbidden": "",
        "library_call": "net.isIP",
    })
    r = t1.try_tier1b(
        fix_diff=diff, repo_root=tmp_path,
        sink_uri="app/views.js", sink_line=4, sink_class="cmdi",
        language="javascript", complete=_fake_complete(reply),
    )
    assert r.status is t1.Tier0Status.NOT_APPLICABLE
    assert "does not appear on the claimed source line" in r.reasoning
