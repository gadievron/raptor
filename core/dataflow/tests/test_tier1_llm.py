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
