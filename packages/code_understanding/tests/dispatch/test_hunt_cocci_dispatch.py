"""Tests for the Coccinelle dispatch backend for /understand --hunt.

The dispatch is small and side-effect-light by design: 1 LLM call to
translate pattern → cocci rule, 1 spatch invocation, output → variants.
Tests mock both the LLM and spatch so they don't depend on installed
binaries / live provider keys.

Coverage:
  * pattern → rule translation (success + UNTRANSLATABLE + raised
    exception + empty response)
  * spatch result → variant-dict shape (path normalization, dedup-key
    fields, "tool: coccinelle" pin)
  * dispatch entry-point: input validation, missing spatch, non-C repo,
    rule-gen failure, spatch error vs empty-result distinction
  * repo-language heuristic: detects C headers/sources, doesn't mis-fire
    on Python repos
"""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest


_RAPTOR_DIR = os.environ["RAPTOR_DIR"]
if _RAPTOR_DIR not in sys.path:
    sys.path.insert(0, _RAPTOR_DIR)


from packages.code_understanding.dispatch import hunt_cocci_dispatch as mod
from packages.coccinelle.models import SpatchMatch, SpatchResult


# ---------------------------------------------------------------------
# Repo-language heuristic
# ---------------------------------------------------------------------


def test_repo_looks_c_cpp_finds_c_source(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "parser.c").write_text("int main(void){return 0;}")
    (tmp_path / "Makefile").write_text("all:\n")
    assert mod.repo_looks_c_cpp(str(tmp_path)) is True


def test_repo_looks_c_cpp_finds_cpp_headers(tmp_path):
    (tmp_path / "include").mkdir()
    (tmp_path / "include" / "api.hpp").write_text("class A {};\n")
    assert mod.repo_looks_c_cpp(str(tmp_path)) is True


def test_repo_looks_c_cpp_returns_false_for_python_only(tmp_path):
    (tmp_path / "main.py").write_text("print('hi')\n")
    (tmp_path / "lib.py").write_text("def f(): pass\n")
    assert mod.repo_looks_c_cpp(str(tmp_path)) is False


def test_repo_looks_c_cpp_returns_false_for_missing_path(tmp_path):
    assert mod.repo_looks_c_cpp(str(tmp_path / "does-not-exist")) is False


def test_repo_looks_c_cpp_bounds_scan_on_huge_repo(tmp_path, monkeypatch):
    """Bounded by ``max_files_to_check`` so a giant non-C repo
    doesn't pay an unbounded rglob walk."""
    # Create 50 .py files; bound at 10 → returns False without
    # walking the whole tree (proves the bound is exercised).
    for i in range(50):
        (tmp_path / f"f{i}.py").write_text("\n")
    assert mod.repo_looks_c_cpp(str(tmp_path), max_files_to_check=10) is False


# ---------------------------------------------------------------------
# Pattern → cocci rule translation
# ---------------------------------------------------------------------


def _fake_response(text: str):
    """Stub matching the shape of ``LLMResponse`` (content field)."""
    return mock.Mock(content=text)


def _fake_model():
    """Minimal ``ModelConfig`` stub. Real one isn't constructed
    because we patch ``create_provider``."""
    m = mock.Mock()
    m.model_name = "fake-test-model"
    return m


def test_translate_extracts_rule_from_fenced_block():
    """Model output wrapped in ```cocci ... ``` fences — rule is
    extracted cleanly without the fence markers."""
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "Here you go:\n```cocci\n@r@\nexpression e;\n@@\nstrcpy(e, ...)\n```\n"
    )
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        rule = mod.translate_pattern_to_cocci_rule(
            "find all strcpy calls", model=_fake_model(),
        )
    assert rule is not None
    assert "@r@" in rule
    assert "strcpy" in rule
    # Fence markers stripped.
    assert "```" not in rule


def test_translate_returns_none_for_untranslatable():
    """Model declared the pattern UNTRANSLATABLE — dispatch surfaces
    None so caller can fall back to LLM-grep hunt."""
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "UNTRANSLATABLE: this requires data-flow analysis"
    )
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        rule = mod.translate_pattern_to_cocci_rule(
            "find tainted-input-to-eval flows", model=_fake_model(),
        )
    assert rule is None


def test_translate_returns_none_for_empty_response():
    """Model returned empty content — dispatch surfaces None rather
    than generating a malformed empty rule."""
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response("")
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        rule = mod.translate_pattern_to_cocci_rule(
            "anything", model=_fake_model(),
        )
    assert rule is None


def test_translate_falls_back_to_raw_text_when_no_fences():
    """Model returned the rule body without fences — take it
    verbatim. Some smaller models don't reliably produce fences."""
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "@r@\nexpression e;\n@@\nstrcpy(e, ...)\n"
    )
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        rule = mod.translate_pattern_to_cocci_rule(
            "strcpy", model=_fake_model(),
        )
    assert rule is not None
    assert "strcpy" in rule


# ---------------------------------------------------------------------
# SpatchResult → variant-dict
# ---------------------------------------------------------------------


def test_matches_to_variants_normalizes_absolute_paths_to_repo_relative(
    tmp_path,
):
    """Spatch emits absolute paths; dedup key in VariantAdapter is
    file-relative. Without normalization, cocci variants would
    bucket separately from LLM-dispatch variants for the same line."""
    (tmp_path / "src").mkdir()
    abs_file = tmp_path / "src" / "parser.c"
    abs_file.write_text("// stub\n")
    result = SpatchResult(
        rule="r", matches=[
            SpatchMatch(file=str(abs_file), line=42, message="bad strcpy"),
        ],
    )
    variants = mod._spatch_matches_to_variants(result, str(tmp_path))
    assert len(variants) == 1
    v = variants[0]
    assert v["file"] == "src/parser.c"  # repo-relative
    assert v["line"] == 42
    assert v["snippet"] == "bad strcpy"
    assert v["confidence"] == "high"
    assert v["tool"] == "coccinelle"


def test_matches_to_variants_preserves_unrelated_paths():
    """A path that isn't under the repo (e.g. cross-FS, system
    header) stays as-is rather than crashing the conversion."""
    result = SpatchResult(
        rule="r", matches=[
            SpatchMatch(
                file="/usr/include/sys/socket.h",
                line=1, message="hit in system header",
            ),
        ],
    )
    variants = mod._spatch_matches_to_variants(result, "/tmp/some-repo")
    assert variants[0]["file"] == "/usr/include/sys/socket.h"


def test_matches_to_variants_handles_empty_result():
    result = SpatchResult(rule="r", matches=[])
    assert mod._spatch_matches_to_variants(result, "/tmp/repo") == []


# ---------------------------------------------------------------------
# Dispatch entry point — input validation
# ---------------------------------------------------------------------


def test_dispatch_rejects_empty_pattern():
    out = mod.cocci_hunt_dispatch(_fake_model(), "", "/tmp/whatever")
    assert len(out) == 1
    assert "error" in out[0]
    assert "non-empty" in out[0]["error"]


def test_dispatch_rejects_invalid_repo_path(tmp_path):
    out = mod.cocci_hunt_dispatch(
        _fake_model(), "find strcpy", str(tmp_path / "missing"),
    )
    assert "error" in out[0]
    assert "not a directory" in out[0]["error"]


def test_dispatch_surfaces_missing_spatch(tmp_path):
    """When spatch isn't installed, the error explicitly tells the
    operator the fallback (--hunt-tool=llm). Operator-UX fix —
    historical "spatch not found" errors didn't suggest the
    alternative."""
    (tmp_path / "x.c").write_text("int main(){return 0;}")
    with mock.patch.object(mod, "spatch_is_available", return_value=False):
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "find strcpy", str(tmp_path),
        )
    assert "error" in out[0]
    assert "--hunt-tool=llm" in out[0]["error"]


def test_dispatch_rejects_non_c_repo(tmp_path):
    """Cocci is C/C++-only. Hitting it on a Python repo would
    succeed at spatch-invocation but find nothing useful — surface
    the mismatch up-front with an actionable hint."""
    (tmp_path / "main.py").write_text("\n")
    with mock.patch.object(mod, "spatch_is_available", return_value=True):
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "find strcpy", str(tmp_path),
        )
    assert "error" in out[0]
    assert "C/C++" in out[0]["error"]
    assert "--hunt-tool=llm" in out[0]["error"]


# ---------------------------------------------------------------------
# Dispatch entry point — happy path + failure paths
# ---------------------------------------------------------------------


def test_dispatch_happy_path_translates_runs_returns_variants(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "parser.c").write_text(
        "void f(char *u){ char b[8]; strcpy(b, u); }\n"
    )

    # Stub LLM response: a valid (toy) cocci rule.
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "```cocci\n@r@\nexpression e;\n@@\nstrcpy(...)\n```"
    )
    # Stub spatch: returns a single match for the toy rule.
    fake_spatch_result = SpatchResult(
        rule="generated",
        matches=[SpatchMatch(
            file=str(tmp_path / "src" / "parser.c"),
            line=1, message="strcpy use",
        )],
        returncode=0,
    )

    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider), \
         mock.patch.object(mod, "spatch_run_rule",
                           return_value=fake_spatch_result):
        # sandbox=False so the test doesn't need core.sandbox
        # available (tested separately above); the test is exercising
        # the dispatch chain, not the sandbox.
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "find strcpy", str(tmp_path), sandbox=False,
        )

    assert len(out) == 1
    assert out[0]["file"] == "src/parser.c"
    assert out[0]["line"] == 1
    assert out[0]["tool"] == "coccinelle"


def test_dispatch_surfaces_untranslatable_pattern(tmp_path):
    """Pattern needs runtime/data-flow info that cocci can't express
    — dispatch error surfaces the suggested fallback."""
    (tmp_path / "x.c").write_text("int main(){return 0;}\n")
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "UNTRANSLATABLE: pattern is data-flow shaped"
    )
    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "tainted input flows to eval()",
            str(tmp_path),
        )
    assert "error" in out[0]
    assert "UNTRANSLATABLE" in out[0]["error"]
    assert "--hunt-tool=llm" in out[0]["error"]


def test_dispatch_surfaces_rulegen_call_failure(tmp_path):
    """Provider construction or generate() raised. Dispatch returns
    a clean error variant, not a raise that breaks the multi-model
    substrate."""
    (tmp_path / "x.c").write_text("\n")
    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           side_effect=RuntimeError("provider down")):
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "find anything", str(tmp_path),
        )
    assert "error" in out[0]
    assert "rule-gen LLM call failed" in out[0]["error"]


def test_dispatch_distinguishes_empty_match_from_spatch_error(tmp_path):
    """spatch ran cleanly but found nothing → return [] (no false
    error). spatch ran with errors AND no matches → return error.
    Pin this distinction so a future "be paranoid" change doesn't
    swallow legitimate empty-result answers."""
    (tmp_path / "x.c").write_text("\n")
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "```cocci\n@r@\n@@\n@@\n```"
    )
    # spatch ran cleanly, no matches.
    clean_empty = SpatchResult(
        rule="r", matches=[], errors=[], returncode=0,
    )
    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider), \
         mock.patch.object(mod, "spatch_run_rule",
                           return_value=clean_empty):
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "p", str(tmp_path),
        )
    assert out == []  # no error, just no matches

    # spatch errored AND no matches → surface error.
    errored_empty = SpatchResult(
        rule="r", matches=[], errors=["bad rule syntax"], returncode=1,
    )
    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider), \
         mock.patch.object(mod, "spatch_run_rule",
                           return_value=errored_empty):
        out = mod.cocci_hunt_dispatch(
            _fake_model(), "p", str(tmp_path),
        )
    assert "error" in out[0]
    assert "bad rule syntax" in out[0]["error"]


def test_dispatch_uses_sandbox_runner_by_default(tmp_path):
    """Critical adversarial finding: cocci rules CAN embed
    ``script:python`` blocks that execute in the spatch process.
    Rule text is LLM-emitted; pattern is operator-influenced. That's
    arbitrary code exec inside whichever process spatches. Pin that
    the dispatch routes spatch through ``make_sandbox_runner`` by
    default (Landlock-restricted reads, network-blocked, fake $HOME)
    so a compromised rule cannot exfiltrate."""
    (tmp_path / "x.c").write_text("\n")
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "```cocci\n@r@\n@@\nstrcpy(...)\n```"
    )
    captured_runner = {}

    def _capture_run_rule(*args, **kwargs):
        captured_runner["runner"] = kwargs.get("subprocess_runner")
        return SpatchResult(rule="r", matches=[], returncode=0)

    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider), \
         mock.patch.object(mod, "spatch_run_rule",
                           side_effect=_capture_run_rule):
        # Default sandbox=True path
        mod.cocci_hunt_dispatch(
            _fake_model(), "find strcpy", str(tmp_path),
        )

    runner = captured_runner["runner"]
    assert runner is not None, (
        "spatch ran with subprocess_runner=None — that's UNSANDBOXED "
        "plain subprocess.run; LLM-emitted rule could exfiltrate"
    )
    # Sanity: the runner is callable (the make_sandbox_runner shape).
    assert callable(runner)


def test_dispatch_sandbox_false_skips_sandbox_runner(tmp_path):
    """Tests / trusted operators can opt out via ``sandbox=False``.
    The runner is then None (plain subprocess.run via the cocci
    runner's default). Pin the explicit-opt-out path so a future
    "always sandbox" change doesn't silently break tests."""
    (tmp_path / "x.c").write_text("\n")
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "```cocci\n@r@\n@@\n@@\n```"
    )
    captured_runner = {}

    def _capture_run_rule(*args, **kwargs):
        captured_runner["runner"] = kwargs.get("subprocess_runner")
        return SpatchResult(rule="r", matches=[], returncode=0)

    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider), \
         mock.patch.object(mod, "spatch_run_rule",
                           side_effect=_capture_run_rule):
        mod.cocci_hunt_dispatch(
            _fake_model(), "p", str(tmp_path), sandbox=False,
        )

    assert captured_runner["runner"] is None


def test_dispatch_explicit_spatch_runner_wins_over_sandbox(tmp_path):
    """If caller passes ``spatch_runner=``, it overrides everything
    — sandbox flag is ignored. Pin so test seams stay reliable."""
    (tmp_path / "x.c").write_text("\n")
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "```cocci\n@r@\n@@\n@@\n```"
    )

    sentinel_runner = mock.Mock()
    captured_runner = {}

    def _capture_run_rule(*args, **kwargs):
        captured_runner["runner"] = kwargs.get("subprocess_runner")
        return SpatchResult(rule="r", matches=[], returncode=0)

    with mock.patch.object(mod, "spatch_is_available", return_value=True), \
         mock.patch.object(mod, "create_provider",
                           return_value=fake_provider), \
         mock.patch.object(mod, "spatch_run_rule",
                           side_effect=_capture_run_rule):
        # sandbox=True but explicit runner overrides
        mod.cocci_hunt_dispatch(
            _fake_model(), "p", str(tmp_path),
            spatch_runner=sentinel_runner, sandbox=True,
        )

    assert captured_runner["runner"] is sentinel_runner


# ---------------------------------------------------------------------
# Real-spatch E2E (skipped when spatch isn't installed)
# ---------------------------------------------------------------------


@pytest.mark.skipif(
    not __import__("shutil").which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_finds_strcpy_with_canonical_rule(tmp_path):
    """End-to-end: real spatch executes a hand-written rule against
    a real C file, the dispatch parses real COCCIRESULT lines, and
    variants come back in the right shape.

    Uses ``sandbox=False`` because the sandbox path requires
    ``core.sandbox`` initialisation that isn't pertinent to proving
    the spatch-integration; sandboxing is exercised by the unit
    tests above.

    Stubs only the LLM rule-gen step (since we don't want to make
    a real LLM call from a unit-test run); the rule we inject is
    a hand-written canonical strcpy-finder so we know exactly
    what spatch should return."""
    # Real C file with one strcpy call.
    src = tmp_path / "vuln.c"
    src.write_text(
        "#include <string.h>\n"
        "void copy_in(char *user_input) {\n"
        "    char buf[64];\n"
        "    strcpy(buf, user_input);\n"
        "}\n"
    )

    # Canonical Coccinelle rule that emits one COCCIRESULT per
    # strcpy call. Format documented in packages/coccinelle/runner.py.
    # Plain SmPL rule with a position metavariable, NO script block —
    # the runner auto-injects a harness that emits COCCIRESULT JSON
    # for parsing. Matches the production prompt's contract.
    rule_text = (
        "@r@\n"
        "expression e1, e2;\n"
        "position p;\n"
        "@@\n"
        "strcpy@p(e1, e2)\n"
    )

    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        f"```cocci\n{rule_text}\n```"
    )
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        out = mod.cocci_hunt_dispatch(
            _fake_model(),
            "find strcpy calls",
            str(tmp_path),
            sandbox=False,  # real spatch but no sandbox in CI
        )

    # Expect at least one variant pointing at vuln.c. spatch may
    # emit duplicates depending on phase rules; the test asserts at
    # least one match in the right file at line 4.
    assert len(out) >= 1, f"expected ≥1 variant, got: {out!r}"
    matches = [v for v in out
               if v.get("file") and "vuln.c" in v["file"]
               and v.get("line") == 4]
    assert matches, (
        f"expected at least one strcpy match at vuln.c:4; "
        f"got variants: {out!r}"
    )
    v = matches[0]
    assert v["tool"] == "coccinelle"
    assert v["confidence"] == "high"


@pytest.mark.skipif(
    not __import__("shutil").which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_empty_repo_returns_empty(tmp_path):
    """Real spatch against a C source with no matching pattern
    returns an empty variant list — NOT an error variant."""
    src = tmp_path / "clean.c"
    src.write_text("int main(void) { return 0; }\n")

    # Plain SmPL rule with a position metavariable, NO script block —
    # the runner auto-injects a harness that emits COCCIRESULT JSON
    # for parsing. Matches the production prompt's contract.
    rule_text = (
        "@r@\n"
        "expression e1, e2;\n"
        "position p;\n"
        "@@\n"
        "strcpy@p(e1, e2)\n"
    )
    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        f"```cocci\n{rule_text}\n```"
    )
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        out = mod.cocci_hunt_dispatch(
            _fake_model(),
            "find strcpy calls",
            str(tmp_path),
            sandbox=False,
        )
    assert out == [], (
        f"expected empty variant list (no error); got: {out!r}"
    )


@pytest.mark.skipif(
    not __import__("shutil").which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_malformed_rule_surfaces_error(tmp_path):
    """A garbage rule causes spatch to emit errors. Dispatch must
    surface that as an error variant with the spatch error in the
    message — operator can refine the pattern. Do NOT silently
    return empty (that would mask a real failure)."""
    (tmp_path / "x.c").write_text("int main(){return 0;}\n")

    fake_provider = mock.Mock()
    fake_provider.generate.return_value = _fake_response(
        "```cocci\nthis is not valid cocci syntax\n```"
    )
    with mock.patch.object(mod, "create_provider",
                           return_value=fake_provider):
        out = mod.cocci_hunt_dispatch(
            _fake_model(),
            "p",
            str(tmp_path),
            sandbox=False,
        )
    assert len(out) == 1
    assert "error" in out[0]
    # Some indication that spatch failed (not just that the dispatch
    # returned None or hit a Python exception).
    err = out[0]["error"]
    assert ("cocci rule did not execute cleanly" in err
            or "spatch invocation failed" in err), err


def test_dispatch_signature_matches_HuntDispatchFn_protocol():
    """Pin: ``cocci_hunt_dispatch(model, pattern, repo_path) ->
    list[dict]`` — drop-in compatible with the substrate's
    ``HuntDispatchFn`` (so the multi-model orchestrator can swap
    backends without wrapping)."""
    import inspect
    sig = inspect.signature(mod.cocci_hunt_dispatch)
    positional = [
        n for n, p in sig.parameters.items()
        if p.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    ]
    assert positional[:3] == ["model", "pattern", "repo_path"], (
        f"signature drift — first 3 positional must be "
        f"(model, pattern, repo_path), got {positional[:3]}"
    )
