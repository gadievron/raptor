"""Tests for core.audit.cocci_flow — flow-sensitive SmPL library.

Two layers:

* Hermetic tests: rendering, hypothesis dispatch, binding extraction
  (identifier-consistency negative controls), and sweep classification
  with a monkeypatched ``run_rule`` — no spatch needed.
* Live tests (skipif spatch missing): each template against its static
  fixture pair under ``fixtures/cocci_flow/`` — the bad fixture must
  confirm, the correctly-guarded fixture must refute (proving the
  ``when !=`` exclusions actually prune guarded paths).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.audit.cocci_flow import (
    CWE_FLOW_TEMPLATES,
    FLOW_TEMPLATES,
    chain_entry_for_cwe,
    extract_flow_binding,
    flow_template_for_cwe,
    flow_template_for_hypothesis,
    render_flow_rule,
    run_flow_cocci_sweep,
    victim_expr_valid,
)

FIXTURES = Path(__file__).parent / "fixtures" / "cocci_flow"


# ── victim validation ────────────────────────────────────────────────


class TestVictimValidation:
    @pytest.mark.parametrize("expr", [
        "buf", "conn->buf", "a.b", "req->hdr->len", "s.f.g", "_x9",
    ])
    def test_valid(self, expr):
        assert victim_expr_valid(expr)

    @pytest.mark.parametrize("expr", [
        "", "9x", "a b", "a->b; free(x)", "a->", "->b", "a..b",
        'x"; @@', "a->b(", "buf[0]", "*p", "a+b",
    ])
    def test_invalid(self, expr):
        assert not victim_expr_valid(expr)


# ── rendering ────────────────────────────────────────────────────────


class TestRenderFlowRule:
    def test_uaf_binds_victim_and_free_fn(self):
        r = render_flow_rule(
            "use_after_free", victim="conn->buf", free_fn="kfree",
        )
        assert r is not None
        assert "kfree(conn->buf);" in r
        assert "when != conn->buf = E1" in r
        assert "COCCIRESULT" in r
        # star-deref pattern must not start at column 0 (SmPL star op)
        for line in r.splitlines():
            if "*conn->buf@p" in line:
                assert line.startswith(" ")

    def test_double_free_binds(self):
        r = render_flow_rule("double_free", victim="ptr")
        assert r is not None
        assert "free@p(ptr);" in r
        assert "when != ptr = E1" in r

    def test_double_fetch_binds(self):
        r = render_flow_rule("double_fetch", victim="uptr")
        assert r is not None
        assert "copy_from_user@p(D2, uptr, S2);" in r

    def test_unchecked_return_binds_func(self):
        r = render_flow_rule("unchecked_return", func="kmalloc")
        assert r is not None
        assert "V = kmalloc(...)" in r
        assert "when != if (<+... V ...+>) S1" in r
        # semicolon-free assignment so decl_init iso applies
        assert "V = kmalloc(...);" not in r

    def test_missing_binding_returns_none(self):
        assert render_flow_rule("use_after_free") is None
        assert render_flow_rule("unchecked_return") is None

    def test_invalid_victim_returns_none(self):
        assert render_flow_rule(
            "use_after_free", victim="x; rm -rf /",
        ) is None
        assert render_flow_rule("double_free", victim="a b") is None

    def test_invalid_helper_fn_returns_none(self):
        assert render_flow_rule(
            "use_after_free", victim="buf", free_fn="free; bad",
        ) is None
        assert render_flow_rule(
            "unchecked_return", func="mal loc",
        ) is None

    def test_unknown_template_returns_none(self):
        assert render_flow_rule("nonsense", victim="buf") is None


# ── dispatch ─────────────────────────────────────────────────────────


class TestDispatch:
    @pytest.mark.parametrize("hyp,expected", [
        ("use-after-free of conn->buf in handler", "use_after_free"),
        ("buffer is used after it is freed", "use_after_free"),
        ("double free of `req` on the error path", "double_free"),
        ("`hdr` is fetched twice from userspace", "double_fetch"),
        ("unchecked return of malloc before memcpy", "unchecked_return"),
        ("integer overflow in length calculation", None),
    ])
    def test_hypothesis_dispatch(self, hyp, expected):
        assert flow_template_for_hypothesis(hyp) == expected

    @pytest.mark.parametrize("cwe,expected", sorted(CWE_FLOW_TEMPLATES.items()))
    def test_cwe_dispatch(self, cwe, expected):
        assert flow_template_for_cwe(cwe) == expected
        assert flow_template_for_cwe(cwe.split("-")[1]) == expected

    def test_cwe_dispatch_unknown(self):
        assert flow_template_for_cwe("CWE-89") is None

    def test_chain_entry(self):
        entry = chain_entry_for_cwe("CWE-416")
        assert entry == {
            "type": "coccinelle_flow",
            "config": {"template": "use_after_free"},
        }
        assert chain_entry_for_cwe("CWE-190") is None

    def test_all_templates_have_cwe_or_keyword_route(self):
        routed = set(CWE_FLOW_TEMPLATES.values())
        assert routed == set(FLOW_TEMPLATES)


# ── binding extraction (identifier-consistency controls) ─────────────


class TestExtractFlowBinding:
    def test_uaf_field_path(self):
        b = extract_flow_binding(
            "use_after_free",
            "use-after-free of conn->buf: kfree(conn->buf) then deref",
        )
        assert b == {"victim": "conn->buf", "free_fn": "kfree"}

    def test_uaf_backtick(self):
        b = extract_flow_binding(
            "use_after_free", "`ctx` is used after being freed",
        )
        assert b is not None
        assert b["victim"] == "ctx"

    def test_uaf_default_free_fn(self):
        b = extract_flow_binding(
            "use_after_free", "`node` is used after release of the slot",
        )
        assert b == {"victim": "node"}

    def test_double_free_victim(self):
        b = extract_flow_binding(
            "double_free", "double free of `req` when init fails",
        )
        assert b is not None and b["victim"] == "req"

    def test_double_fetch_from_phrasing(self):
        b = extract_flow_binding(
            "double_fetch",
            "header re-fetched from `uarg` after validation",
        )
        assert b is not None and b["victim"] == "uarg"

    def test_unchecked_return_named_fn(self):
        b = extract_flow_binding(
            "unchecked_return",
            "return value of kmalloc is dereferenced without check",
        )
        assert b == {"func": "kmalloc"}

    def test_unchecked_return_allocator_hint(self):
        b = extract_flow_binding(
            "unchecked_return",
            "missing null check: fopen result used directly",
        )
        assert b == {"func": "fopen"}

    def test_no_identifier_binds_nothing(self):
        assert extract_flow_binding(
            "use_after_free", "the memory is freed twice somewhere",
        ) is None
        assert extract_flow_binding(
            "unchecked_return", "a return value is not checked",
        ) is None

    def test_prose_words_never_bind(self):
        # "freed twice" / "the pointer" must not bind prose as victims.
        assert extract_flow_binding(
            "double_free", "freeing the same pointer twice",
        ) is None


# ── sweep classification (hermetic, stubbed runner) ──────────────────


class _FakeSpatchResult:
    def __init__(self, matches=None, errors=None, returncode=0):
        self.matches = matches or []
        self.errors = errors or []
        self.returncode = returncode


class _FakeMatch:
    def __init__(self, line, rule="flow_use_after_free", message="m"):
        self.line = line
        self.rule = rule
        self.message = message

    def to_dict(self):
        return {"line": self.line, "rule": self.rule,
                "message": self.message, "file": "src/a.c"}


HYP = "use-after-free of `buf` after free(buf)"


class TestRunFlowCocciSweep:
    def _target(self, tmp_path: Path) -> Path:
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / "a.c").write_text("int x;\n")
        return tmp_path

    def _patch(self, monkeypatch, result=None, available=True, exc=None):
        import packages.coccinelle.runner as runner_mod

        def fake_run_rule(target, rule, **kw):
            if exc is not None:
                raise exc
            # The rendered rule must exist on disk and bind the victim.
            text = Path(rule).read_text()
            assert "buf" in text
            return result

        monkeypatch.setattr(runner_mod, "run_rule", fake_run_rule)
        monkeypatch.setattr(
            runner_mod, "is_available", lambda: available,
        )

    def _run(self, tmp_path, **kw):
        args = {
            "target_path": tmp_path,
            "file_path": "src/a.c",
            "function_name": "handler",
            "hypothesis": HYP,
        }
        args.update(kw)
        return run_flow_cocci_sweep(**args)

    def test_path_traversal_blocked(self, tmp_path: Path):
        r = self._run(self._target(tmp_path), file_path="../evil.c")
        assert r.outcome == "error"

    def test_missing_file(self, tmp_path: Path):
        r = self._run(tmp_path, file_path="nope.c")
        assert r.outcome == "error"

    def test_no_template_is_inconclusive(self, tmp_path: Path):
        r = self._run(
            self._target(tmp_path),
            hypothesis="integer overflow in size calc",
        )
        assert r.outcome == "inconclusive"

    def test_no_binding_is_inconclusive(self, tmp_path: Path):
        r = self._run(
            self._target(tmp_path),
            hypothesis="the memory is freed twice somewhere",
            template="double_free",
        )
        assert r.outcome == "inconclusive"
        assert "identifier-consistency" in r.details["reason"]

    def test_spatch_unavailable_is_error(
        self, tmp_path: Path, monkeypatch,
    ):
        self._patch(monkeypatch, available=False)
        r = self._run(self._target(tmp_path))
        assert r.outcome == "error"
        assert "not installed" in r.errors[0]

    def test_matches_confirm(self, tmp_path: Path, monkeypatch):
        self._patch(
            monkeypatch, _FakeSpatchResult(matches=[_FakeMatch(7)]),
        )
        r = self._run(self._target(tmp_path))
        assert r.outcome == "confirmed"
        assert r.matches[0]["line"] == 7
        assert r.rule_id == "cocci-flow:use_after_free"
        assert r.details["binding"]["victim"] == "buf"

    def test_no_matches_refute(self, tmp_path: Path, monkeypatch):
        self._patch(monkeypatch, _FakeSpatchResult())
        r = self._run(self._target(tmp_path))
        assert r.outcome == "refuted"

    def test_spatch_errors_are_error_never_refuted(
        self, tmp_path: Path, monkeypatch,
    ):
        self._patch(
            monkeypatch,
            _FakeSpatchResult(errors=["parse error: line 3"]),
        )
        r = self._run(self._target(tmp_path))
        assert r.outcome == "error"

    def test_nonzero_exit_is_error(self, tmp_path: Path, monkeypatch):
        self._patch(
            monkeypatch, _FakeSpatchResult(returncode=2),
        )
        r = self._run(self._target(tmp_path))
        assert r.outcome == "error"
        assert "exited with code 2" in r.errors[0]

    def test_partial_timeout_result_is_error(
        self, tmp_path: Path, monkeypatch,
    ):
        # runner returns partial matches + timeout error, rc=-1:
        # must classify error even though matches exist.
        self._patch(
            monkeypatch,
            _FakeSpatchResult(
                matches=[_FakeMatch(7)],
                errors=["Timeout after 120s (partial output captured)"],
                returncode=-1,
            ),
        )
        r = self._run(self._target(tmp_path))
        assert r.outcome == "error"

    def test_runner_exception_is_error(self, tmp_path: Path, monkeypatch):
        self._patch(monkeypatch, exc=RuntimeError("spatch blew up"))
        r = self._run(self._target(tmp_path))
        assert r.outcome == "error"
        assert "spatch blew up" in r.errors[0]

    def test_line_range_filters_matches(self, tmp_path: Path, monkeypatch):
        self._patch(
            monkeypatch,
            _FakeSpatchResult(matches=[_FakeMatch(7), _FakeMatch(90)]),
        )
        r = self._run(
            self._target(tmp_path), line_start=1, line_end=20,
        )
        assert r.outcome == "confirmed"
        assert len(r.matches) == 1

    def test_temp_rule_cleaned_up(self, tmp_path: Path, monkeypatch):
        import packages.coccinelle.runner as runner_mod
        seen = {}

        def fake_run_rule(target, rule, **kw):
            seen["rule"] = Path(rule)
            return _FakeSpatchResult()

        monkeypatch.setattr(runner_mod, "run_rule", fake_run_rule)
        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        self._run(self._target(tmp_path))
        assert not seen["rule"].exists()


# ── live spatch: guarded-fixture negative controls ───────────────────


_LIVE_CASES = (
    (
        "use_after_free",
        "use-after-free of `buf` after free",
        "uaf_bad.c", "uaf_guarded.c",
    ),
    (
        "double_free",
        "double free of `buf` on the error path",
        "double_free_bad.c", "double_free_guarded.c",
    ),
    (
        "double_fetch",
        "double fetch from `uptr` after validation",
        "double_fetch_bad.c", "double_fetch_guarded.c",
    ),
    (
        "unchecked_return",
        "return value of malloc dereferenced unchecked",
        "unchecked_return_bad.c", "unchecked_return_guarded.c",
    ),
)


@pytest.mark.skipif(
    shutil.which("spatch") is None, reason="spatch not installed",
)
class TestFixturesLive:
    """Each template must match its bad fixture and — the negative
    control — must NOT match the correctly-guarded fixture."""

    def _sweep(self, filename, hypothesis, template):
        return run_flow_cocci_sweep(
            target_path=FIXTURES,
            file_path=filename,
            function_name="",
            hypothesis=hypothesis,
            template=template,
        )

    @pytest.mark.parametrize(
        "template,hyp,bad,guarded", _LIVE_CASES,
        ids=[c[0] for c in _LIVE_CASES],
    )
    def test_bad_fixture_confirms(self, template, hyp, bad, guarded):
        r = self._sweep(bad, hyp, template)
        assert r.outcome == "confirmed", (r.outcome, r.errors, r.details)
        assert r.matches

    @pytest.mark.parametrize(
        "template,hyp,bad,guarded", _LIVE_CASES,
        ids=[c[0] for c in _LIVE_CASES],
    )
    def test_guarded_fixture_refutes(self, template, hyp, bad, guarded):
        r = self._sweep(guarded, hyp, template)
        assert r.outcome == "refuted", (r.outcome, r.errors, r.matches)

    def test_uaf_matches_all_three_deref_forms(self):
        r = self._sweep(
            "uaf_bad.c", "use-after-free of `buf`", "use_after_free",
        )
        lines = sorted(m["line"] for m in r.matches)
        assert len(lines) == 3
