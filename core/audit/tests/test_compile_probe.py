"""Compiler-channel spot-checks — core/audit/compile_probe.py.

Fully hermetic: the toolchain probe and the sandboxed compiler
invocation are stubbed; generated probe sources are recorded and
canned success / assert-failure / unrelated-error outcomes drive the
three-step protocol.  Compile success/failure is the verdict — no
diagnostic parsing decides anything.
"""

from __future__ import annotations

import json
import subprocess
import types
from pathlib import Path

import pytest

import core.audit.compile_probe as cp
from core.audit.compile_probe import (
    CompileProbeResult,
    ProbeBudget,
    compile_probe_question,
    generate_probe_source,
    parse_probe_claim,
    probe_receipt,
)

# ------------------------------------------------------------------
# Claim parsing + sanitisation
# ------------------------------------------------------------------


class TestParseProbeClaim:
    def test_plain_identifier(self) -> None:
        assert parse_probe_claim("Is MAX_BUF 4096?") == ("MAX_BUF", "4096")

    def test_equals_form(self) -> None:
        assert parse_probe_claim(
            "Does STATE_DONE equal 3?",
        ) == ("STATE_DONE", "3")

    def test_hex_value(self) -> None:
        assert parse_probe_claim("Is FLAG_MASK 0xFF00?") == (
            "FLAG_MASK", "0xFF00",
        )

    def test_sizeof(self) -> None:
        assert parse_probe_claim(
            "Is sizeof(struct foo) 64 on this target?",
        ) == ("sizeof(struct foo)", "64")

    def test_offsetof(self) -> None:
        assert parse_probe_claim(
            "Is offsetof(struct foo, len) == 8?",
        ) == ("offsetof(struct foo, len)", "8")

    def test_no_value_claim(self) -> None:
        assert parse_probe_claim(
            "Does parse_config validate input?",
        ) is None

    def test_injection_rejected(self) -> None:
        assert parse_probe_claim(
            'Is MAX_BUF; system("x") 4?',
        ) != ('MAX_BUF; system("x")', "4")
        assert parse_probe_claim('Is `X"` 4?') is None

    def test_overlong_expression_rejected(self) -> None:
        assert parse_probe_claim(
            f"Is sizeof(struct {'a' * 200}) 64?",
        ) is None


class TestGenerateProbeSource:
    def test_claim_tu_shape(self) -> None:
        src = generate_probe_source(
            Path("/repo/inc/limits.h"), "MAX_BUF", "4096", "c",
        )
        assert '#include "/repo/inc/limits.h"' in src
        assert (
            '_Static_assert((MAX_BUF) == (4096), "RAPTOR_STUDY_PROBE");'
            in src
        )

    def test_cpp_uses_static_assert(self) -> None:
        src = generate_probe_source(
            Path("/repo/a.hpp"), "kLimit", "8", "c++",
        )
        assert 'static_assert((kLimit) == (8), "RAPTOR_STUDY_PROBE");' in src
        assert "_Static_assert" not in src

    def test_baseline_has_no_assert(self) -> None:
        src = generate_probe_source(Path("/repo/a.h"), None, None, "c")
        assert "assert" not in src

    def test_tautology(self) -> None:
        src = generate_probe_source(Path("/repo/a.h"), "X", None, "c")
        assert "_Static_assert((X) == (X)" in src


# ------------------------------------------------------------------
# Compile stub harness
# ------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _toolchain(monkeypatch):
    cp._reset_toolchain_cache()
    monkeypatch.setattr(
        cp, "_find_toolchain",
        lambda lang: ("/usr/bin/cc", "cc (test) 13.2.0"),
    )
    yield
    cp._reset_toolchain_cache()


class FakeCompiler:
    """Canned per-step outcomes keyed by TU shape.

    Steps are recognised structurally: no assert → baseline;
    ``== (EXPR)`` tautology; otherwise the claim TU.  Records every
    generated probe source.
    """

    ASSERT_FAIL_DIAG = (
        "probe.c:3:1: error: static assertion failed: "
        '"RAPTOR_STUDY_PROBE"'
    )
    UNRELATED_DIAG = (
        "inc/limits.h:1:10: fatal error: config.h: "
        "No such file or directory"
    )

    def __init__(self, *, baseline_ok=True, tautology_ok=True,
                 claim_ok=True, raise_timeout=False):
        self.baseline_ok = baseline_ok
        self.tautology_ok = tautology_ok
        self.claim_ok = claim_ok
        self.raise_timeout = raise_timeout
        self.sources: list[str] = []
        self.cmds: list[list[str]] = []

    def __call__(self, cmd, **kwargs):
        if self.raise_timeout:
            raise subprocess.TimeoutExpired(cmd, 30)
        self.cmds.append(list(cmd))
        tu = Path(cmd[-1]).read_text()
        self.sources.append(tu)
        if "assert" not in tu:
            ok, diag = self.baseline_ok, (
                "" if self.baseline_ok else self.UNRELATED_DIAG
            )
        else:
            # tautology: assert((X) == (X))
            import re
            m = re.search(r"assert\(\((.+?)\) == \((.+?)\),", tu)
            if m and m.group(1) == m.group(2):
                ok, diag = self.tautology_ok, (
                    "" if self.tautology_ok
                    else "probe.c:3:16: error: expression in static "
                         "assertion is not constant"
                )
            else:
                ok, diag = self.claim_ok, (
                    "" if self.claim_ok else self.ASSERT_FAIL_DIAG
                )
        return types.SimpleNamespace(
            returncode=0 if ok else 1, stderr=diag, stdout="",
        )


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    (tmp_path / "inc").mkdir()
    (tmp_path / "inc" / "limits.h").write_text(
        "#define BASE 1024\n"
        "#define SLOT 768\n"
        "#define MAX_BUF (BASE + 4*SLOT)\n"
        "enum state { STATE_INIT, STATE_RUN, STATE_HOLD, STATE_DONE };\n"
        "struct foo { long a; long b; };\n",
    )
    return tmp_path


def _items() -> list[dict]:
    return [
        {"name": "MAX_BUF", "kind": "macro", "file": "inc/limits.h",
         "line": 3, "definition": "#define MAX_BUF (BASE + 4*SLOT)"},
        {"name": "STATE_DONE", "kind": "flag_enum",
         "file": "inc/limits.h", "line": 4,
         "definition": "enum state { STATE_INIT, STATE_RUN, "
                       "STATE_HOLD, STATE_DONE };"},
        {"name": "foo", "kind": "struct", "file": "inc/limits.h",
         "line": 5, "definition": "struct foo { long a; long b; };"},
    ]


def _install(monkeypatch, fake: FakeCompiler) -> None:
    import core.sandbox.context as _sbx
    monkeypatch.setattr(_sbx, "run", fake)


# ------------------------------------------------------------------
# Verdicts
# ------------------------------------------------------------------


class TestCompileProbeVerdicts:
    def test_computed_constant_verified(self, monkeypatch, repo) -> None:
        fake = FakeCompiler(claim_ok=True)
        _install(monkeypatch, fake)
        r = compile_probe_question("Is MAX_BUF 4096?", _items(), repo)
        assert r is not None and r.status == "verified"
        assert r.expression == "MAX_BUF"
        assert r.claimed_value == "4096"
        assert r.compiler == "/usr/bin/cc"
        assert "13.2.0" in r.compiler_version
        assert r.probe_sha256
        # three-step protocol ran: baseline, tautology, claim
        assert len(fake.sources) == 3
        assert "assert" not in fake.sources[0]
        assert "(MAX_BUF) == (MAX_BUF)" in fake.sources[1]
        assert "(MAX_BUF) == (4096)" in fake.sources[2]
        # include paths passed as list args, never a shell string
        assert any("-I" in c for c in fake.cmds[0])

    def test_computed_constant_contradicted(
        self, monkeypatch, repo,
    ) -> None:
        fake = FakeCompiler(claim_ok=False)
        _install(monkeypatch, fake)
        r = compile_probe_question("Is MAX_BUF 4095?", _items(), repo)
        assert r.status == "contradicted"
        assert "DOES NOT hold" in r.answer
        assert "static assertion failed" in r.diagnostic_snippet

    def test_enum_auto_value(self, monkeypatch, repo) -> None:
        fake = FakeCompiler(claim_ok=True)
        _install(monkeypatch, fake)
        r = compile_probe_question("Is STATE_DONE 3?", _items(), repo)
        assert r.status == "verified"
        assert "(STATE_DONE) == (3)" in fake.sources[2]

    def test_sizeof_claim(self, monkeypatch, repo) -> None:
        fake = FakeCompiler(claim_ok=True)
        _install(monkeypatch, fake)
        r = compile_probe_question(
            "Is sizeof(struct foo) 16?", _items(), repo,
        )
        assert r.status == "verified"
        assert "(sizeof(struct foo)) == (16)" in fake.sources[2]


class TestGracefulDegradation:
    def test_unrelated_compile_failure_is_unavailable(
        self, monkeypatch, repo,
    ) -> None:
        """A broken baseline (missing config.h) must NEVER become a
        contradiction verdict."""
        fake = FakeCompiler(baseline_ok=False)
        _install(monkeypatch, fake)
        r = compile_probe_question("Is MAX_BUF 4096?", _items(), repo)
        assert r.status == "unavailable"
        assert "does not compile standalone" in r.reason
        assert len(fake.sources) == 1, "must stop after baseline"

    def test_non_constant_expression_is_unavailable(
        self, monkeypatch, repo,
    ) -> None:
        fake = FakeCompiler(tautology_ok=False)
        _install(monkeypatch, fake)
        r = compile_probe_question("Is MAX_BUF 4096?", _items(), repo)
        assert r.status == "unavailable"
        assert "not a compile-time constant" in r.reason
        assert len(fake.sources) == 2, "must stop after tautology"

    def test_no_toolchain(self, monkeypatch, repo) -> None:
        monkeypatch.setattr(cp, "_find_toolchain", lambda lang: None)
        r = compile_probe_question("Is MAX_BUF 4096?", _items(), repo)
        assert r.status == "unavailable"
        assert "no working c compiler" in r.reason

    def test_timeout_is_unavailable(self, monkeypatch, repo) -> None:
        _install(monkeypatch, FakeCompiler(raise_timeout=True))
        r = compile_probe_question("Is MAX_BUF 4096?", _items(), repo)
        assert r.status == "unavailable"
        assert "invocation failed" in r.reason

    def test_probe_cap(self, monkeypatch, repo) -> None:
        fake = FakeCompiler()
        _install(monkeypatch, fake)
        budget = ProbeBudget(remaining=1)
        r1 = compile_probe_question(
            "Is MAX_BUF 4096?", _items(), repo, budget=budget,
        )
        r2 = compile_probe_question(
            "Is STATE_DONE 3?", _items(), repo, budget=budget,
        )
        assert r1.status == "verified"
        assert r2.status == "unavailable"
        assert "probe cap" in r2.reason

    def test_missing_defining_file(self, monkeypatch, tmp_path) -> None:
        _install(monkeypatch, FakeCompiler())
        items = [{"name": "MAX_BUF", "file": "inc/limits.h", "line": 3,
                  "definition": "#define MAX_BUF (X)"}]
        r = compile_probe_question("Is MAX_BUF 4?", items, tmp_path)
        assert r.status == "unavailable"
        assert "not found" in r.reason

    def test_path_escape_rejected(self, monkeypatch, tmp_path) -> None:
        _install(monkeypatch, FakeCompiler())
        outside = tmp_path.parent / "evil.h"
        outside.write_text("#define MAX_BUF 4\n")
        items = [{"name": "MAX_BUF", "file": "../evil.h", "line": 1,
                  "definition": "#define MAX_BUF 4"}]
        r = compile_probe_question("Is MAX_BUF 4?", items, tmp_path)
        assert r.status == "unavailable"
        assert "escapes the source root" in r.reason

    def test_non_c_corpus_returns_none(self, monkeypatch, tmp_path) -> None:
        _install(monkeypatch, FakeCompiler())
        items = [{"name": "MAX_FRAME", "file": "lib.rs", "line": 1,
                  "definition": "pub const MAX_FRAME: usize = A + B;"}]
        assert compile_probe_question(
            "Is MAX_FRAME 4096?", items, tmp_path,
        ) is None

    def test_no_sandbox_is_unavailable(self, monkeypatch, repo) -> None:
        monkeypatch.setattr(cp, "_compile_tu", lambda *a, **kw: None)
        r = compile_probe_question("Is MAX_BUF 4096?", _items(), repo)
        assert r.status == "unavailable"


class TestProbeReceipt:
    def test_mechanical_tier_receipt(self) -> None:
        r = CompileProbeResult(
            status="verified", expression="MAX_BUF",
            claimed_value="4096", compiler="/usr/bin/cc",
            compiler_version="cc (test) 13.2.0",
            probe_sha256="abc123def4567890",
            include_file="inc/limits.h",
        )
        receipt = probe_receipt(r, line=3)
        assert receipt.tier == "mechanical"
        assert receipt.verified
        assert receipt.sha256 == "abc123def4567890"
        assert "cc (test) 13.2.0" in receipt.note
        assert "(MAX_BUF) == (4096)" in receipt.quote

    def test_contradiction_receipt_carries_diag(self) -> None:
        r = CompileProbeResult(
            status="contradicted", expression="MAX_BUF",
            claimed_value="4095", compiler="/usr/bin/cc",
            compiler_version="cc 13",
            diagnostic_snippet="error: static assertion failed",
            include_file="inc/limits.h",
        )
        receipt = probe_receipt(r)
        assert "static assertion failed" in receipt.note


# ------------------------------------------------------------------
# Consumer integration (tier + receipt threading + override logging
# + prior-state preservation)
# ------------------------------------------------------------------


class TestConsumerIntegration:
    def _seed(self, tmp_path, question):
        from core.concepts.audit_bridge import queue_reading_list_item
        queue_reading_list_item(
            tmp_path, question=question,
            source_file="src/main.c", source_function="handler",
        )

    def _corpus(self, tmp_path):
        sl = tmp_path / "study-list.json"
        sl.write_text(json.dumps({
            "target": str(tmp_path), "source_root": str(tmp_path),
            "items": [{
                "name": "MAX_BUF", "kind": "macro",
                "file": "inc/limits.h", "line": 3,
                "definition": "#define MAX_BUF (BASE + 4*SLOT)",
            }],
        }))
        return sl

    def _mark(self, tmp_path, question, dm=None, budget=None):
        from core.audit.orchestrator import (
            StudyRequest,
            _mark_batch_reading_list,
        )
        req = StudyRequest(
            question=question, source_file="src/main.c",
            source_function="handler",
        )
        return _mark_batch_reading_list(
            tmp_path, [req], dm, {},
            study_list_path=self._corpus(tmp_path),
            source_root=tmp_path,
            probe_budget=budget,
        )

    def test_verified_probe_resolves_with_receipt(
        self, tmp_path, monkeypatch,
    ) -> None:
        import core.audit.orchestrator as _orch
        monkeypatch.setattr(
            _orch, "_record_study_scorecard", lambda *a: None,
        )
        monkeypatch.setattr(
            cp, "compile_probe_question",
            lambda q, items, root, budget=None: CompileProbeResult(
                status="verified", expression="MAX_BUF",
                claimed_value="4096",
                answer="compile-probe: (MAX_BUF) == 4096 holds",
                compiler="/usr/bin/cc", compiler_version="cc 13",
                probe_sha256="feedface00000000",
                include_file="inc/limits.h",
            ),
        )
        q = "Is MAX_BUF 4096?"
        self._seed(tmp_path, q)
        eligible = self._mark(tmp_path, q)
        rl = json.loads((tmp_path / "reading-list.json").read_text())
        assert rl["items"][0]["resolved"]
        assert rl["items"][0]["resolved_concept_id"] == (
            "compileprobe:MAX_BUF"
        )
        assert "src/main.c:handler" in eligible
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["tier"] == "mechanical"
        assert answers[0]["receipt"]["sha256"] == "feedface00000000"
        assert "compile-probe" in answers[0]["receipt"]["note"]

    def test_contradicted_probe_overrides_llm_summary(
        self, tmp_path, monkeypatch,
    ) -> None:
        import core.audit.orchestrator as _orch
        monkeypatch.setattr(
            _orch, "_record_study_scorecard", lambda *a: None,
        )
        monkeypatch.setattr(
            cp, "compile_probe_question",
            lambda q, items, root, budget=None: CompileProbeResult(
                status="contradicted", expression="MAX_BUF",
                claimed_value="4096",
                answer="compile-probe: (MAX_BUF) == 4096 DOES NOT hold",
                compiler="/usr/bin/cc", compiler_version="cc 13",
                probe_sha256="feedface00000000",
                diagnostic_snippet="static assertion failed",
                include_file="inc/limits.h",
            ),
        )
        q = "Is MAX_BUF 4096?"
        self._seed(tmp_path, q)
        # A verbatim LLM concept claims the same identifier — the
        # contradiction must displace it (non-actionable), recorded
        # as an override with the compiler receipt.
        dm = {"concepts": [{"id": "max_buf_limit",
                            "provenance": "verbatim",
                            "receipt": {"verified": True}}],
              "invariants": [], "contracts": []}
        self._mark(tmp_path, q, dm=dm)
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["spot_check_override"] is True
        assert "DOES NOT hold" in answers[0]["answer"]
        assert answers[0]["tier"] == "mechanical"
        # resolved mechanically — the LLM summary never resolves it
        assert answers[0]["resolved_concept_id"].startswith(
            "compileprobe:",
        )

    def test_unavailable_probe_keeps_prior_state_with_note(
        self, tmp_path, monkeypatch,
    ) -> None:
        monkeypatch.setattr(
            cp, "compile_probe_question",
            lambda q, items, root, budget=None: CompileProbeResult(
                status="unavailable", expression="MAX_BUF",
                claimed_value="4096",
                reason="no working c compiler on PATH",
            ),
        )
        q = "Is MAX_BUF 4096?"
        self._seed(tmp_path, q)
        eligible = self._mark(tmp_path, q)
        rl = json.loads((tmp_path / "reading-list.json").read_text())
        item = rl["items"][0]
        assert not item["resolved"]
        assert not item["unresolvable"], (
            "unavailable probe must not fabricate a verdict"
        )
        assert eligible == set()
        answers = json.loads(
            (tmp_path / "study-answers.json").read_text())["answers"]
        assert answers[0]["status"] == "pending"
        assert answers[0]["probe_note"].startswith(
            "compile-probe unavailable/failed:",
        )


# ------------------------------------------------------------------
# Determine-value mode (bisection; config-gated, default off)
# ------------------------------------------------------------------


class TestParseDetermineExpression:
    def test_value_of_identifier(self) -> None:
        assert cp.parse_determine_expression(
            "What is the value of MAX_BUF?",
        ) == "MAX_BUF"

    def test_evaluate_to(self) -> None:
        assert cp.parse_determine_expression(
            "What does STATE_DONE evaluate to?",
        ) == "STATE_DONE"

    def test_builtin(self) -> None:
        assert cp.parse_determine_expression(
            "What is sizeof(struct foo) on this target?",
        ) == "sizeof(struct foo)"

    def test_claim_shaped_defers_to_claim_probe(self) -> None:
        assert cp.parse_determine_expression("Is MAX_BUF 4096?") is None

    def test_non_constant_question(self) -> None:
        assert cp.parse_determine_expression(
            "What does parse_config do with its input?",
        ) is None

    def test_injection_rejected(self) -> None:
        # The identifier capture can only yield \w+ names; the builtin
        # capture admits wider text, so the allowlist must reject it.
        assert cp.parse_determine_expression(
            "What is sizeof(struct foo; system I mean)?",
        ) is None
        # Quoted-identifier extraction strips down to the bare (safe)
        # name — hostile quoting never reaches the TU.
        assert cp.parse_determine_expression(
            'What is the value of `X"`?',
        ) == "X"


class EvalFakeCompiler:
    """Fake compiler that EVALUATES probe assertions against a fixed
    integer value, so the bisection walks a realistic verdict
    surface.  ``lie_in_search`` inverts every ``<=`` answer to prove
    the final equality probe is the only verdict channel."""

    def __init__(self, value: int, *, lie_in_search: bool = False,
                 sign_probes_ill_formed: bool = False):
        self.value = value
        self.lie_in_search = lie_in_search
        self.sign_probes_ill_formed = sign_probes_ill_formed
        self.sources: list[str] = []

    @staticmethod
    def _parse_literal(text: str) -> int | None:
        text = text.strip().rstrip(";").strip()
        text = text.rstrip(")").strip().lstrip("(").strip()
        if text == "-9223372036854775807LL - 1":
            return -(2 ** 63)
        try:
            return int(text.rstrip("UL").rstrip("ul"))
        except ValueError:
            return None  # not a literal (tautology rhs)

    def __call__(self, cmd, **kwargs):
        import re as _re

        tu = Path(cmd[-1]).read_text()
        self.sources.append(tu)
        ok = True
        if "assert" in tu:
            body = _re.search(r'assert\((.*), "RAPTOR', tu, _re.S)
            expr = (body.group(1) if body else "").strip()
            if _re.search(r"\) >= 0\)", expr):
                ok = (not self.sign_probes_ill_formed
                      and self.value >= 0)
            elif _re.search(r"\) < 0\)", expr):
                ok = (not self.sign_probes_ill_formed
                      and self.value < 0)
            elif "<=" in expr:
                lit = self._parse_literal(expr.split("<=", 1)[1])
                assert lit is not None, expr
                ok = self.value <= lit
                if self.lie_in_search:
                    ok = not ok
            elif "==" in expr:
                lit = self._parse_literal(expr.split("==", 1)[1])
                # tautology TU rhs is the expression itself
                ok = True if lit is None else self.value == lit
        return types.SimpleNamespace(
            returncode=0 if ok else 1,
            stderr="" if ok else "static assertion failed", stdout="",
        )


class TestDetermineProbe:
    def _run(self, monkeypatch, repo, value, question=None, **kw):
        fake = EvalFakeCompiler(value, **kw)
        _install(monkeypatch, fake)
        r = cp.determine_probe_question(
            question or "What is the value of MAX_BUF?",
            _items(), repo,
        )
        return r, fake

    def test_positive_value_determined(self, monkeypatch, repo) -> None:
        r, fake = self._run(monkeypatch, repo, 4096)
        assert r is not None and r.status == "verified"
        assert r.claimed_value == "4096"
        assert "determine" in r.answer and "== 4096" in r.answer
        assert r.probe_sha256
        # final TU asserts equality with the ULL literal
        assert "(MAX_BUF) == 4096ULL" in fake.sources[-1]

    def test_zero(self, monkeypatch, repo) -> None:
        r, _ = self._run(monkeypatch, repo, 0)
        assert r.status == "verified" and r.claimed_value == "0"

    def test_negative_value_determined(self, monkeypatch, repo) -> None:
        r, fake = self._run(monkeypatch, repo, -5)
        assert r.status == "verified" and r.claimed_value == "-5"
        assert "(-5LL)" in fake.sources[-1]

    def test_large_unsigned_value(self, monkeypatch, repo) -> None:
        r, _ = self._run(monkeypatch, repo, 2 ** 63 + 17)
        assert r.status == "verified"
        assert r.claimed_value == str(2 ** 63 + 17)

    def test_int64_min(self, monkeypatch, repo) -> None:
        r, _ = self._run(monkeypatch, repo, -(2 ** 63))
        assert r.status == "verified"
        assert r.claimed_value == str(-(2 ** 63))

    def test_search_lies_never_produce_a_verdict(
        self, monkeypatch, repo,
    ) -> None:
        # A misled bisection converges on a wrong candidate; the
        # equality probe fails and the result is unavailable — the
        # search is never trusted.
        r, _ = self._run(monkeypatch, repo, 4096, lie_in_search=True)
        assert r.status == "unavailable"
        assert "no verdict" in r.reason

    def test_ill_formed_comparisons_bail_before_search(
        self, monkeypatch, repo,
    ) -> None:
        r, fake = self._run(
            monkeypatch, repo, 7, sign_probes_ill_formed=True,
        )
        assert r.status == "unavailable"
        assert "sign probes" in r.reason
        # baseline + tautology + two sign probes only — no bisection
        assert len(fake.sources) == 4

    def test_budget_cap(self, monkeypatch, repo) -> None:
        fake = EvalFakeCompiler(4096)
        _install(monkeypatch, fake)
        budget = ProbeBudget(remaining=0)
        r = cp.determine_probe_question(
            "What is the value of MAX_BUF?", _items(), repo,
            budget=budget,
        )
        assert r.status == "unavailable"
        assert "cap" in r.reason
        assert fake.sources == []

    def test_claim_shaped_question_returns_none(
        self, monkeypatch, repo,
    ) -> None:
        fake = EvalFakeCompiler(4096)
        _install(monkeypatch, fake)
        assert cp.determine_probe_question(
            "Is MAX_BUF 4096?", _items(), repo,
        ) is None

    def test_receipt_is_mechanical(self, monkeypatch, repo) -> None:
        r, _ = self._run(monkeypatch, repo, 4096)
        receipt = probe_receipt(r)
        assert receipt.verified is True
        assert receipt.tier == "mechanical"
        assert receipt.file == "inc/limits.h"


class TestDetermineGateDefaultOff:
    def test_orchestrator_config_defaults_off(self) -> None:
        from core.audit.orchestrator import OrchestratorConfig

        cfg = OrchestratorConfig(target_path=Path("."), out_dir=Path("."))
        assert cfg.probe_determine_value is False

    def test_pipeline_opts_default_off(self) -> None:
        from core.audit.pipeline import AuditPipelineOpts

        assert AuditPipelineOpts().probe_determine_value is False


# ------------------------------------------------------------------
# Include-path splice safety
# ------------------------------------------------------------------


class TestIncludePathSpliceSafety:
    """Target file names are attacker-controlled; a quote or newline
    in the name would break out of the probe TU's `#include "..."`
    line. Unsafe names make the probe unavailable — never spliced."""

    def test_safe_names_pass(self) -> None:
        assert cp.include_path_is_safe(Path("/repo/inc/limits.h"))
        assert cp.include_path_is_safe(Path("/repo/weird name (v2).h"))

    @pytest.mark.parametrize("bad", [
        'inc/e"vil.h',
        "inc/back\\slash.h",
        "inc/ctrl\x01.h",
    ])
    def test_unsafe_names_rejected(self, bad: str) -> None:
        assert not cp.include_path_is_safe(Path("/repo") / bad)

    def test_hostile_filename_probe_unavailable(
        self, monkeypatch, repo,
    ) -> None:
        fake = FakeCompiler()
        _install(monkeypatch, fake)
        hostile = 'inc/e"vil.h'
        (repo / hostile).write_text("#define MAX_BUF 4096\n")
        items = [{
            "name": "MAX_BUF", "kind": "macro", "file": hostile,
            "line": 1, "definition": "#define MAX_BUF 4096",
        }]
        r = compile_probe_question("Is MAX_BUF 4096?", items, repo)
        assert r is not None
        assert r.status == "unavailable"
        assert "#include" in (r.reason or "")
        # No TU was ever generated with the hostile path.
        assert not fake.sources


# ------------------------------------------------------------------
# Symlinked source roots (shared fixture farms)
# ------------------------------------------------------------------


class RecordingCompiler(FakeCompiler):
    """FakeCompiler that also records the sandbox kwargs per call."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.kwargs: list[dict] = []

    def __call__(self, cmd, **kwargs):
        self.kwargs.append(dict(kwargs))
        return super().__call__(cmd, **kwargs)


class TestSymlinkedSourceRoot:
    """The #include path and the sandbox mount target must agree.

    A run whose fixture directory is a symlink into another tree used
    to build the include path via ``.resolve()`` (following the link)
    while handing the UNRESOLVED root to the sandbox as its mount
    target — inside the mount namespace the resolved path does not
    exist, so every baseline compile failed "defining file does not
    compile standalone" on a file that plainly exists.
    """

    @pytest.fixture()
    def linked(self, tmp_path: Path) -> Path:
        real = tmp_path / "real"
        (real / "inc").mkdir(parents=True)
        (real / "inc" / "limits.h").write_text(
            "#define BASE 1024\n"
            "#define SLOT 768\n"
            "#define MAX_BUF (BASE + 4*SLOT)\n",
        )
        farm = tmp_path / "farm"
        farm.mkdir()
        link = farm / "root"
        link.symlink_to(real)
        return link

    def test_probe_paths_agree_under_symlinked_root(
        self, monkeypatch, linked: Path,
    ) -> None:
        fake = RecordingCompiler()
        _install(monkeypatch, fake)
        items = [{
            "name": "MAX_BUF", "kind": "macro", "file": "inc/limits.h",
            "line": 3, "definition": "#define MAX_BUF (BASE + 4*SLOT)",
        }]
        r = compile_probe_question("Is MAX_BUF 4096?", items, linked)
        assert r is not None
        assert r.status in ("verified", "contradicted")
        resolved_root = str(linked.resolve())
        for tu in fake.sources:
            for line in tu.splitlines():
                if line.startswith('#include "'):
                    inc = line.split('"')[1]
                    assert inc.startswith(resolved_root), (
                        f"include path {inc} not under the resolved "
                        f"root {resolved_root}"
                    )
        for kw in fake.kwargs:
            assert kw.get("target") == resolved_root, (
                "sandbox mount target must be the SAME canonical root "
                "the #include path was built from"
            )

    def test_determine_paths_agree_under_symlinked_root(
        self, monkeypatch, linked: Path,
    ) -> None:
        # determine mode shares the path plumbing; a lightweight probe
        # that dies at the sign check still exercises baseline +
        # tautology with the resolved pair.
        fake = RecordingCompiler(claim_ok=False)
        _install(monkeypatch, fake)
        items = [{
            "name": "MAX_BUF", "kind": "macro", "file": "inc/limits.h",
            "line": 3, "definition": "#define MAX_BUF (BASE + 4*SLOT)",
        }]
        cp.determine_probe_question(
            "What is the value of MAX_BUF?", items, linked,
        )
        resolved_root = str(linked.resolve())
        assert fake.kwargs, "probe never reached a sandboxed compile"
        for kw in fake.kwargs:
            assert kw.get("target") == resolved_root
