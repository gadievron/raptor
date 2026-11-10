"""Both directions of the live transport/product partition
(``core.audit.tests._live_transport``) — HERMETIC (no engines, no
sandbox), so the guards' own contracts are enforced on every host,
including the ones where the live legs skip.

Three layers per channel, the test_sanwit_live idiom:

* direction tests — a transport-shaped degradation skips a REAL live
  test body; a product-shaped failure on that same body stays a hard
  failure (``_fail_on_skip``: an unexpected skip is itself a failure,
  because ``pytest.raises`` re-raises ``Skipped``);
* minted-identity pins — the reason strings the guards key on are the
  ones the product code actually produces (anti-drift);
* structural fences — per touched file, the exact set of functions
  routing through the guarded runners is enumerated; adding a live
  call site without the guard (or reverting one to the raw runner)
  must be a deliberate decision, never a silent gap.
"""

from __future__ import annotations

import ast
import errno
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest

from core.audit import preprocessor_view as pv
from core.audit.expanded_semgrep import ExpandedRuleResult
from core.audit.sweep import SweepResult
from core.audit.tests._live_transport import (
    COMPILER_TRANSPORT_RE,
    CPP_TRANSPORT_RE,
    EXPANDED_VIEW_TRANSPORT_RE,
    SEMGREP_TRANSPORT_RE,
    expand_translation_unit_guarded,
    run_compiler_analyzer_sweep_guarded,
    run_pinned_subprocess,
    run_semgrep_sweep_guarded,
    skip_if_compiler_transport_degraded,
    skip_if_cpp_transport_degraded,
    skip_if_expanded_view_transport_degraded,
    skip_if_semgrep_transport_degraded,
    skip_unless_cpp_carries_probe,
    skip_unless_semgrep_carries_probe,
)

_TESTS_DIR = Path(__file__).resolve().parent


def _fail_on_skip(call: Callable[[], None]) -> None:
    """No-skip-direction fence: an unexpected ``pytest.skip`` raised
    by the code under test would otherwise propagate as SKIPPED —
    straight through ``pytest.raises``, which re-raises it — and the
    test would pass silently, the exact masking this file exists to
    rule out. An unexpected skip is a hard failure."""
    try:
        call()
    except pytest.skip.Exception as exc:
        pytest.fail(f"guard skipped a product-visible shape: {exc}")


def _semgrep_error(
    reason: str, *, rule_id: str | None = "engine/semgrep/rules/x.yaml",
) -> SweepResult:
    return SweepResult(
        tool="semgrep", file_path="app.c", function_name="f",
        outcome="error", errors=[reason], rule_id=rule_id,
    )


# ---------------------------------------------------------------------
# semgrep channel — guard directions
# ---------------------------------------------------------------------


class TestSemgrepGuardDirections:
    @pytest.mark.parametrize("reason", [
        "Timeout after 900s",
        "Timeout after 45s",
        "[Errno 11] Resource temporarily unavailable",
        "[Errno 12] Cannot allocate memory",
        "[Errno 2] No such file or directory: 'semgrep'",
        "semgrep is not installed (semgrep binary not found on PATH)",
        "core.sandbox unavailable — refusing to run semgrep on the "
        "target outside a sandbox",
        "semgrep exited with code -9",
        "semgrep exited with code -11: some stderr tail",
    ])
    def test_transport_reasons_skip(self, reason: str) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_semgrep_transport_degraded(_semgrep_error(reason))

    def test_sweep_availability_arm_skips(self) -> None:
        # run_semgrep_sweep's own pre-spawn arm: rule_id=None, exact
        # reason.
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_semgrep_transport_degraded(
                _semgrep_error("semgrep not installed", rule_id=None),
            )

    @pytest.mark.parametrize("reason", [
        # The engine's own verdicts on the input — product territory.
        "semgrep exited with code 2: invalid rule schema",
        "semgrep exited with code 7",
        "SemgrepError: invalid pattern",
        "Fatal: rule did not parse",
        "semgrep failed to parse app.c (reported in files_failed)",
        # Prefix/suffix look-alikes the anchoring must refuse.
        "Timeout after 900s\n",
        "Timeout after 900s of deliberation",
        "semgrep exited with code -9x",
        "semgrep exited with code 19",
        # Bracket-prefixed but NOT the spawn arm's "[Errno N] " shape —
        # the arm keys on the errno spelling, never on a bare bracket.
        "[analyzer] rule crashed",
    ])
    def test_product_error_reasons_do_not_skip(self, reason: str) -> None:
        _fail_on_skip(
            lambda: skip_if_semgrep_transport_degraded(
                _semgrep_error(reason),
            ),
        )

    def test_rule_id_keying_blocks_broad_except_leaks(self) -> None:
        # The sweep's closing ``except Exception`` lands with
        # rule_id=None and str(exc) — an OSError from PRODUCT code
        # (not the engine spawn) is shaped "[Errno N] ..." there and
        # must stay a hard failure.
        _fail_on_skip(
            lambda: skip_if_semgrep_transport_degraded(
                _semgrep_error(
                    "[Errno 2] No such file or directory: 'x.yaml'",
                    rule_id=None,
                ),
            ),
        )
        # And the exact availability text with a TRUTHY rule_id is
        # not the arm that mints it — no skip.
        _fail_on_skip(
            lambda: skip_if_semgrep_transport_degraded(
                _semgrep_error("semgrep not installed"),
            ),
        )

    def test_availability_arm_is_exact_match_only(self) -> None:
        # The rule_id=None arm keys on the EXACT pre-spawn spelling:
        # the sweep's closing broad except lands on the same identity
        # with arbitrary str(exc), so a prefix-extended spelling must
        # stay a hard failure.
        _fail_on_skip(
            lambda: skip_if_semgrep_transport_degraded(
                _semgrep_error(
                    "semgrep not installed correctly", rule_id=None,
                ),
            ),
        )

    def test_multi_error_results_do_not_skip(self) -> None:
        res = _semgrep_error("Timeout after 900s")
        res.errors.append("Fatal: rule did not parse")
        _fail_on_skip(lambda: skip_if_semgrep_transport_degraded(res))

    def test_non_error_outcomes_never_skip(self) -> None:
        # Full-identity keying: a classified verdict whose match text
        # merely QUOTES a transport phrase passes through.
        res = SweepResult(
            tool="semgrep", file_path="app.c", function_name="f",
            outcome="confirmed", errors=["Timeout after 900s"],
            rule_id="engine/semgrep/rules/x.yaml",
        )
        _fail_on_skip(lambda: skip_if_semgrep_transport_degraded(res))

    def test_other_tools_never_skip(self) -> None:
        res = SweepResult(
            tool="coccinelle", file_path="app.c", function_name="f",
            outcome="error", errors=["Timeout after 900s"],
            rule_id="x.cocci",
        )
        _fail_on_skip(lambda: skip_if_semgrep_transport_degraded(res))


# ---------------------------------------------------------------------
# semgrep channel — minted-identity pins (real runner + real sweep,
# only the child spawn is injected)
# ---------------------------------------------------------------------


def _raising_runner(exc: BaseException):
    def _runner(cmd, **kwargs):  # noqa: ANN001, ANN003 — subprocess.run signature
        raise exc
    return _runner


def _rc_runner(returncode: int):
    def _runner(cmd, **kwargs):  # noqa: ANN001, ANN003 — subprocess.run signature
        return subprocess.CompletedProcess(cmd, returncode, "", "")
    return _runner


class TestSemgrepMintedIdentities:
    """The regex arms match what the runner ACTUALLY mints — pinned by
    running the real ``run_rule`` with an injected child spawn."""

    def _minted(self, monkeypatch: pytest.MonkeyPatch, runner, *,
                expected_error_count: int = 1) -> list[str]:
        import packages.semgrep.runner as runner_mod

        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        result = runner_mod.run_rule(
            Path("/nonexistent-target"), "rules/x.yaml",
            subprocess_runner=runner,
        )
        assert result.returncode == -1 or result.returncode not in (0, 1)
        assert len(result.errors) == expected_error_count
        return result.errors

    def test_timeout_identity(self, monkeypatch) -> None:
        errors = self._minted(
            monkeypatch,
            _raising_runner(subprocess.TimeoutExpired(["semgrep"], 900)),
        )
        assert SEMGREP_TRANSPORT_RE.match(errors[0]), errors

    def test_spawn_oserror_identity(self, monkeypatch) -> None:
        errors = self._minted(
            monkeypatch,
            _raising_runner(OSError(errno.EAGAIN, "Resource temporarily unavailable")),
        )
        assert SEMGREP_TRANSPORT_RE.match(errors[0]), errors

    def test_signal_kill_identity(self, monkeypatch) -> None:
        errors = self._minted(monkeypatch, _rc_runner(-9), expected_error_count=2)
        assert errors[1] == "semgrep produced empty SARIF output"
        assert SEMGREP_TRANSPORT_RE.match(errors[0]), errors

    def test_positive_exit_stays_product(self, monkeypatch) -> None:
        errors = self._minted(monkeypatch, _rc_runner(7), expected_error_count=2)
        assert errors[1] == "semgrep produced empty SARIF output"
        assert not SEMGREP_TRANSPORT_RE.match(errors[0]), errors

    def test_not_installed_identity(self, monkeypatch) -> None:
        import packages.semgrep.runner as runner_mod

        monkeypatch.setattr(runner_mod, "is_available", lambda: False)
        result = runner_mod.run_rule(Path("/tmp"), "rules/x.yaml")
        assert SEMGREP_TRANSPORT_RE.match(result.errors[0]), result.errors

    def test_sandbox_refusal_identity(self) -> None:
        from packages.semgrep.runner import _SANDBOX_REFUSAL

        assert SEMGREP_TRANSPORT_RE.match(_SANDBOX_REFUSAL)

    def test_sweep_availability_arm_matches_guard(
        self, monkeypatch, tmp_path,
    ) -> None:
        # Full chain: the sweep's pre-spawn arm rides rule_id=None and
        # the guard converts it to a skip through the guarded runner.
        import packages.semgrep.runner as runner_mod

        (tmp_path / "app.c").write_text("void f(void) {}\n")
        monkeypatch.setattr(runner_mod, "is_available", lambda: False)
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            run_semgrep_sweep_guarded(
                target_path=tmp_path, file_path="app.c",
                function_name="f", rule_config="rules/x.yaml",
            )


def _stub_semgrep_runner(
    monkeypatch: pytest.MonkeyPatch, **result_kwargs,
) -> None:
    """Pin the runner seam to a fixed result: the sweep grades a REAL
    engine outcome shape without any engine present."""
    import packages.semgrep.runner as runner_mod
    from packages.semgrep.models import SemgrepResult

    monkeypatch.setattr(runner_mod, "is_available", lambda: True)
    monkeypatch.setattr(
        runner_mod, "run_rule",
        lambda *a, **k: SemgrepResult(**result_kwargs),
    )


class TestSemgrepDirectionsThroughLiveBody:
    """A REAL live test body (test_encoding_rules_c's mode
    adjudication) routed through an injected transport outcome — the
    guard converts a degraded runtime to a skip and leaves a product
    misclassification a hard failure."""

    def _run_live_body(self, tmp_path: Path) -> None:
        from core.audit.tests.test_encoding_rules_c import (
            _CRLF_CASES,
            TestCrlfRuleLive,
        )

        name, snippet, should_fire = _CRLF_CASES[0]
        TestCrlfRuleLive().test_mode(name, snippet, should_fire, tmp_path)

    def test_degraded_transport_skips_the_live_assertions(
        self, monkeypatch, tmp_path,
    ) -> None:
        _stub_semgrep_runner(
            monkeypatch, errors=["Timeout after 900s"], returncode=-1,
        )
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            self._run_live_body(tmp_path)

    def test_product_misclassification_still_fails(
        self, monkeypatch, tmp_path,
    ) -> None:
        # A healthy engine that scanned nothing and found nothing:
        # the sweep grades it, the guard stays out of the way, and
        # the ground-truth assertion fails hard.
        _stub_semgrep_runner(monkeypatch, returncode=0)

        def body() -> None:
            with pytest.raises(AssertionError):
                self._run_live_body(tmp_path)

        _fail_on_skip(body)

    def test_product_error_shape_still_fails(
        self, monkeypatch, tmp_path,
    ) -> None:
        # The engine's own failure verdict (positive exit) must reach
        # the assertion as a hard failure, never a skip.
        _stub_semgrep_runner(
            monkeypatch,
            errors=["semgrep exited with code 2: invalid rule schema"],
            returncode=2,
        )

        def body() -> None:
            with pytest.raises(AssertionError):
                self._run_live_body(tmp_path)

        _fail_on_skip(body)


class TestPhpDirectionsThroughLiveBody:
    """A REAL php live test body (test_cwe_dispatch_php's
    TestLiveAdjudication, called directly so the class-level
    needs_semgrep mark stays out of the way) routed through an
    injected transport outcome — hermetic on every host."""

    def _run_live_body(self, tmp_path: Path) -> None:
        from core.audit.tests.test_cwe_dispatch_php import (
            _PHP_FAMILIES,
            TestLiveAdjudication,
        )

        cwe = sorted(_PHP_FAMILIES)[0]
        TestLiveAdjudication().test_vulnerable_snippet_confirms(
            cwe, tmp_path,
        )

    def test_degraded_transport_skips_the_live_assertions(
        self, monkeypatch, tmp_path,
    ) -> None:
        _stub_semgrep_runner(
            monkeypatch, errors=["Timeout after 900s"], returncode=-1,
        )
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            self._run_live_body(tmp_path)

    def test_product_misclassification_still_fails(
        self, monkeypatch, tmp_path,
    ) -> None:
        # A healthy engine that found nothing in the vulnerable
        # snippet: the guard stays out of the way and the
        # ground-truth assertion fails hard.
        _stub_semgrep_runner(monkeypatch, returncode=0)

        def body() -> None:
            with pytest.raises(AssertionError):
                self._run_live_body(tmp_path)

        _fail_on_skip(body)

    def test_product_error_shape_still_fails(
        self, monkeypatch, tmp_path,
    ) -> None:
        _stub_semgrep_runner(
            monkeypatch,
            errors=["semgrep exited with code 2: invalid rule schema"],
            returncode=2,
        )

        def body() -> None:
            with pytest.raises(AssertionError):
                self._run_live_body(tmp_path)

        _fail_on_skip(body)


# ---------------------------------------------------------------------
# compiler channel — guard directions
# ---------------------------------------------------------------------


_COMPILER_NOT_INSTALLED_REASON = (
    "compiler static analyzer not installed "
    "(need gcc >= 10 with -fanalyzer, or clang)"
)


def _compiler_error(
    reason: str, *, rule_id: str | None = "compiler:cwe-416",
) -> SweepResult:
    return SweepResult(
        tool="compiler", file_path="app.c", function_name="f",
        outcome="error", errors=[reason], rule_id=rule_id,
    )


def _compiler_verdict(
    outcome: str, *, compiler: str | None,
) -> SweepResult:
    details = {"compiler": compiler} if compiler is not None else None
    return SweepResult(
        tool="compiler", file_path="app.c", function_name="f",
        outcome=outcome, rule_id="compiler:cwe-416", details=details,
    )


class TestCompilerGuardDirections:
    @pytest.mark.parametrize("reason", [
        "analyzer timed out (120s)",
        "analyzer timed out (45s)",
        "analyzer killed by signal 9",
        "analyzer killed by signal 11",
        "analyzer invocation failed: [Errno 11] Resource temporarily "
        "unavailable",
        "analyzer invocation failed: [Errno 12] Cannot allocate memory",
    ])
    def test_transport_reasons_skip(self, reason: str) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_compiler_transport_degraded(
                _compiler_error(reason), gcc_probed=True,
            )

    def test_availability_arm_skips_on_gcc_probed_hosts(self) -> None:
        # rule_id=None + the exact pre-spawn message: the gcc probe
        # itself degrades under load, so on a host that probed gcc
        # healthy at collection this is a transport statement.
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_compiler_transport_degraded(
                _compiler_error(
                    _COMPILER_NOT_INSTALLED_REASON, rule_id=None,
                ),
                gcc_probed=True,
            )

    def test_availability_arm_stays_hard_on_clang_only_hosts(self) -> None:
        # _clang_path is a bare PATH lookup load cannot flip: the same
        # message on a clang-only host is a product-shaped surprise.
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                _compiler_error(
                    _COMPILER_NOT_INSTALLED_REASON, rule_id=None,
                ),
                gcc_probed=False,
            ),
        )

    @pytest.mark.parametrize("reason", [
        # The sweep's own verdicts on the input — product territory.
        "path escapes target: ../evil.c",
        "file not found: /repo/ghost.c",
        "core.sandbox unavailable — refusing to run the compiler "
        "on untrusted source without isolation",
        # The broad except-tuple also wraps ValueError/TypeError from
        # product code — only the errno'd OSError subset is transport.
        "analyzer invocation failed: expected str, bytes or "
        "os.PathLike object, not NoneType",
        "analyzer invocation failed: embedded null byte",
        # Anchoring look-alikes.
        "analyzer timed out (120s) again",
        "analyzer killed by signal 9; retried",
        "analyzer timed out (120s)\n",
    ])
    def test_product_error_reasons_do_not_skip(self, reason: str) -> None:
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                _compiler_error(reason), gcc_probed=True,
            ),
        )

    def test_rule_id_keying_blocks_none_arm_leaks(self) -> None:
        # A transport-shaped reason with rule_id=None is not the arm
        # that mints it — no skip.
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                _compiler_error("analyzer timed out (120s)", rule_id=None),
                gcc_probed=True,
            ),
        )
        # And the availability text on the compiler:* arm is not the
        # arm that mints IT — no skip.
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                _compiler_error(_COMPILER_NOT_INSTALLED_REASON),
                gcc_probed=True,
            ),
        )

    def test_multi_error_results_do_not_skip(self) -> None:
        res = _compiler_error("analyzer timed out (120s)")
        res.errors.append("compile failed")
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                res, gcc_probed=True,
            ),
        )

    def test_other_tools_never_skip(self) -> None:
        res = SweepResult(
            tool="semgrep", file_path="app.c", function_name="f",
            outcome="error", errors=["analyzer timed out (120s)"],
            rule_id="compiler:cwe-416",
        )
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                res, gcc_probed=True,
            ),
        )

    @pytest.mark.parametrize("outcome", [
        "confirmed", "refuted", "inconclusive",
    ])
    def test_probe_flip_to_clang_skips_on_gcc_probed_hosts(
        self, outcome: str,
    ) -> None:
        # gcc probed healthy at collection, but THIS run's probe lost
        # it under load and the sweep silently fell back to clang —
        # the verdict comes from a different analyzer than the leg's
        # expectations were written against.
        with pytest.raises(
            pytest.skip.Exception, match="fell back to clang",
        ):
            skip_if_compiler_transport_degraded(
                _compiler_verdict(outcome, compiler="clang"),
                gcc_probed=True,
            )

    def test_clang_verdicts_stand_on_clang_only_hosts(self) -> None:
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                _compiler_verdict("confirmed", compiler="clang"),
                gcc_probed=False,
            ),
        )

    def test_gcc_verdicts_never_skip(self) -> None:
        for outcome in ("confirmed", "refuted", "inconclusive"):
            _fail_on_skip(
                lambda o=outcome: skip_if_compiler_transport_degraded(
                    _compiler_verdict(o, compiler="gcc"),
                    gcc_probed=True,
                ),
            )

    def test_detail_less_results_never_skip(self) -> None:
        # Pre-toolchain inconclusives (unmapped CWE, non-C file) carry
        # no details dict — the flip arm must stay out of the way.
        _fail_on_skip(
            lambda: skip_if_compiler_transport_degraded(
                _compiler_verdict("inconclusive", compiler=None),
                gcc_probed=True,
            ),
        )


# ---------------------------------------------------------------------
# compiler channel — minted-identity pins (real sweep, injected
# toolchain probes + sandbox seam)
# ---------------------------------------------------------------------


class TestCompilerMintedIdentities:
    """The regex arms match what run_compiler_analyzer_sweep ACTUALLY
    mints — pinned by running the real sweep with the toolchain
    probes and the sandbox-run seam injected (no compiler, no
    sandbox)."""

    @pytest.fixture(autouse=True)
    def _fresh_compiler_caches(self):
        from core.audit import compiler_sweep as cs
        from core.audit.run_memo import BoundedMemo
        from core.testing.module_state import isolated_module_state

        with isolated_module_state(
            cs, {
                "_PROBE_CACHE": {},
                "_tu_cache": BoundedMemo(cs._TU_CACHE_MAX_ENTRIES),
                "_include_dirs_memo": BoundedMemo(cs._TU_CACHE_MAX_ENTRIES),
            }, lock=cs._PROBE_LOCK,
        ):
            yield

    def _run_real_sweep(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        gcc: tuple[str, str] | None,
        clang: str | None,
        sandbox_run,
    ) -> SweepResult:
        from core.audit import compiler_sweep as cs

        target = tmp_path / "repo"
        target.mkdir(exist_ok=True)
        (target / "uaf.c").write_text("int f(void) { return 0; }\n")
        monkeypatch.setattr(cs, "_gcc_analyzer", lambda: gcc)
        monkeypatch.setattr(cs, "_clang_path", lambda: clang)
        if sandbox_run is not None:
            monkeypatch.setattr("core.sandbox.context.run", sandbox_run)
        return cs.run_compiler_analyzer_sweep(
            target_path=target, file_path="uaf.c", function_name="f",
            hypothesis="use-after-free of `p`", cwe="CWE-416",
            out_dir=tmp_path / "out",
        )

    @staticmethod
    def _fake_gcc() -> tuple[str, str]:
        import sys

        # A real on-disk path (the cache key stats the compiler
        # binary) whose spawn never happens — the sandbox seam is
        # stubbed.
        return (sys.executable, "json")

    def _minted_error(
        self, monkeypatch, tmp_path, sandbox_run,
    ) -> SweepResult:
        result = self._run_real_sweep(
            monkeypatch, tmp_path,
            gcc=self._fake_gcc(), clang=None, sandbox_run=sandbox_run,
        )
        assert result.outcome == "error"
        assert result.rule_id == "compiler:cwe-416"
        assert len(result.errors) == 1
        return result

    def test_timeout_identity(self, monkeypatch, tmp_path) -> None:
        result = self._minted_error(
            monkeypatch, tmp_path,
            _raising_runner(subprocess.TimeoutExpired(["gcc"], 120)),
        )
        assert COMPILER_TRANSPORT_RE.match(result.errors[0]), result.errors

    def test_signal_kill_identity(self, monkeypatch, tmp_path) -> None:
        result = self._minted_error(
            monkeypatch, tmp_path, _rc_runner(-9),
        )
        assert COMPILER_TRANSPORT_RE.match(result.errors[0]), result.errors

    def test_spawn_oserror_identity(self, monkeypatch, tmp_path) -> None:
        result = self._minted_error(
            monkeypatch, tmp_path,
            _raising_runner(
                OSError(errno.EAGAIN, "Resource temporarily unavailable"),
            ),
        )
        assert COMPILER_TRANSPORT_RE.match(result.errors[0]), result.errors

    def test_product_typeerror_stays_hard(self, monkeypatch, tmp_path) -> None:
        # The same except-tuple wraps TypeError from product code —
        # the minted spelling must NOT match, and the guarded runner
        # must return it as a hard error result, not a skip.
        result = self._minted_error(
            monkeypatch, tmp_path,
            _raising_runner(TypeError(
                "expected str, bytes or os.PathLike object, not NoneType",
            )),
        )
        assert not COMPILER_TRANSPORT_RE.match(result.errors[0]), (
            result.errors
        )

    def test_timeout_constant_pins_the_arm(self) -> None:
        from core.audit import compiler_sweep as cs

        assert COMPILER_TRANSPORT_RE.match(
            f"analyzer timed out ({cs._COMPILE_TIMEOUT_S}s)",
        )

    def test_not_installed_identity_and_guard_chain(
        self, monkeypatch, tmp_path,
    ) -> None:
        # Both probes gone: the sweep mints the availability arm with
        # rule_id=None, and the guarded runner converts it to a skip
        # on a gcc-probed host.
        result = self._run_real_sweep(
            monkeypatch, tmp_path, gcc=None, clang=None, sandbox_run=None,
        )
        assert result.outcome == "error"
        assert result.rule_id is None
        assert result.errors == [_COMPILER_NOT_INSTALLED_REASON]
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_compiler_transport_degraded(result, gcc_probed=True)

    def test_probe_flip_minted_through_real_sweep(
        self, monkeypatch, tmp_path,
    ) -> None:
        # gcc probe returns None, clang present: the real sweep runs
        # the (stubbed) clang leg and stamps details["compiler"] =
        # "clang" — the guarded chain skips on a gcc-probed host and
        # returns the verdict on a clang-only one.
        import sys

        from core.audit import compiler_sweep as cs

        target = tmp_path / "repo"
        target.mkdir()
        (target / "uaf.c").write_text("int f(void) { return 0; }\n")
        monkeypatch.setattr(cs, "_gcc_analyzer", lambda: None)
        monkeypatch.setattr(cs, "_clang_path", lambda: sys.executable)
        monkeypatch.setattr("core.sandbox.context.run", _rc_runner(0))

        def _call() -> SweepResult:
            return run_compiler_analyzer_sweep_guarded(
                gcc_probed=False,
                target_path=target, file_path="uaf.c",
                function_name="f", hypothesis="use-after-free of `p`",
                cwe="CWE-416", out_dir=tmp_path / "out",
            )

        result: SweepResult | None = None

        def body() -> None:
            nonlocal result
            result = _call()

        _fail_on_skip(body)
        assert result is not None
        assert (result.details or {}).get("compiler") == "clang"
        cs._reset_tu_cache()
        with pytest.raises(
            pytest.skip.Exception, match="fell back to clang",
        ):
            run_compiler_analyzer_sweep_guarded(
                gcc_probed=True,
                target_path=target, file_path="uaf.c",
                function_name="f", hypothesis="use-after-free of `p`",
                cwe="CWE-416", out_dir=tmp_path / "out",
            )

    def test_guard_chain_timeout_skips(self, monkeypatch, tmp_path) -> None:
        # Full chain: real sweep + injected deadline through the
        # guarded runner.
        from core.audit import compiler_sweep as cs

        target = tmp_path / "repo"
        target.mkdir()
        (target / "uaf.c").write_text("int f(void) { return 0; }\n")
        monkeypatch.setattr(cs, "_gcc_analyzer", self._fake_gcc)
        monkeypatch.setattr(cs, "_clang_path", lambda: None)
        monkeypatch.setattr(
            "core.sandbox.context.run",
            _raising_runner(subprocess.TimeoutExpired(["gcc"], 120)),
        )
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            run_compiler_analyzer_sweep_guarded(
                gcc_probed=True,
                target_path=target, file_path="uaf.c",
                function_name="f", hypothesis="use-after-free of `p`",
                cwe="CWE-416", out_dir=tmp_path / "out",
            )


# ---------------------------------------------------------------------
# expanded-view channel
# ---------------------------------------------------------------------


def _expanded(reason: str, *, ok: bool = False) -> ExpandedRuleResult:
    return ExpandedRuleResult(
        ok=ok, file_path="main.c", rule_config="rules/x.yaml",
        reason=reason,
    )


class TestExpandedViewGuardDirections:
    @pytest.mark.parametrize("reason", [
        "no fidelity-3 view: preprocessor timed out (60s)",
        "no fidelity-3 view: preprocessor invocation failed: "
        "[Errno 12] Cannot allocate memory",
        "no fidelity-3 view: no C preprocessor available "
        "(need gcc, g++ or cpp)",
        "no fidelity-3 view: core.sandbox unavailable — refusing to "
        "run the preprocessor on untrusted source without isolation",
        "no fidelity-3 view: preprocess failed — no fidelity-3 view: "
        "exit code -9",
        "semgrep not installed",
        "semgrep runner unavailable: No module named 'jsonschema'",
        "semgrep errors on expanded view: Timeout after 900s",
        "semgrep errors on expanded view: [Errno 11] Resource "
        "temporarily unavailable",
    ])
    def test_transport_reasons_skip(self, reason: str) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_expanded_view_transport_degraded(_expanded(reason))

    @pytest.mark.parametrize("reason", [
        # The pipeline's own verdicts on the input — product territory.
        "not a C/C++ file: app.py",
        "path escapes target: ../main.c",
        "expansion budget exhausted (12 preprocessor runs)",
        # The preprocessor REJECTED the source (positive exit /
        # diagnostic text) — never transport.
        "no fidelity-3 view: preprocess failed — no fidelity-3 view: "
        "exit code 1",
        "no fidelity-3 view: preprocess failed — no fidelity-3 view: "
        "main.c:3:10: fatal error: gen.h: No such file or directory",
        "no fidelity-3 view: expanded output exceeds 8388608 bytes",
        # Broad product-code wrap — never generically transport.
        "semgrep on expanded view failed: KeyError('findings')",
        # Engine verdicts behind the expanded-view prefix.
        "semgrep errors on expanded view: Fatal: rule did not parse",
        "semgrep errors on expanded view: semgrep exited with code 2",
        # Multi-error joins stay hard even when the first arm is
        # transport-shaped.
        "semgrep errors on expanded view: [Errno 11] Resource "
        "temporarily unavailable; Fatal: rule did not parse",
        # Anchoring look-alikes.
        "no fidelity-3 view: preprocessor timed out (60s) again",
    ])
    def test_product_reasons_do_not_skip(self, reason: str) -> None:
        _fail_on_skip(
            lambda: skip_if_expanded_view_transport_degraded(
                _expanded(reason),
            ),
        )

    def test_ok_results_never_skip(self) -> None:
        _fail_on_skip(
            lambda: skip_if_expanded_view_transport_degraded(
                _expanded("", ok=True),
            ),
        )

    def test_preprocessor_deadline_constant_pins_the_arm(self) -> None:
        # Anti-drift: the deadline arm is built from the same constant
        # the product mints with.
        reason = (
            "no fidelity-3 view: "
            f"preprocessor timed out ({pv._PREPROCESS_TIMEOUT_S}s)"
        )
        assert EXPANDED_VIEW_TRANSPORT_RE.match(reason)

    def test_minted_join_through_real_pipeline(
        self, monkeypatch, tmp_path,
    ) -> None:
        # The real run_expanded_semgrep_rule joins a degraded view's
        # errors behind "no fidelity-3 view: " — pinned by running it
        # with the view seam injected (the preprocessor's own minted
        # deadline string).
        from core.audit import expanded_semgrep as es

        target = tmp_path / "t"
        target.mkdir()
        (target / "main.c").write_text("void f(void) { MACRO(1); }\n")
        monkeypatch.setattr(
            es, "expand_translation_unit",
            lambda **kw: pv.ExpandedView(
                ok=False, file_path=kw["file_path"],
                errors=[
                    f"preprocessor timed out ({pv._PREPROCESS_TIMEOUT_S}s)",
                ],
            ),
        )
        res = es.run_expanded_semgrep_rule(
            target_path=target, file_path="main.c",
            rule_config="rules/x.yaml", budget=es.ExpansionBudget(),
        )
        assert res.ok is False
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_expanded_view_transport_degraded(res)

    def test_minted_semgrep_arm_through_real_pipeline(
        self, monkeypatch, tmp_path,
    ) -> None:
        # The expanded pass surfaces the runner's minted transport
        # error behind "semgrep errors on expanded view: " — the real
        # run_rule runs with an injected raising child spawn.
        import packages.semgrep.runner as runner_mod
        from core.audit import expanded_semgrep as es

        target = tmp_path / "t"
        target.mkdir()
        (target / "main.c").write_text("void f(void) { MACRO(1); }\n")
        monkeypatch.setattr(
            es, "expand_translation_unit",
            lambda **kw: pv.ExpandedView(
                ok=True, file_path=kw["file_path"],
                text="void f(void) { strcpy(a, b); }\n",
                line_map=(("main.c", 1),),
            ),
        )
        monkeypatch.setattr(runner_mod, "is_available", lambda: True)
        real_run_rule = runner_mod.run_rule
        monkeypatch.setattr(
            runner_mod, "run_rule",
            lambda target, config, **kw: real_run_rule(
                target, config,
                subprocess_runner=_raising_runner(
                    subprocess.TimeoutExpired(["semgrep"], 900),
                ),
            ),
        )
        res = es.run_expanded_semgrep_rule(
            target_path=target, file_path="main.c",
            rule_config="rules/x.yaml", budget=es.ExpansionBudget(),
        )
        assert res.ok is False
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_expanded_view_transport_degraded(res)


# ---------------------------------------------------------------------
# preprocessor (cpp) channel — guard directions
# ---------------------------------------------------------------------


_CPP_NOT_INSTALLED_REASON = "no C preprocessor available (need gcc, g++ or cpp)"


def _cpp_view(reason: str, *, tool: str = "gcc") -> pv.ExpandedView:
    return pv.ExpandedView(
        ok=False, file_path="app.c", tool=tool, errors=[reason],
    )


def _cpp_expansion(reason: str) -> pv.FunctionExpansion:
    return pv.FunctionExpansion(
        ok=False, file_path="app.c", line_start=3, line_end=9,
        errors=[reason],
    )


class TestCppGuardDirections:
    @pytest.mark.parametrize("reason", [
        "preprocessor timed out (60s)",
        "preprocessor timed out (5s)",
        "preprocessor timed out (59.9998s)",
        "preprocessor timed out (0.0001s)",
        "preprocessor invocation failed: [Errno 11] Resource "
        "temporarily unavailable",
        "preprocessor invocation failed: [Errno 12] Cannot allocate "
        "memory",
        "preprocess failed — no fidelity-3 view: exit code -9",
    ])
    def test_transport_reasons_skip(self, reason: str) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_cpp_transport_degraded(
                _cpp_view(reason), cpp_probed=True,
            )

    def test_availability_arm_skips_on_cpp_probed_hosts(self) -> None:
        # The per-test probe (fresh cache each test) can itself time
        # out / fail to spawn / be killed under load: on a host that
        # probed the preprocessor healthy at collection this message
        # is a transport statement.
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_cpp_transport_degraded(
                _cpp_view(_CPP_NOT_INSTALLED_REASON, tool=""),
                cpp_probed=True,
            )

    def test_cpp_availability_arm_stays_hard_on_unprobed_hosts(self) -> None:
        # Without a healthy collection-time probe there is nothing for
        # load to flip — the same message is a product-shaped surprise.
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(
                _cpp_view(_CPP_NOT_INSTALLED_REASON, tool=""),
                cpp_probed=False,
            ),
        )

    def test_cpp_availability_arm_is_exact_match_only(self) -> None:
        # Exact match: a prefix-extended spelling is not the arm the
        # product mints and must stay a hard failure.
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(
                _cpp_view(
                    "no C preprocessor available (need gcc, g++ or cpp)"
                    " — probe flaked", tool="",
                ),
                cpp_probed=True,
            ),
        )

    def test_cpp_errno_shape_is_exact_only(self) -> None:
        # The spawn arm keys on the "[Errno N] " spelling, never on a
        # bare bracket.
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(
                _cpp_view("preprocessor invocation failed: [cpp] "
                          "driver crashed"),
                cpp_probed=True,
            ),
        )

    @pytest.mark.parametrize("reason", [
        # The pipeline's own verdicts on the input — product territory.
        "path escapes target: ../evil.c",
        "file not found: /repo/ghost.c",
        "not a C/C++ translation unit: .py",
        # Deterministic in this channel (the live fixtures monkeypatch
        # the sandbox seam, so the import cannot flip under load).
        "core.sandbox unavailable — refusing to run the preprocessor "
        "on untrusted source without isolation",
        # The preprocessor's own verdict on the source: diagnostics
        # and positive exit codes.
        "preprocess failed — no fidelity-3 view: main.c:3:10: fatal "
        "error: gen.h: No such file or directory",
        "preprocess failed — no fidelity-3 view: exit code 1",
        # Non-KILL signals are the preprocessor's behaviour on the
        # input — a segfaulting cpp is evidence, not churn.
        "preprocess failed — no fidelity-3 view: exit code -11",
        "preprocess failed — no fidelity-3 view: exit code -15",
        "preprocess failed — no fidelity-3 view: exit code -6",
        "preprocess failed — no fidelity-3 view: exit code -7",
        "preprocess failed — no fidelity-3 view: exit code -99",
        # Product-code file I/O and the size cap.
        "expanded output exceeds 16777216 bytes",
        "could not read preprocessor output: [Errno 28] No space left "
        "on device",
        # The broad except-tuple also wraps ValueError/TypeError from
        # product code — only the errno'd OSError subset is transport.
        "preprocessor invocation failed: expected str, bytes or "
        "os.PathLike object, not NoneType",
        "preprocessor invocation failed: embedded null byte",
        # Anchoring look-alikes.
        "preprocessor timed out (60s) again",
        "preprocessor timed out (60s)\n",
        "preprocessor timed out (59.9998s) again",
        "preprocessor timed out (59.9998s)\n",
        "preprocessor timed out (59.s)",
        "preprocessor timed out (.5s)",
        "preprocessor timed out (-1.5s)",
        "preprocess failed — no fidelity-3 view: exit code -9; retried",
        "preprocess failed — no fidelity-3 view: exit code -9\n",
    ])
    def test_cpp_product_reasons_do_not_skip(self, reason: str) -> None:
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(
                _cpp_view(reason), cpp_probed=True,
            ),
        )

    def test_cpp_ok_results_never_skip(self) -> None:
        view = pv.ExpandedView(
            ok=True, file_path="app.c", text="int x;",
            line_map=(("app.c", 1),), tool="gcc",
        )
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(view, cpp_probed=True),
        )

    def test_cpp_multi_error_results_do_not_skip(self) -> None:
        view = _cpp_view("preprocessor timed out (60s)")
        view.errors.append("preprocess failed — no fidelity-3 view: x")
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(view, cpp_probed=True),
        )

    def test_function_expansion_transport_skips(self) -> None:
        # expand_function copies a degraded view's errors verbatim —
        # the same identity keying holds on the FunctionExpansion leg.
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_cpp_transport_degraded(
                _cpp_expansion("preprocessor timed out (60s)"),
                cpp_probed=True,
            )

    def test_cpp_function_expansion_product_stays_hard(self) -> None:
        _fail_on_skip(
            lambda: skip_if_cpp_transport_degraded(
                _cpp_expansion(
                    "preprocess failed — no fidelity-3 view: exit code -11",
                ),
                cpp_probed=True,
            ),
        )


# ---------------------------------------------------------------------
# preprocessor (cpp) channel — minted-identity pins (real
# expand_translation_unit, only the toolchain probe and the sandbox
# seam injected)
# ---------------------------------------------------------------------


class TestCppMintedIdentities:
    """The regex arms match what expand_translation_unit ACTUALLY
    mints — pinned by running the real product code with the
    preprocessor probe and the sandbox-run seam injected (no
    toolchain, no sandbox)."""

    @pytest.fixture(autouse=True)
    def _fresh_cpp_probe_cache(self):
        from core.testing.module_state import isolated_module_state

        with isolated_module_state(pv, {"_PROBE_CACHE": {}}, lock=pv._PROBE_LOCK):
            yield

    def _run_real_expand(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        *,
        sandbox_run,
        pre: list | None,
    ) -> pv.ExpandedView:
        target = tmp_path / "repo"
        target.mkdir(exist_ok=True)
        (target / "main.c").write_text("int f(void) { return 0; }\n")
        # The probe seam: a fake argv whose path never spawns (the
        # sandbox seam is stubbed), or None for the availability arm.
        monkeypatch.setattr(pv, "_preprocessor_for", lambda is_cxx: pre)
        if sandbox_run is not None:
            monkeypatch.setattr("core.sandbox.context.run", sandbox_run)
        return pv.expand_translation_unit(
            target_path=target, file_path="main.c",
            out_dir=tmp_path / "out",
        )

    @staticmethod
    def _fake_pre() -> list:
        return ["/usr/bin/gcc", "-E", "-x", "c"]

    def _minted_error(
        self, monkeypatch, tmp_path, sandbox_run,
    ) -> pv.ExpandedView:
        view = self._run_real_expand(
            monkeypatch, tmp_path, sandbox_run=sandbox_run,
            pre=self._fake_pre(),
        )
        assert view.ok is False
        assert len(view.errors) == 1
        return view

    def test_timeout_identity(self, monkeypatch, tmp_path) -> None:
        view = self._minted_error(
            monkeypatch, tmp_path,
            _raising_runner(subprocess.TimeoutExpired(["gcc"], 60)),
        )
        assert CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_spawn_oserror_identity(self, monkeypatch, tmp_path) -> None:
        view = self._minted_error(
            monkeypatch, tmp_path,
            _raising_runner(
                OSError(errno.EAGAIN, "Resource temporarily unavailable"),
            ),
        )
        assert CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_sigkill_identity(self, monkeypatch, tmp_path) -> None:
        # SIGKILL with empty stderr — the resource ceiling's kill.
        view = self._minted_error(monkeypatch, tmp_path, _rc_runner(-9))
        assert view.errors == [
            "preprocess failed — no fidelity-3 view: exit code -9",
        ]
        assert CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_cpp_sigsegv_minted_stays_product(
        self, monkeypatch, tmp_path,
    ) -> None:
        # Every non-KILL signal is evidence about the preprocessor on
        # this input, never transport.
        view = self._minted_error(monkeypatch, tmp_path, _rc_runner(-11))
        assert view.errors == [
            "preprocess failed — no fidelity-3 view: exit code -11",
        ]
        assert not CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_positive_exit_stays_product(self, monkeypatch, tmp_path) -> None:
        def _diag_runner(cmd, **kwargs):  # noqa: ANN001, ANN003 — subprocess.run signature
            return subprocess.CompletedProcess(
                cmd, 1, "", "main.c:1:1: error: unknown type name",
            )

        view = self._minted_error(monkeypatch, tmp_path, _diag_runner)
        assert not CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_product_typeerror_stays_hard(self, monkeypatch, tmp_path) -> None:
        view = self._minted_error(
            monkeypatch, tmp_path,
            _raising_runner(TypeError(
                "expected str, bytes or os.PathLike object, not NoneType",
            )),
        )
        assert not CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_output_read_failure_stays_product(
        self, monkeypatch, tmp_path,
    ) -> None:
        # rc=0 but the output file was never written: product-code
        # file I/O mints "could not read preprocessor output: [Errno
        # N] ..." — errno-shaped under a DIFFERENT prefix, never the
        # spawn arm.
        view = self._minted_error(monkeypatch, tmp_path, _rc_runner(0))
        assert view.errors[0].startswith(
            "could not read preprocessor output: [Errno ",
        ), view.errors
        assert not CPP_TRANSPORT_RE.match(view.errors[0]), view.errors

    def test_not_installed_identity_and_guard_chain(
        self, monkeypatch, tmp_path,
    ) -> None:
        view = self._run_real_expand(
            monkeypatch, tmp_path, sandbox_run=None, pre=None,
        )
        assert view.ok is False
        assert view.errors == [_CPP_NOT_INSTALLED_REASON]
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_if_cpp_transport_degraded(view, cpp_probed=True)

    def test_timeout_constant_pins_the_arm(self) -> None:
        assert CPP_TRANSPORT_RE.match(
            f"preprocessor timed out ({pv._PREPROCESS_TIMEOUT_S}s)",
        )

    def test_guard_chain_timeout_skips(self, monkeypatch, tmp_path) -> None:
        # Full chain: real expand + injected deadline through the
        # guarded runner.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "main.c").write_text("int f(void) { return 0; }\n")
        monkeypatch.setattr(
            pv, "_preprocessor_for", lambda is_cxx: self._fake_pre(),
        )
        monkeypatch.setattr(
            "core.sandbox.context.run",
            _raising_runner(subprocess.TimeoutExpired(["gcc"], 60)),
        )
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            expand_translation_unit_guarded(
                cpp_probed=True, target_path=target, file_path="main.c",
                out_dir=tmp_path / "out",
            )


class TestCppDirectionsThroughLiveBody:
    """A REAL live test body (test_preprocessor_view's whole-TU
    line-map leg, called directly so the module-level needs_cpp mark
    stays out of the way) routed through an injected sandbox seam —
    hermetic on every host."""

    def _run_live_body(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, sandbox_run,
    ) -> None:
        from core.audit.tests.test_preprocessor_view import TestExpandedView

        monkeypatch.setattr(
            pv, "_preprocessor_for",
            lambda is_cxx: ["/usr/bin/gcc", "-E", "-x", "c"],
        )
        monkeypatch.setattr("core.sandbox.context.run", sandbox_run)
        TestExpandedView().test_tu_lines_map_to_original_coordinates(
            tmp_path, [],
        )

    def test_degraded_transport_skips_the_live_assertions(
        self, monkeypatch, tmp_path,
    ) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            self._run_live_body(
                monkeypatch, tmp_path,
                _raising_runner(subprocess.TimeoutExpired(["gcc"], 60)),
            )

    def test_cpp_segfaulting_preprocessor_still_fails(
        self, monkeypatch, tmp_path,
    ) -> None:
        # The core direction: a segfaulting preprocessor is evidence
        # about the toolchain on this input — the product assertion
        # must fail hard, never skip.
        def body() -> None:
            with pytest.raises(AssertionError):
                self._run_live_body(monkeypatch, tmp_path, _rc_runner(-11))

        _fail_on_skip(body)

    def test_cpp_product_degradation_still_fails(
        self, monkeypatch, tmp_path,
    ) -> None:
        # rc=0 with no output written — a product-shaped degradation
        # ("could not read preprocessor output: ...") reaches the
        # assertion as a hard failure.
        def body() -> None:
            with pytest.raises(AssertionError):
                self._run_live_body(monkeypatch, tmp_path, _rc_runner(0))

        _fail_on_skip(body)


class TestCppCarryProbe:
    """The trivially expandable probe for the identity-collapsed
    surfaces: healthy toolchain returns silently and scrubs its spy
    entries; transport failures skip and product failures remain hard."""

    @staticmethod
    def _writing_runner(cmd, **kwargs):  # noqa: ANN001, ANN003, ANN205 — subprocess.run signature
        out = Path(cmd[cmd.index("-o") + 1])
        src = Path(cmd[cmd.index("-o") - 1])
        out.write_text(
            f'# 1 "{src}"\n' + src.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def test_healthy_probe_returns_and_scrubs_spy(
        self, monkeypatch, tmp_path,
    ) -> None:
        monkeypatch.setattr(
            pv, "_preprocessor_for",
            lambda is_cxx: ["/usr/bin/gcc", "-E", "-x", "c"],
        )
        spy: list = [{"cmd": ["sentinel"]}]

        def recording(cmd, **kwargs):  # noqa: ANN001, ANN003 — subprocess.run signature
            spy.append({"cmd": cmd, **kwargs})
            return self._writing_runner(cmd, **kwargs)

        monkeypatch.setattr("core.sandbox.context.run", recording)
        _fail_on_skip(
            lambda: skip_unless_cpp_carries_probe(
                tmp_path, cpp_probed=True, context="probe test",
                spy_calls=spy,
            ),
        )
        # Pre-existing entries survive; the probe's own are scrubbed.
        assert spy == [{"cmd": ["sentinel"]}]

    def test_transport_degraded_probe_skips(
        self, monkeypatch, tmp_path,
    ) -> None:
        monkeypatch.setattr(
            pv, "_preprocessor_for",
            lambda is_cxx: ["/usr/bin/gcc", "-E", "-x", "c"],
        )
        monkeypatch.setattr("core.sandbox.context.run", _rc_runner(-9))
        with pytest.raises(
            pytest.skip.Exception, match="transport degraded",
        ):
            skip_unless_cpp_carries_probe(
                tmp_path, cpp_probed=True, context="probe test",
            )

    def test_product_diagnostic_fails_with_probe_identity(
        self, monkeypatch, tmp_path,
    ) -> None:
        # A rejection of this known-good TU is product-visible evidence,
        # even when the consumer has collapsed the failure identity.
        def _diag_runner(cmd, **kwargs):  # noqa: ANN001, ANN003 — subprocess.run signature
            return subprocess.CompletedProcess(
                cmd, 1, "", "probe.c:1:1: error: unsupported dialect",
            )

        monkeypatch.setattr(
            pv, "_preprocessor_for",
            lambda is_cxx: ["/usr/bin/gcc", "-E", "-x", "c"],
        )
        monkeypatch.setattr("core.sandbox.context.run", _diag_runner)
        with pytest.raises(
            pytest.fail.Exception,
            match="cannot carry a trivial known-good TU",
        ):
            skip_unless_cpp_carries_probe(
                tmp_path, cpp_probed=True, context="probe test",
            )


    @pytest.mark.parametrize("reason", [
        "could not read preprocessor output: [Errno 2] missing output",
        "preprocessor invocation failed: malformed invocation",
    ])
    def test_product_failure_does_not_skip(self, monkeypatch, tmp_path, reason):
        monkeypatch.setattr(
            pv, "expand_translation_unit",
            lambda **kwargs: pv.ExpandedView(ok=False, file_path="probe.c", errors=[reason]),
        )
        def body():
            with pytest.raises(pytest.fail.Exception, match="known-good TU"):
                skip_unless_cpp_carries_probe(
                    tmp_path, cpp_probed=True, context="product control",
                )
        _fail_on_skip(body)


class TestSemgrepCarryProbe:
    @pytest.mark.parametrize("outcome,errors", [
        ("refuted", []),
        ("error", ["invalid rule schema"]),
    ])
    def test_product_failure_does_not_skip(self, monkeypatch, tmp_path, outcome, errors):
        result = SweepResult(
            tool="semgrep", outcome=outcome, errors=errors,
            file_path="probe.py", function_name="probe", rule_id="probe",
        )
        monkeypatch.setattr("core.audit.sweep.run_semgrep_sweep", lambda **kwargs: result)
        def body():
            with pytest.raises(pytest.fail.Exception, match="known-matching probe"):
                skip_unless_semgrep_carries_probe(tmp_path, context="product control")
        _fail_on_skip(body)

    @pytest.mark.parametrize("outcome,errors", [
        ("confirmed", []),
        ("error", ["Timeout after 45s"]),
        ("error", ["semgrep is not installed (semgrep binary not found on PATH)"]),
    ])
    def test_healthy_or_transport_partition(self, monkeypatch, tmp_path, outcome, errors):
        result = SweepResult(
            tool="semgrep", outcome=outcome, errors=errors,
            file_path="probe.py", function_name="probe", rule_id="probe",
        )
        monkeypatch.setattr("core.audit.sweep.run_semgrep_sweep", lambda **kwargs: result)
        if outcome == "confirmed":
            _fail_on_skip(lambda: skip_unless_semgrep_carries_probe(tmp_path, context="healthy"))
        else:
            with pytest.raises(pytest.skip.Exception, match="transport degraded"):
                skip_unless_semgrep_carries_probe(tmp_path, context="transport")


# ---------------------------------------------------------------------
# raw engine pins
# ---------------------------------------------------------------------


class TestPinnedSubprocess:
    def test_healthy_exit_codes_return(self) -> None:
        # No-skip direction: an engine-chosen exit code must REACH the
        # caller, never skip.
        proc = None

        def body() -> None:
            nonlocal proc
            proc = run_pinned_subprocess(
                ["/bin/sh", "-c", "exit 3"], timeout=30, context="pin",
            )

        _fail_on_skip(body)
        assert proc is not None
        assert proc.returncode == 3

    def test_spawn_failure_skips(self, tmp_path: Path) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="could not spawn",
        ):
            run_pinned_subprocess(
                [str(tmp_path / "no-such-engine")], timeout=30,
                context="pin",
            )

    def test_deadline_skips(self) -> None:
        with pytest.raises(pytest.skip.Exception, match="timed out"):
            run_pinned_subprocess(
                ["/bin/sleep", "30"], timeout=1, context="pin",
            )

    def test_signal_kill_skips(self) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="killed by signal 9",
        ):
            run_pinned_subprocess(
                ["/bin/sh", "-c", "kill -9 $$"], timeout=30,
                context="pin",
            )

    def test_signal_narrowing_keeps_product_signals(self) -> None:
        import signal

        # SIGTERM proves real signal delivery without deliberately generating
        # a segmentation-fault report on the developer's machine.
        # skip_signals=(9,) — a non-KILL signal is the engine's own
        # behaviour on the input and must reach the caller.
        proc = None

        def body() -> None:
            nonlocal proc
            proc = run_pinned_subprocess(
                ["/bin/sh", "-c", "kill -TERM $$"], timeout=30,
                context="pin", skip_signals=(9,),
            )

        _fail_on_skip(body)
        assert proc is not None
        assert proc.returncode == -signal.SIGTERM


# ---------------------------------------------------------------------
# structural fences
# ---------------------------------------------------------------------


def _function_call_map(file_name: str) -> dict[str, set[str]]:
    """Function name -> every callable name invoked anywhere in its
    body (``f(...)`` and ``obj.f(...)`` both count as ``f``; nested
    defs are attributed to the enclosing function too, so a guard
    call inside a closure still satisfies the fence)."""
    tree = ast.parse(
        (_TESTS_DIR / file_name).read_text(encoding="utf-8"),
    )
    out: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        called: set[str] = set()
        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            if isinstance(n.func, ast.Name):
                called.add(n.func.id)
            elif isinstance(n.func, ast.Attribute):
                called.add(n.func.attr)
        out.setdefault(node.name, set()).update(called)
    return out


def _callers_of(call_map: dict[str, set[str]], name: str) -> set[str]:
    return {fn for fn, called in call_map.items() if name in called}


def _stmt_order(
    file_name: str, function_name: str,
) -> dict[str, list[int]]:
    """Top-level statement indices of *function_name*'s body, keyed by
    each callable name invoked (anywhere) inside that statement."""
    tree = ast.parse(
        (_TESTS_DIR / file_name).read_text(encoding="utf-8"),
    )
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.FunctionDef)
            and node.name == function_name
        ):
            out: dict[str, list[int]] = {}
            for i, stmt in enumerate(node.body):
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Call):
                        if isinstance(n.func, ast.Name):
                            out.setdefault(n.func.id, []).append(i)
                        elif isinstance(n.func, ast.Attribute):
                            out.setdefault(n.func.attr, []).append(i)
            return out
    raise AssertionError(f"{function_name} not found in {file_name}")


class TestSemgrepSurfaceFences:
    def test_pkcs_identity_fixtures_are_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_pkcs_padding_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"_scan_owned_pkcs_cases", "test_go_pkcs_diagnostic_requires_protocol_review"}
        assert _callers_of(calls, "_scan_owned_pkcs_cases") == {
            "test_pkcs_jvm_import_identity", "test_pkcs_python_import_identity",
            "test_pkcs_go_import_identity",
            "test_pkcs_go_signing_import_identity",
        }

    def test_password_hash_jca_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_password_hash_java_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_password_hash_jca_import_identity"}

    def test_password_hash_hashlib_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_password_hash_python_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_password_hash_hashlib_import_identity"}

    def test_password_hash_node_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_password_hash_js_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_password_hash_node_import_identity"}

    def test_nonce_reuse_receiver_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_nonce_reuse_receiver_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_nonce_reuse_receiver_reassignment", "test_nonce_reuse_messages_require_api_context"}

    def test_pycryptodome_nonce_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_pycryptodome_nonce_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_pycryptodome_nonce_imports_and_arguments"}

    def test_aead_nonce_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_aead_nonce_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_aead_nonce_constructor_identity",
            "test_aead_direct_reassignment_ends_constructor_origin",
            "test_aead_keyword_arguments_and_ccm_tag_length",
        }

    def test_hazmat_iv_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_hazmat_iv_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_hazmat_iv_imports_and_keyword_arguments"}

    def test_block_mode_jvm_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_block_mode_jvm_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_block_mode_jvm_factory_identity_and_case"}

    def test_block_mode_python_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_block_mode_python_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_block_mode_python_argument_and_import_identity"}

    def test_jwt_js_import_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/semgrep/tests/test_jwt_js_import_identity.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_jwt_javascript_typescript_import_identity"}

    """Every live semgrep call site routes through the guarded
    runner, enumerated per file. A new live test that calls the raw
    sweep — or a guard silently dropped — flips these."""

    def test_generated_source_wrapper_arity_regression(self) -> None:
        calls = _function_call_map("../../analysis/tests/test_java_source_summaries.py")
        assert _callers_of(calls, "run_semgrep_sweep") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_generated_sources_preserve_proven_overload_arity",
        }

    def test_python_sql_recovery_native_surface(self) -> None:
        calls = _function_call_map("../../detectors/tests/test_python_sql.py")
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_two_source_batch_uses_one_marker_and_one_native_scan", "transport",
        }
        assert _callers_of(calls, "run_rule") == {
            "test_two_source_batch_uses_one_marker_and_one_native_scan", "invoke",
        }

    def test_engine_sql_argument_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_sql_argument_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_sql_text_argument_is_the_sink"}

    def test_engine_pbkdf2_keyword_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_pbkdf2_keyword_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_pbkdf2_iteration_argument_forms", "test_pbkdf2_jvm_constructor_forms",
            "test_pbkdf2_keysize_argument_forms",
        }

    def test_engine_tls_session_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_tls_session_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_requests_session_context_and_factory_forms"}

    def test_engine_asym_jvm_go_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_asym_jvm_go_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_asymmetric_jvm_go_language_identity"}

    def test_engine_asym_python_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_asym_python_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_asymmetric_key_python_argument_identity"}

    def test_engine_prng_jvm_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_prng_jvm_precision.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_prng_jvm_constructor_identity"}

    def test_engine_javascript_header_regressions(self) -> None:
        calls = _function_call_map("../../../engine/semgrep/tests/test_javascript_header_sources.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_header_property_sources"}

    def test_nosemgrep_rule_scope_regressions(self) -> None:
        calls = _function_call_map("../../../packages/semgrep/tests/test_nosemgrep.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_native_rule_scoped_suppression_annotation",
            "test_native_capped_source_cannot_create_unscoped_suppression",
        }

    def test_encoding_rules_c(self) -> None:
        calls = _function_call_map("test_encoding_rules_c.py")
        assert _callers_of(calls, "run_semgrep_sweep") == set()
        assert _callers_of(calls, "run_semgrep_sweep_guarded") == {
            "_sweep",
            "test_tempfile_marker_rule_still_refutes",
        }
        assert _callers_of(calls, "_sweep") == {
            "test_mode",
            "test_fires_on_cpp",
            "test_complete_cpp_method_escaper_silent",
            "test_incomplete_cpp_method_escaper_fires",
            "test_correct_code_with_libc_guard_and_macro_never_confirms",
            "test_strchr_reject_with_macro_never_confirms",
            "test_macro_hidden_sink_earns_a_lead_not_a_confirm",
        }

    def test_probed_language_semgrep(self) -> None:
        calls = _function_call_map("test_probed_language_semgrep.py")
        # The one raw caller is TestFlagEmission._sweep — hermetic
        # (injected runner module), no engine, no transport.
        assert _callers_of(calls, "run_semgrep_sweep") == {"_sweep"}
        assert _callers_of(calls, "run_semgrep_sweep_guarded") == {
            "test_probed_vulnerable_mod_confirms",
            "test_probed_sanitized_confirm_only_mod_stays_inconclusive",
            "test_unmarked_rule_clean_probe_has_scanned_witness",
            "test_no_hint_stays_inconclusive",
            "test_c_content_never_scanned_as_php",
            "test_partial_parse_never_refutes",
            "test_mapped_extension_differential",
        }
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_engine_skips_unknown_extension_without_flag",
        }
        assert _callers_of(calls, "guard_refinement_semgrep") == {
            "test_refinement_dispatch_confirms_probed_file",
        }

    def test_expanded_semgrep(self) -> None:
        calls = _function_call_map("test_expanded_semgrep.py")
        assert _callers_of(
            calls, "skip_if_expanded_view_transport_degraded",
        ) == {"test_e2e_real_semgrep_finds_macro_hidden_strcpy",
              "test_corpus_expands_spliced_macro_call_with_comment_before_arguments"}
        # Placement: guard after the live run, before the first
        # assert.
        order = _stmt_order(
            "test_expanded_semgrep.py",
            "test_e2e_real_semgrep_finds_macro_hidden_strcpy",
        )
        run_at = order["run_expanded_semgrep_rule"]
        guard_at = order["skip_if_expanded_view_transport_degraded"]
        assert min(guard_at) > max(run_at)

    def test_negative_controls(self) -> None:
        calls = _function_call_map("test_negative_controls.py")
        assert _callers_of(calls, "skip_unless_semgrep_carries_probe") == {
            "test_cpp_uaf_rule_caps_against_real_semgrep",
        }

    def test_backlog_drain_real_roundtrip(self) -> None:
        calls = _function_call_map("test_backlog_drain_real_roundtrip.py")
        assert _callers_of(calls, "_probe_or_skip_semgrep") == {
            "test_semgrepable_dark_row_is_witnessed",
            "test_unmatchable_rule_leaves_row_dark",
            # Hermetic partition controls exercise this same adapter seam.
            "test_product_failure_is_hard",
            "test_healthy_adapter_returns",
            "test_transport_failure_still_skips",
        }
        # Both round-trip tests re-probe AFTER the drain ran: the
        # drain report collapses failure identity, so the pre-flight
        # probe alone cannot license the post-drain adjudication.
        for test_name in (
            "test_semgrepable_dark_row_is_witnessed",
            "test_unmatchable_rule_leaves_row_dark",
        ):
            order = _stmt_order(
                "test_backlog_drain_real_roundtrip.py", test_name,
            )
            drain_at = order["drain"]
            probe_at = order["_probe_or_skip_semgrep"]
            assert max(probe_at) > max(drain_at), test_name


class TestCoccinelleSurfaceFences:
    def test_chroot_candidate_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_chroot_no_chdir_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_prior_directory_change_remains_a_review_candidate"}

    def test_lock_order_candidate_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_lock_order_violation_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_receiver_changes_require_lock_identity_review"}

    def test_uncatchable_signal_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_signal_sigkill_sigstop_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_action_queries_and_checked_failure_candidates"}

    def test_signal_handler_candidate_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_signal_handler_unsafe_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_nonlocal_jump_calls_are_review_candidates"}

    def test_signed_widening_candidate_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_sign_extension_widen_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_guarded_widening_requires_value_range_review",
            "test_signed_destination_absence_is_inconclusive",
        }

    def test_inet_ntoa_candidate_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_inet_ntoa_double_call_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_shared_buffer_calls_require_context_review"}

    def test_pointer_sizeof_expression_fixture_is_guarded(self):
        calls = _function_call_map("../../../engine/coccinelle/tests/test_double_sizeof_rule.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {"test_pointer_sizeof_expression_forms"}


class TestCodeQLSurfaceFences:
    def test_owned_native_iris_query_selection(self) -> None:
        calls = _function_call_map("../../../packages/codeql/tests/test_query_selection_reuse.py")
        assert _callers_of(calls, "run") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "native_resolve", "test_native_iris_security_selection_retains_direct_probe",
        }


class TestCompilerSurfaceFences:
    """Every live compiler-analyzer call site routes through the
    guarded runner (via the file-local ``_guarded_compiler_sweep``),
    enumerated exactly. A new live test calling the raw sweep — or a
    guard silently dropped — flips these."""

    def test_compiler_sweep(self) -> None:
        calls = _function_call_map("test_compiler_sweep.py")
        # The toolchain-fault test deliberately mints not-installed.
        # Diagnostic-protocol, location, and corroboration tests stub
        # discovery and execution to pin product classification behavior.
        # Nested raw calls also count for the enclosing test function.
        assert _callers_of(calls, "run_compiler_analyzer_sweep") == {
            "test_unusable_family_diagnostic_location_is_not_evidence",
            "test_unlocated_shared_checker_retains_family_discrimination",
            "test_aliasing_corroboration_receives_only_locatable_candidates",
            "test_relative_header_diagnostic_does_not_confirm_tu_hypothesis",
            "test_encoded_sarif_primary_location_confirms_its_actual_file",
            "test_both_missing_is_error",
            "test_shared_clang_checker_unknown_wording",
            "test_corrupt_gcc_output_errors_without_poisoning_audit_cache",
            "test_failed_sarif_invocation_is_not_cached_as_refutation",
            "sweep",
        }
        assert _callers_of(
            calls, "run_compiler_analyzer_sweep_guarded",
        ) == {"_guarded_compiler_sweep"}
        assert _callers_of(calls, "_guarded_compiler_sweep") == {
            "test_named_gcc_object_wins_over_unrelated_same_line_identifier",
            "test_explicit_common_identifier_does_not_confirm_another_objects_bug",
            "test_cpp_leak_checker_and_cleanup_controls",
            "test_aliasing_local_assignment_requires_definite_initialization",
            "test_aliasing_scalar_value_batch_requires_supported_evaluated_access",
            "test_aliasing_unary_values_require_actual_incompatible_access",
            "test_aliasing_memo_is_tu_wide_and_returns_isolated_proofs",
            "test_aliasing_no_clang_retains_candidate",
            "test_aliasing_proof_cannot_confirm_another_identifier",
            "test_aliasing_warning_needs_an_independent_access_proof",
            "test_incomplete_aliasing_attempt_is_not_memoized",
            "_sweep",
            "test_sandbox_used_with_network_deny",
            "test_non_c_file_inconclusive",
            "test_path_escape_is_error",
            "test_missing_file_is_error",
            "test_pragma_suppressed_silence_cannot_refute",
            "test_linemarker_system_header_silence_cannot_refute",
            "test_clean_tu_with_prose_mentions_still_refutes",
            "_sweep_uaf",
            "test_in_tree_linemarker_still_refutes",
            "test_conditional_analyzer_token_in_header_cannot_refute",
            "sweep",
            "test_forged_refutation_is_inconclusive",
            "test_control_still_confirms",
            "test_quota_exhaustion_is_inconclusive",
            "test_limit_is_inconclusive",
        }


class TestPhpSurfaceFences:
    """Every live php-dispatch semgrep call site and every live
    interpreter spawn routes through the guarded runners, enumerated
    per file."""

    def test_cwe_dispatch_php(self) -> None:
        calls = _function_call_map("test_cwe_dispatch_php.py")
        assert _callers_of(calls, "run_semgrep_sweep") == set()
        assert _callers_of(calls, "run_semgrep_sweep_guarded") == {
            "test_command_and_protocol_argument_roles",
            "test_command_and_protocol_partial_scope_stays_inconclusive",
            "test_vulnerable_snippet_confirms",
            "test_sanitized_snippet_refutes",
            "test_attribute_encoding_miss_on_indirect_flow_stays_inconclusive",
            "test_crypto_builtin_and_name_context",
            "test_crypto_name_misses_stay_inconclusive",
            "test_encoded_request_in_unquoted_attribute_confirms",
            "test_raw_attribute_context_does_not_borrow_body_taint",
        }
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_semgrep_php_target_selection_pin",
        }

    def test_engine_call_argument_regressions(self) -> None:
        calls = _function_call_map(
            "../../../engine/semgrep/tests/test_php_call_argument_precision.py",
        )
        assert _callers_of(calls, "run_semgrep_sweep") == set()
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "test_command_and_protocol_payload_positions",
        }

    def test_cwe_dispatch_php_web(self) -> None:
        calls = _function_call_map("test_cwe_dispatch_php_web.py")
        assert _callers_of(calls, "run_semgrep_sweep") == set()
        assert _callers_of(calls, "run_semgrep_sweep_guarded") == {
            "test_vulnerable_snippet_confirms",
            "test_sanitized_snippet_refutes",
            "test_attr_rule_silence_never_refutes_body_xss",
        }

    def test_dark_verify_interpreter_pins(self) -> None:
        # The live interpreter round-trips all funnel through
        # _run_stdout; the one direct pin is the ruby foreign-load
        # leg (it adjudicates on stdout, not the exit code).
        calls = _function_call_map("test_dark_verify.py")
        assert _callers_of(calls, "run_pinned_subprocess") == {
            "_run_stdout",
            "test_live_foreign_load_reports_binding_error",
        }
        assert _callers_of(calls, "_run_stdout") == {
            "test_live_target_load_passes_binding",
            "test_live_shadowed_init_reports_binding_error",
            "test_json_encode_escapes_backslash_and_control_chars",
            "test_ruby_roundtrips_as_data",
            "test_perl_roundtrips_as_data",
            "test_php_roundtrips_as_data",
            "test_lua_roundtrips_as_data",
            "test_perl_backtick_block_interpolation_stays_data",
        }


class TestCppSurfaceFences:
    """Every real-cpp live call site routes through the guarded
    runners (via the file-local wrappers), enumerated exactly; the
    identity-collapsed surfaces carry the probe, probe-before-run. A
    new live test calling the raw runner — or a guard silently
    dropped — flips these."""

    def test_preprocessor_view(self) -> None:
        calls = _function_call_map("test_preprocessor_view.py")
        # The raw callers: three pre-toolchain product legs (path
        # escape / missing file / non-C — degraded before any spawn)
        # and the deliberate availability mint (it manufactures the
        # guard's transport arm on purpose, so it must bypass the
        # guard). The pinned-budget tests also bypass the guard to
        # inspect deterministic sandbox stubs and pre-launch exhaustion.
        # The prepared-view fixture also stubs tool discovery and sandbox
        # execution. Nested helper calls count for the fixture as well.
        assert _callers_of(calls, "expand_translation_unit") == {
            "expand",
            "prepared_reuse",
            "test_non_c_file_degrades",
            "test_path_escape_degrades",
            "test_missing_file_degrades",
            "test_no_preprocessor_degrades",
            "test_pinned_preprocessor_uses_remaining_budget_without_tool_discovery",
            "test_preprocessor_deadline_exhausted_during_preparation_does_not_launch",
        }
        assert _callers_of(calls, "expand_translation_unit_guarded") == {
            "_expand_tu_guarded",
        }
        assert _callers_of(calls, "_expand_tu_guarded") == {
            "test_shared_include_memo_does_not_share_preprocessor_macro_context",
            "test_tu_lines_map_to_original_coordinates",
            "test_macro_expanded_line_keeps_original_line",
            "test_system_header_expansion_is_unattributable",
            "test_linemarkers_are_removed_from_view",
            "test_macro_config_object_selects_ifdef_arm",
            "test_macro_config_list_form",
            "test_no_macro_config_takes_else_arm",
            "test_reuses_prebuilt_view",
            "test_missing_generated_header_degrades",
            "test_no_sandbox_no_preprocess",
            "test_sandbox_used_with_network_deny",
            "test_single_tu_only_no_build_system",
        }
        # The one raw expand_function caller runs on a prebuilt view —
        # no subprocess, no transport surface.
        assert _callers_of(calls, "expand_function") == {
            "test_reuses_prebuilt_view",
        }
        assert _callers_of(calls, "expand_function_guarded") == {
            "_expand_function_guarded",
        }
        assert _callers_of(calls, "_expand_function_guarded") == {
            "test_function_range_selected_with_original_lines",
            "test_function_range_shows_expanded_macros",
            "test_degraded_view_degrades_function_expansion",
        }
        # Identity-collapsed surfaces carry the probe
        # (test_max_files_budget is deliberately probe-free: with
        # max_files=0 nothing spawns and its empty-spy assertion
        # proves it).
        assert _callers_of(calls, "skip_unless_cpp_carries_probe") == {
            "_probe_cpp",
        }
        assert _callers_of(calls, "_probe_cpp") == {
            "test_macro_defined_functions_recovered_with_attribution",
            "test_pre_expansion_definitions_not_reported",
            "test_plain_tu_recovers_nothing",
            "test_degraded_view_recovers_nothing",
            "test_macro_functions_added_to_checklist",
            "test_prefilter_skips_files_without_macro_invocations",
            "test_idempotent",
            "test_native_checklist_recovers_spliced_definition_macro",
        }
        # Placement: the probe runs BEFORE the collapsed-surface
        # adjudication it licenses.
        for test_name, adjudicator in (
            (
                "test_macro_defined_functions_recovered_with_attribution",
                "recover_macro_defined_functions",
            ),
            (
                "test_pre_expansion_definitions_not_reported",
                "recover_macro_defined_functions",
            ),
            (
                "test_plain_tu_recovers_nothing",
                "recover_macro_defined_functions",
            ),
            (
                "test_degraded_view_recovers_nothing",
                "recover_macro_defined_functions",
            ),
            (
                "test_macro_functions_added_to_checklist",
                "augment_checklist_with_macro_functions",
            ),
            (
                "test_prefilter_skips_files_without_macro_invocations",
                "augment_checklist_with_macro_functions",
            ),
            (
                "test_idempotent",
                "augment_checklist_with_macro_functions",
            ),
            (
                "test_native_checklist_recovers_spliced_definition_macro",
                "augment_checklist_with_macro_functions",
            ),
        ):
            order = _stmt_order("test_preprocessor_view.py", test_name)
            probe_at = order["_probe_cpp"]
            run_at = order[adjudicator]
            assert max(probe_at) < min(run_at), test_name

    def test_cpp_no_skip_directions_are_fenced(self) -> None:
        # The cpp no-skip direction tests in THIS file must route
        # through _fail_on_skip: pytest.raises does not intercept
        # Skipped, so without the fence an over-matching guard would
        # turn these product directions into silent skips.
        calls = _function_call_map("test_live_transport_guards.py")
        fenced = _callers_of(calls, "_fail_on_skip")
        assert {
            "test_cpp_availability_arm_stays_hard_on_unprobed_hosts",
            "test_cpp_availability_arm_is_exact_match_only",
            "test_cpp_errno_shape_is_exact_only",
            "test_cpp_product_reasons_do_not_skip",
            "test_cpp_ok_results_never_skip",
            "test_cpp_multi_error_results_do_not_skip",
            "test_cpp_function_expansion_product_stays_hard",
            "test_cpp_segfaulting_preprocessor_still_fails",
            "test_cpp_product_degradation_still_fails",
        } <= fenced
