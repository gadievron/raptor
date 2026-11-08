"""Exit-code and eligible-count semantics of
``libexec/raptor-compile-invariants``.

An all-failed compilation pass (e.g. LLM transport down) must exit
nonzero so chained pipeline steps don't proceed as if rules were
produced, and the "eligible" progress count must mirror the filters
the compiler actually applies (grade ladder, --min-confidence, --max).
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

import pytest

from core.testing.module_views import scoped_function_imports

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-compile-invariants"


@pytest.fixture(scope="module")
def cli():
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_compile_invariants", str(SCRIPT),
        )
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        with patch.object(sys, "path", sys.path.copy()):
            loader.exec_module(mod)
        yield mod
    finally:
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


def _invariant(iid: str, confidence: str = "traced") -> SimpleNamespace:
    return SimpleNamespace(
        id=iid,
        statement="s",
        negation="n",
        mechanical_rule=None,
        confidence=confidence,
    )


def _result(iid: str, success: bool) -> SimpleNamespace:
    return SimpleNamespace(
        invariant_id=iid,
        success=success,
        rule_id=f"rule-{iid}" if success else None,
        matches=[],
        errors=[] if success else ["compile refused"],
    )


def _run_main(cli, monkeypatch, tmp_path: Path, invariants, results,
              extra_argv: list[str] | None = None) -> int:
    (tmp_path / "domain-model.json").write_text("{}", encoding="utf-8")

    from core.concepts import compiler as compiler_mod
    from core.concepts import model as model_mod

    saved: list = []
    fake_model = SimpleNamespace(
        invariants=invariants,
        save=lambda p: saved.append(p),
    )
    monkeypatch.setattr(
        model_mod.DomainModel, "load", staticmethod(lambda p: fake_model),
    )
    monkeypatch.setattr(
        compiler_mod, "compile_model",
        lambda *a, **k: results,
    )

    client_mod = ModuleType("core.llm.client")
    client_mod.LLMClient = lambda **k: object()
    # Dispatcher routing has its own contracts in test_llm_dispatcher_bootstrap.
    lifecycle_mod = ModuleType("core.llm.dispatcher.lifecycle")
    lifecycle_mod.ensure_route_for_client = lambda *a, **k: None

    monkeypatch.setattr(
        "sys.argv",
        ["raptor-compile-invariants", str(tmp_path),
         *(extra_argv or [])],
    )
    with scoped_function_imports(cli, ("main",), {
        "core.llm.client": client_mod,
        "core.llm.dispatcher.lifecycle": lifecycle_mod,
    }):
        return cli.main()


class TestExitCode:
    def test_all_failed_exits_nonzero(self, cli, monkeypatch,
                                      tmp_path: Path):
        rc = _run_main(
            cli, monkeypatch, tmp_path,
            invariants=[_invariant("i1"), _invariant("i2")],
            results=[_result("i1", False), _result("i2", False)],
        )
        assert rc == 1

    def test_partial_success_exits_zero(self, cli, monkeypatch,
                                        tmp_path: Path):
        rc = _run_main(
            cli, monkeypatch, tmp_path,
            invariants=[_invariant("i1"), _invariant("i2")],
            results=[_result("i1", True), _result("i2", False)],
        )
        assert rc == 0

    def test_nothing_eligible_exits_zero(self, cli, monkeypatch,
                                         tmp_path: Path):
        rc = _run_main(cli, monkeypatch, tmp_path,
                       invariants=[], results=[])
        assert rc == 0


class TestEligibleCount:
    def test_count_respects_min_confidence_and_max(
        self, cli, monkeypatch, tmp_path: Path, capsys,
    ):
        invariants = [
            _invariant("low", confidence="inferred"),  # below floor
            _invariant("a"),
            _invariant("b"),
            _invariant("c"),
        ]
        rc = _run_main(
            cli, monkeypatch, tmp_path,
            invariants=invariants,
            results=[_result("a", True)],
            extra_argv=["--min-confidence", "traced", "--max", "2"],
        )
        assert rc == 0
        err = capsys.readouterr().err
        # 3 pass the confidence floor, capped at --max 2.
        assert "2 invariant(s) eligible for compilation" in err


@pytest.mark.parametrize("finish", ["normal", "error", "interrupt"])
def test_run_main_restores_private_client_imports(finish, tmp_path):
    from core.concepts import compiler as compiler_mod
    from core.concepts import model as model_mod

    cli_mod = ModuleType("owned_compile_cli")
    exec("def main():\n    from core.llm.client import LLMClient\n"
         "    assert LLMClient() is not None\n"
         "    from core.llm.dispatcher.lifecycle import ensure_route_for_client\n"
         "    ensure_route_for_client(object(), 'owned')\n"
         "    if failure is not None: raise failure('injected')\n"
         "    return 7\n", vars(cli_mod))
    cli_mod.failure = {"normal": None, "error": RuntimeError, "interrupt": KeyboardInterrupt}[finish]
    borrowed = ModuleType("core.llm.client")
    borrowed.LLMClient = object()
    borrowed_lifecycle = ModuleType("core.llm.dispatcher.lifecycle")
    borrowed_lifecycle.ensure_route_for_client = object()
    original_main = cli_mod.main
    original_load = vars(model_mod.DomainModel)["load"]
    original_compile = compiler_mod.compile_model
    missing = object()
    inherited_client = sys.modules.get("core.llm.client", missing)
    inherited_lifecycle = sys.modules.get("core.llm.dispatcher.lifecycle", missing)

    with pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, "core.llm.client", borrowed)
        scope.setitem(sys.modules, "core.llm.dispatcher.lifecycle", borrowed_lifecycle)
        if cli_mod.failure is None:
            assert _run_main(cli_mod, scope, tmp_path, [], []) == 7
        else:
            with pytest.raises(cli_mod.failure, match="injected"):
                _run_main(cli_mod, scope, tmp_path, [], [])
        assert cli_mod.main is original_main
        assert sys.modules["core.llm.client"] is borrowed
        assert not callable(borrowed.LLMClient), "borrowed client binding was replaced"
        assert sys.modules["core.llm.dispatcher.lifecycle"] is borrowed_lifecycle
        assert not callable(borrowed_lifecycle.ensure_route_for_client)

    assert sys.modules.get("core.llm.client", missing) is inherited_client
    assert sys.modules.get("core.llm.dispatcher.lifecycle", missing) is inherited_lifecycle
    assert vars(model_mod.DomainModel)["load"] is original_load
    assert compiler_mod.compile_model is original_compile
