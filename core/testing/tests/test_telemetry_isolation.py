"""Telemetry fixtures preserve borrowed counters, aliases, and warning latches."""

import copy
from importlib import import_module
from types import SimpleNamespace

import pytest

from core.security import prompt_telemetry
from core.testing.telemetry import pin_defense_telemetry

MODULES = [
    "packages.llm_analysis.tests.test_dispatch",
    "packages.llm_analysis.tests.test_defense_wiring",
    "packages.llm_analysis.tests.test_orchestrator",
    "packages.sca.llm.tests.test_run_stage",
    "packages.sca.llm.tests.test_adversarial_injection",
    "packages.sca.llm.tests.test_cross_family",
    "packages.fuzzing.tests.test_harness_generator",
    "packages.binary_analysis.tests.test_radare2_understand",
]

SCA_MODULES = {name for name in MODULES if name.startswith("packages.sca.")}
HARNESS_MODULE = "packages.fuzzing.tests.test_harness_generator"


def populated_collector():
    collector = prompt_telemetry.DefenseTelemetry()
    collector.record_response(
        model_id="borrowed",
        profile_name="test",
        nonce="0123456789abcdef",
        raw_response="0123456789abcdef",
        schema_accepted=False,
        schema_retried=False,
    )
    for _ in range(5):
        collector.record_preflight(hit=True)
    collector.set_probe_result("borrowed", False)
    collector.record_weakened_override("borrowed", "existing run")
    return collector


def state(collector):
    return copy.deepcopy(
        {key: value for key, value in vars(collector).items() if key != "_lock"}
    )


@pytest.mark.parametrize("module_name", MODULES)
@pytest.mark.parametrize("error", [None, RuntimeError, KeyboardInterrupt])
def test_module_fixture_preserves_borrowed_state(module_name, error, monkeypatch):
    module = import_module(module_name)
    from packages.sca import llm
    from packages.fuzzing import harness_generator

    borrowed = populated_collector()
    alias_borrowed = populated_collector()
    harness_borrowed = populated_collector()
    monkeypatch.setattr(prompt_telemetry, "defense_telemetry", borrowed)
    monkeypatch.setattr(llm, "defense_telemetry", alias_borrowed)
    monkeypatch.setattr(harness_generator, "defense_telemetry", harness_borrowed)
    before, alias_before = state(borrowed), state(alias_borrowed)
    harness_before = state(harness_borrowed)

    def invoke():
        with pytest.MonkeyPatch.context() as scope:
            module._isolated_defense_telemetry.__wrapped__(scope)
            owned = prompt_telemetry.defense_telemetry
            assert owned is not borrowed
            assert state(owned) == state(prompt_telemetry.DefenseTelemetry())
            if module_name in SCA_MODULES:
                assert llm.defense_telemetry is owned
            if module_name == HARNESS_MODULE:
                assert harness_generator.defense_telemetry is owned
            owned.record_preflight(hit=True)
            owned.set_probe_result("owned", True)
            owned.record_weakened_override("owned", "test")
            # The production orchestrator resets at entry. It must clear only
            # this test's collector, never the object borrowed from its caller.
            owned.reset()
            owned.record_preflight(hit=False)
            if error is not None:
                raise error("test interrupted")

    if error is None:
        invoke()
    else:
        with pytest.raises(error, match="test interrupted"):
            invoke()
    assert prompt_telemetry.defense_telemetry is borrowed
    assert llm.defense_telemetry is alias_borrowed
    assert state(borrowed) == before
    assert state(alias_borrowed) == alias_before
    assert harness_generator.defense_telemetry is harness_borrowed
    assert state(harness_borrowed) == harness_before


@pytest.mark.parametrize("module_name", MODULES)
def test_each_fixture_invocation_gets_a_fresh_collector(module_name):
    module = import_module(module_name)
    collectors = []
    for _ in range(2):
        with pytest.MonkeyPatch.context() as scope:
            module._isolated_defense_telemetry.__wrapped__(scope)
            collector = prompt_telemetry.defense_telemetry
            assert collector.summary()["defense_telemetry"]["preflight"]["checked"] == 0
            collector.record_preflight(hit=True)
            collectors.append(collector)
    assert collectors[0] is not collectors[1]


@pytest.mark.parametrize("stage", [0, 1, 2])
@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_partial_setup_uses_the_fixture_undo_stack(stage, error, monkeypatch):
    borrowed = populated_collector()
    consumers = [
        SimpleNamespace(defense_telemetry=populated_collector()) for _ in range(2)
    ]
    monkeypatch.setattr(prompt_telemetry, "defense_telemetry", borrowed)
    originals = [borrowed, *(consumer.defense_telemetry for consumer in consumers)]
    before = [state(collector) for collector in originals]

    with pytest.raises(error, match="setup interrupted"):
        with pytest.MonkeyPatch.context() as scope:

            class InterruptedPatch:
                calls = 0

                def setattr(self, module, name, value):
                    scope.setattr(module, name, value)
                    self.calls += 1
                    if self.calls == stage + 1:
                        raise error("setup interrupted")

            pin_defense_telemetry(InterruptedPatch(), *consumers)

    restored = [
        prompt_telemetry.defense_telemetry,
        *(c.defense_telemetry for c in consumers),
    ]
    assert all(actual is original for actual, original in zip(restored, originals))
    assert [state(collector) for collector in restored] == before
