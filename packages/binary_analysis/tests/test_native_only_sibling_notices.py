"""Native-only binary views identify older portable receipts without new work."""
import copy
import json
from types import SimpleNamespace

import pytest

from core.reporting.options import ReportOptions
from core.testing.state_isolation import pin_user_state_dirs
from packages.binary_analysis import (
    corpus_reporting,
    graph_reporting,
    harness_reporting,
    hunt_reporting,
    sibling_reporting,
)

KINDS = ("corpus", "graph", "harness", "hunt", "sibling")


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path)


def _case(kind, tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    reference = inputs / "recorded-reference.json"
    reference.write_text("{}", encoding="utf-8")
    args = SimpleNamespace(_report_options=ReportOptions(("json",)), report_format=["json"],
                           report_output=None, run_dir=str(run), target=str(reference),
                           edges=False, evidence=False, kind=None, tier=None)
    if kind == "corpus":
        module = corpus_reporting
        payload = {"summary": {"samples_seen": 1, "samples_profiled": 1, "samples_skipped": 0,
                               "family_count": 0}, "families": [], "options": {},
                   "provenance": {"tier": "corpus_statistic"}, "artifacts": {}}
        invoke = lambda value: module.complete_corpus_report(args, value, inputs, run)
    elif kind == "graph":
        module = graph_reporting
        payload = {"exists": True, "nodes": {"function": 1}, "edges": {}, "evidence": {}}
        invoke = lambda value: module.complete_graph_report(args, value, reference, 0)
    elif kind == "harness":
        module = harness_reporting
        payload = {"id": "recorded-plan", "status": "needs_abi_contract",
                   "target": {"path": str(reference)}, "unknowns": ["ABI not verified"],
                   "verification_contract": [], "linked_evidence": {}, "artifacts": {}}
        invoke = lambda value: module.complete_harness_report(args, value, run)
    elif kind == "hunt":
        module = hunt_reporting
        payload = [{"mode": "anchor", "binary": str(reference), "families": [],
                    "scan": {"degraded": True}, "artifacts": {}}]
        invoke = lambda value: module.complete_hunt_report(args, value, run)
    else:
        module = sibling_reporting
        payload = {"clusters": [], "asymmetries": [], "artifacts": {},
                   "claim": "structural_lead_only", "hypothesis_seeds_emitted": 0}
        invoke = lambda value: module.complete_sibling_report(args, value, run)
    native = run / "captured-native.json"
    native.write_text(json.dumps(payload), encoding="utf-8")
    return module, args, json.loads(native.read_text(encoding="utf-8")), invoke, run, native


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("disabled", [False, True])
def test_native_only_view_preserves_prior_receipt_and_warns_once(
    tmp_path, monkeypatch, capsys, kind, disabled,
):
    module, args, payload, invoke, run, native = _case(kind, tmp_path)
    original = copy.deepcopy(payload)
    result = invoke(payload)
    assert result is not None and not result.errors
    assert payload == original and (run / "reporting-manifest.json").is_file()
    portable = {p.relative_to(run): p.read_bytes() for p in run.rglob("*")
                if p.is_file() and p != native}
    native.write_text(json.dumps({"current": "PRIVATE_CURRENT_CAPTURE_625"}), encoding="utf-8")
    native_bytes = native.read_bytes()
    args._report_options = ReportOptions(enabled=not disabled)
    args.report_format = None

    def forbidden(*a, **kw):
        pytest.fail("native-only completion must not construct another portable result")

    monkeypatch.setattr(module, "NativeResult", forbidden)
    capsys.readouterr()
    assert invoke(payload) is None
    streams = capsys.readouterr()
    assert streams.err.count("prior report artifacts were not refreshed") == 1
    assert "Summary" not in streams.err and "PRIVATE_CURRENT_CAPTURE_625" not in streams.err
    assert native.read_bytes() == native_bytes and payload == original
    assert {p.relative_to(run): p.read_bytes() for p in run.rglob("*")
            if p.is_file() and p != native} == portable


@pytest.mark.parametrize("kind", KINDS)
def test_fresh_native_only_view_does_not_create_a_portable_receipt(tmp_path, monkeypatch, capsys, kind):
    module, args, payload, invoke, run, native = _case(kind, tmp_path)
    args._report_options = ReportOptions()
    args.report_format = None
    before = native.read_bytes()

    def forbidden(*a, **kw):
        pytest.fail("fresh native-only completion must not construct a portable result")

    monkeypatch.setattr(module, "NativeResult", forbidden)
    assert invoke(payload) is None
    streams = capsys.readouterr()
    assert streams.out == streams.err == ""
    assert list(run.iterdir()) == [native] and native.read_bytes() == before
