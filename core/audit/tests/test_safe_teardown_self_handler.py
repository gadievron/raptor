"""Container syntax cannot supply an executing-item teardown contract."""

import json

import pytest

from core.audit.callback_lifetime import check_safe_teardown


@pytest.mark.parametrize("source", [
    pytest.param(
        "other = container_of(w, struct unrelated, work); "
        "del_timer(&d->timer); kfree(d);", id="unrelated-container"),
    pytest.param(
        "d = container_of(w, struct dev, work); "
        "del_timer(&d->timer); kfree(d);", id="work-derived-timer-cancel"),
    pytest.param(
        "d = container_of(t, struct dev, timer); "
        "cancel_work(&d->work); kfree(d);", id="timer-derived-work-cancel"),
    pytest.param(
        "d = container_of(w, struct dev, first); "
        "cancel_work(&d->second); kfree(d);", id="different-work-member"),
    pytest.param(
        "void callback(struct work_struct *w) { "
        "struct dev *d = container_of(w, struct dev, work); "
        "cancel_work(&d->work); kfree(d); }", id="matching-work-no-contract"),
    pytest.param(
        "void callback(struct timer_list *t) { "
        "struct dev *d = container_of(t, struct dev, timer); "
        "del_timer(&d->timer); kfree(d); }", id="matching-timer-no-contract"),
    pytest.param(
        "INIT_WORK(&d->work, callback); "
        "d = container_of(w, struct dev, work); "
        "cancel_work(&d->work); kfree(d);", id="registration-not-execution-contract"),
    pytest.param(
        "/* executing work is non-reentrant */ "
        "d = container_of(w, struct dev, work); "
        "cancel_work(&d->work); kfree(d);", id="comment-is-not-attestation"),
    pytest.param(
        "d = container_of(item, struct dev, member); "
        "cancel_work(select_item(d)); kfree(d);", id="ambiguous-item"),
    pytest.param(
        "d = container_of(w, struct dev, work); "
        "e = container_of(t, struct dev, timer); "
        "del_timer(&e->timer); kfree(d);", id="multiple-containers"),
    pytest.param(
        "d = container_of(w, struct dev, work); "
        "kfree(d); cancel_work(&d->work);", id="free-before-cancel"),
    pytest.param(
        "d = container_of(w, struct dev, work); "
        "cancel_work_sync(&d->work); kfree(d); "
        "del_timer(&e->timer); kfree(e);", id="later-free-keeps-async-refusal"),
    pytest.param(
        "d = container_of(w, struct dev, work); "
        "kfree(d); cancel_work_sync(&d->work);", id="free-before-wait"),
    pytest.param(
        "/* d = container_of(w, struct dev, work); */ "
        "del_timer(&d->timer); kfree(d);", id="commented-container"),
    pytest.param(
        'log("d = container_of(w, struct dev, work)"); '
        "del_timer(&d->timer); kfree(d);", id="string-container"),
])
def test_unproven_self_handler_is_non_discharging(source):
    result = check_safe_teardown(source)
    assert result.safe is False
    assert result.no_dealloc is False


@pytest.mark.parametrize(("source", "reason", "no_dealloc"), [
    ("d = container_of(w, struct dev, work); cancel_work_sync(&d->work); kfree(d);",
     "waiting teardown", False),
    ("d = container_of(w, struct dev, work); kfree_rcu(d, rcu);",
     "RCU-deferred reclamation", False),
    ("d = container_of(w, struct dev, work); cancel_work(&d->work);",
     "no deallocation", True),
], ids=["waiting-control", "rcu-control", "no-free-control"])
def test_existing_teardown_arms_remain_available(source, reason, no_dealloc):
    result = check_safe_teardown(source)
    assert result.safe is True
    assert result.reason.startswith(reason)
    assert result.no_dealloc is no_dealloc


def _lifetime_outcome(cwe):
    from core.audit.orchestrator import ReviewOutcome

    return ReviewOutcome("owned.c", "teardown", "clean", "owned assessment",
                         hypotheses=[{"mechanism": f"{cwe} callback lifetime",
                                      "confidence": "refuted",
                                      "counter": "claimed self-handler non-reentrancy"}])


def _rescue(outcome, source, output):
    from core.audit import refutation
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(refutation, {"_threading_seen_cache": {}}):
        return refutation.rescue_self_refuted(outcome, source=source, out_dir=output)


@pytest.mark.parametrize("cwe", ["CWE-415", "CWE-416"])
def test_unrelated_container_cannot_enable_owned_discharge_record(tmp_path, cwe):
    source = ("other = container_of(w, struct unrelated, work); "
              "del_timer(&d->timer); kfree(d);")
    verdict = _rescue(_lifetime_outcome(cwe), source, tmp_path)
    assert verdict is not None and verdict.demote_to == "suspicious"
    path = tmp_path / "suppressions.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    assert all(row.get("verdict") != "in_function_witness_corroborates_dismissal" for row in rows)


def test_waiting_control_still_requires_durable_owned_record(tmp_path):
    source = "cancel_work_sync(&d->work); kfree(d);"
    assert _rescue(_lifetime_outcome("CWE-416"), source, tmp_path) is None
    rows = [json.loads(line) for line in (tmp_path / "suppressions.jsonl").read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["verdict"] == "in_function_witness_corroborates_dismissal"
    assert rows[0]["dropped"] is False


def test_unrecordable_waiting_control_remains_non_discharging(tmp_path):
    output = tmp_path / "owned-file"
    output.write_text("preserved")
    verdict = _rescue(_lifetime_outcome("CWE-416"),
                      "cancel_work_sync(&d->work); kfree(d);", output)
    assert verdict is not None and verdict.demote_to == "suspicious"
    assert output.read_text() == "preserved"
