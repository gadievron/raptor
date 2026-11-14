"""Input-owner identity and lifetime controls; no backend execution fixtures."""

from concurrent.futures import ThreadPoolExecutor
from copy import copy, deepcopy
from dataclasses import FrozenInstanceError

import pytest

from core.audit.prepared_execution_attempt import ExecutionAttemptReference, ExecutionInputOwner
from core.audit.prepared_execution_inputs import InputsUnavailable


CAPS = dict(max_args=4, max_env=4, max_item_bytes=128, max_total_bytes=512)


def owner(**kwargs):
    return ExecutionInputOwner(**{"max_attempts": 2, "max_retained_bytes": 1024, **kwargs})


def reserve(subject, argv=None, environment=None):
    return subject.reserve(["/compiler", "unit.c"] if argv is None else argv,
                           {"LANG": "C"} if environment is None else environment,
                           "/owned", **CAPS)


def test_selected_retry_cannot_borrow_prior_attempt_inputs():
    subject = owner()
    first, final = reserve(subject, ["/compiler", "first.c"]), reserve(subject)
    old = subject.handoff_for_dispatch(first)
    current = subject.handoff_for_dispatch(final)
    subject.select_terminal(final)
    assert subject.read_selected(final) is current
    assert current.inputs.argv == (b"/compiler", b"unit.c")
    assert old.inputs.argv == (b"/compiler", b"first.c")
    with pytest.raises(InputsUnavailable, match="selected_attempt_mismatch"):
        subject.read_selected(first)
    assert current.authenticated_build is False
    assert current.observed_child_context is False


@pytest.mark.parametrize("alter", [copy, deepcopy, lambda ref: ExecutionAttemptReference(ref.ordinal),
                                   lambda ref: {"ordinal": ref.ordinal}, lambda ref: None])
def test_value_equal_or_serialised_references_are_not_owned(alter):
    subject = owner()
    reference = reserve(subject)
    with pytest.raises(InputsUnavailable, match="unowned_attempt_reference"):
        subject.handoff_for_dispatch(alter(reference))
    assert subject.handoff_for_dispatch(reference).attempt is reference


def test_foreign_owner_same_ordinal_is_refused():
    first, second = owner(), owner()
    foreign, local = reserve(first), reserve(second)
    assert foreign == local and foreign is not local
    with pytest.raises(InputsUnavailable, match="unowned_attempt_reference"):
        second.handoff_for_dispatch(foreign)
    assert second.handoff_for_dispatch(local).attempt is local


def test_same_attempt_handoff_is_single_use():
    subject = owner()
    reference = reserve(subject)
    subject.handoff_for_dispatch(reference)
    with pytest.raises(InputsUnavailable, match="attempt_already_handed_off"):
        subject.handoff_for_dispatch(reference)


def test_selection_requires_handoff_and_is_terminal():
    subject = owner()
    first, second = reserve(subject), reserve(subject)
    with pytest.raises(InputsUnavailable, match="terminal_attempt_unselected"):
        subject.read_selected(first)
    with pytest.raises(InputsUnavailable, match="attempt_not_handed_off"):
        subject.select_terminal(first)
    subject.handoff_for_dispatch(first)
    subject.select_terminal(first)
    for action in (lambda: reserve(subject), lambda: subject.handoff_for_dispatch(second),
                   lambda: subject.select_terminal(first)):
        with pytest.raises(InputsUnavailable, match="terminal_attempt_already_selected"):
            action()


def test_source_and_returned_container_mutation_cannot_change_selected_bytes():
    subject = owner()
    argv, env = ["/compiler", "secret.c"], {"TOKEN": "secret-value", "LANG": "C"}
    reference = reserve(subject, argv, env)
    argv[1], env["TOKEN"] = "other.c", "other"
    handoff = subject.handoff_for_dispatch(reference)
    handoff.inputs.exec_inputs()[1][b"TOKEN"] = b"changed"
    subject.select_terminal(reference)
    selected = subject.read_selected(reference)
    assert selected.inputs.argv == (b"/compiler", b"secret.c")
    assert selected.inputs.environment == ((b"TOKEN", b"secret-value"), (b"LANG", b"C"))
    assert "secret" not in repr(selected) and "TOKEN" not in repr(selected)
    with pytest.raises(FrozenInstanceError):
        selected.attempt = ExecutionAttemptReference(4)


def test_failed_snapshot_does_not_consume_attempt_budget():
    subject = owner(max_attempts=1)
    with pytest.raises(InputsUnavailable):
        reserve(subject, ["relative"])
    assert reserve(subject).ordinal == 0
    with pytest.raises(InputsUnavailable, match="attempt_count_budget"):
        reserve(subject)


def test_retained_payload_budget_counts_all_attempts_even_after_handoff():
    sample = owner()
    size = sample.handoff_for_dispatch(reserve(sample)).inputs.payload_bytes
    subject = owner(max_retained_bytes=size)
    first = reserve(subject)
    subject.handoff_for_dispatch(first)
    with pytest.raises(InputsUnavailable, match="retained_input_byte_budget"):
        reserve(subject)
    subject.select_terminal(first)
    assert subject.read_selected(first).inputs.payload_bytes == size


@pytest.mark.parametrize("field", ["max_attempts", "max_retained_bytes"])
@pytest.mark.parametrize("value", [True, 0, -1, 1.5])
def test_owner_budgets_are_exact_positive_integers(field, value):
    with pytest.raises(InputsUnavailable, match="invalid_attempt_budget"):
        owner(**{field: value})


def test_close_refuses_all_owner_operations_but_does_not_claim_external_revocation():
    subject = owner()
    reference = reserve(subject)
    handed_off = subject.handoff_for_dispatch(reference)
    subject.select_terminal(reference)
    subject.close()
    subject.close()
    for action in (lambda: reserve(subject), lambda: subject.handoff_for_dispatch(reference),
                   lambda: subject.select_terminal(reference), lambda: subject.read_selected(reference)):
        with pytest.raises(InputsUnavailable, match="input_owner_closed"):
            action()
    assert handed_off.inputs.argv == (b"/compiler", b"unit.c")


def test_two_concurrent_consumers_cannot_replay_one_handoff():
    subject = owner()
    reference = reserve(subject)

    def consume():
        try:
            return subject.handoff_for_dispatch(reference)
        except InputsUnavailable as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: consume(), range(2)))
    assert sum(not isinstance(item, str) for item in results) == 1
    assert results.count("attempt_already_handed_off") == 1


def test_interrupted_publication_cannot_leave_retained_bytes_uncharged():
    sample = owner()
    size = sample.handoff_for_dispatch(reserve(sample)).inputs.payload_bytes
    subject = owner(max_retained_bytes=size)

    class InterruptAfterInsert(dict):
        interrupted = False

        def __setitem__(self, key, value):
            super().__setitem__(key, value)
            if not self.interrupted:
                self.interrupted = True
                raise KeyboardInterrupt("after retained record publication")

    subject._attempts = InterruptAfterInsert()
    with pytest.raises(KeyboardInterrupt, match="after retained record publication"):
        reserve(subject)
    with pytest.raises(InputsUnavailable, match="retained_input_byte_budget"):
        reserve(subject)
    subject.close()
