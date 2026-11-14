"""Declaration custody preserves raw bytes and bounds retained state."""
from dataclasses import replace
import pytest
from core.audit.prepared_declaration_custody import DeclarationOwner
from core.audit.prepared_invocation_candidate import CandidateUnavailable


def own(raw):
    owner = DeclarationOwner(max_retained_bytes=16384, max_captures=4, max_selections=8)
    capture = owner.capture(raw, declared_build_association="declared-build",
                            max_database_bytes=4096, max_entries=4,
                            max_entry_bytes=2048, max_depth=16)
    return owner, capture


def test_exact_utf8_interval_preserves_spacing_and_escaped_braces():
    entry = ' { "file":"café.c", "directory":"/build", "arguments":["cc","a}\\\"{","@rsp"] }'.encode()
    raw = b"[\n" + entry + b"\r\n]"
    owner, capture = own(raw)
    selected = owner.select(capture, "café.c", max_entry_bytes=2048, max_entries=4)
    assert selected.selected_entry_bytes == entry.strip()
    start, end = selected.selected_interval
    assert raw[start:end] == selected.selected_entry_bytes
    assert selected.capture.database_bytes == raw and owner.retains(selected)
    assert selected.invocation.ordered_arguments == ("cc", 'a}"{', "@rsp")
    assert selected.invocation.response_file_references == ((2, "@rsp"),)
    assert selected.authenticated_build is False and capture.authenticated_build is False


@pytest.mark.parametrize("raw", [b'[{}', b'[{},]', b'[{}]x', b'[null]', b'[{"x":1,"x":2}]',
                                 b'[{"file":"a.c"},{"file":"a.c"}]',
                                 b'[{"file":"a.c","directory":"/b","command":"cc a.c"}]',
                                 b'[{"file":"a.c"},{}]', b'[NaN]', b'[{}{}]', b'["{"]'])
def test_malformed_or_unselectable_database_refuses(raw):
    with pytest.raises(CandidateUnavailable):
        owner, capture = own(raw)
        owner.select(capture, "a.c", max_entry_bytes=2048, max_entries=4)


def test_unowned_or_reconstructed_selection_does_not_gain_custody():
    owner, capture = own(b'[{"file":"a.c","directory":"/b","arguments":["cc"]}]')
    selected = owner.select(capture, "a.c", max_entry_bytes=2048, max_entries=4)
    assert not owner.retains(replace(selected, selected_entry_bytes=b"{}"))
    assert not owner.retains(replace(selected, selected_interval=(0, 2)))
    assert not owner.retains(replace(selected))
    assert not owner.retains(replace(selected, invocation=replace(selected.invocation, ordered_arguments=("evil",))))
    with pytest.raises(CandidateUnavailable, match="capture_not_owned"):
        DeclarationOwner(max_retained_bytes=16384, max_captures=4, max_selections=8).select(capture, "a.c", max_entry_bytes=2048, max_entries=4)


@pytest.mark.parametrize("field", ["max_database_bytes", "max_entries", "max_entry_bytes", "max_depth"])
@pytest.mark.parametrize("bad", [True, 0, -1, 1.5])
def test_caps_require_positive_integer_values(field, bad):
    caps = dict(max_database_bytes=4096, max_entries=4, max_entry_bytes=2048, max_depth=16)
    caps[field] = bad
    with pytest.raises(CandidateUnavailable):
        DeclarationOwner(max_retained_bytes=16384, max_captures=4, max_selections=8).capture(b"[]", declared_build_association="build", **caps)


def test_depth_and_whole_database_caps_refuse_instead_of_prefix():
    with pytest.raises(CandidateUnavailable):
        DeclarationOwner(max_retained_bytes=16384, max_captures=4, max_selections=8).capture(b'[{"nested":[[]]}]', declared_build_association="build",
                                  max_database_bytes=4096, max_entries=4, max_entry_bytes=2048, max_depth=2)
    with pytest.raises(CandidateUnavailable):
        DeclarationOwner(max_retained_bytes=16384, max_captures=4, max_selections=8).capture(b"[{}]", declared_build_association="build",
                                  max_database_bytes=3, max_entries=4, max_entry_bytes=2048, max_depth=4)


ENTRY = b'{"file":"a.c","directory":"/b","arguments":["cc"]}'
DATABASE = b'[' + ENTRY + b']'
CAPTURE_ARGS = dict(declared_build_association="build", max_database_bytes=4096,
                    max_entries=4, max_entry_bytes=2048, max_depth=16)
CAPTURE_CHARGE = len(DATABASE) + len(b"build")


def make_owner(*, byte_cap=16384, captures=4, selections=8):
    return DeclarationOwner(max_retained_bytes=byte_cap, max_captures=captures,
                            max_selections=selections)


def selected(owner, capture):
    return owner.select(capture, "a.c", max_entry_bytes=2048, max_entries=4)


@pytest.mark.parametrize("field", ["max_retained_bytes", "max_captures", "max_selections"])
@pytest.mark.parametrize("bad", [True, 0, -1, 1.5])
def test_owner_requires_explicit_positive_integer_budgets(field, bad):
    caps = dict(max_retained_bytes=4096, max_captures=4, max_selections=4)
    caps[field] = bad
    with pytest.raises(CandidateUnavailable, match="invalid_owner_budget"):
        DeclarationOwner(**caps)


def test_capture_byte_refusal_is_atomic_and_exact_limit_admits():
    owner = make_owner(byte_cap=CAPTURE_CHARGE)
    with pytest.raises(CandidateUnavailable, match="payload_retention_exhausted"):
        owner.capture(DATABASE + b" ", **CAPTURE_ARGS)
    assert owner.retained_payload_bytes == 0
    capture = owner.capture(DATABASE, **CAPTURE_ARGS)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE
    with pytest.raises(CandidateUnavailable, match="payload_retention_exhausted"):
        selected(owner, capture)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE
    assert owner.release_capture(capture) and owner.retained_payload_bytes == 0


def test_equal_captures_charge_independently_and_release_only_original():
    owner = make_owner(byte_cap=CAPTURE_CHARGE * 2, captures=2)
    first = owner.capture(DATABASE, **CAPTURE_ARGS)
    second = owner.capture(DATABASE, **CAPTURE_ARGS)
    assert first is not second and owner.retained_payload_bytes == CAPTURE_CHARGE * 2
    assert not owner.release_capture(replace(first))
    with pytest.raises(CandidateUnavailable, match="capture_retention_exhausted"):
        owner.capture(DATABASE, **CAPTURE_ARGS)
    assert owner.release_capture(first)
    assert not owner.release_capture(first)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE
    assert owner.release_capture(second) and owner.retained_payload_bytes == 0


def test_failed_parse_and_failed_selection_do_not_consume_retention_slots():
    owner = make_owner(captures=1, selections=1)
    with pytest.raises(CandidateUnavailable):
        owner.capture(b"[{", **CAPTURE_ARGS)
    assert owner.retained_payload_bytes == 0
    capture = owner.capture(DATABASE, **CAPTURE_ARGS)
    with pytest.raises(CandidateUnavailable):
        owner.select(capture, "missing.c", max_entry_bytes=2048, max_entries=4)
    selection = selected(owner, capture)
    assert owner.retains(selection)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE + len(ENTRY)


def test_duplicate_selections_charge_separate_slices_and_release_restores_slot():
    owner = make_owner(byte_cap=CAPTURE_CHARGE + 2 * len(ENTRY), selections=2)
    capture = owner.capture(DATABASE, **CAPTURE_ARGS)
    first, second = selected(owner, capture), selected(owner, capture)
    assert first is not second and owner.retains(first) and owner.retains(second)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE + 2 * len(ENTRY)
    with pytest.raises(CandidateUnavailable, match="selection_retention_exhausted"):
        selected(owner, capture)
    assert not owner.release_selection(replace(first))
    assert owner.release_selection(first)
    assert not owner.retains(first) and owner.retains(second)
    assert not owner.release_selection(first)
    replacement = selected(owner, capture)
    assert owner.retains(replacement)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE + 2 * len(ENTRY)


def test_byte_exhaustion_does_not_invalidate_issued_selection():
    owner = make_owner(byte_cap=CAPTURE_CHARGE + len(ENTRY))
    capture = owner.capture(DATABASE, **CAPTURE_ARGS)
    first = selected(owner, capture)
    with pytest.raises(CandidateUnavailable, match="payload_retention_exhausted"):
        selected(owner, capture)
    assert owner.retains(first)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE + len(ENTRY)


def test_capture_release_invalidates_only_its_selections():
    owner = make_owner()
    first = owner.capture(DATABASE, **CAPTURE_ARGS)
    second = owner.capture(DATABASE, **CAPTURE_ARGS)
    one, two = selected(owner, first), selected(owner, second)
    assert owner.release_capture(first)
    assert not owner.retains(one) and owner.retains(two)
    assert not owner.release_selection(one)
    assert owner.retained_payload_bytes == CAPTURE_CHARGE + len(ENTRY)
    with pytest.raises(CandidateUnavailable, match="capture_not_owned"):
        selected(owner, first)


def test_close_is_terminal_idempotent_and_releases_all_owner_references():
    owner = make_owner()
    capture = owner.capture(DATABASE, **CAPTURE_ARGS)
    selection = selected(owner, capture)
    owner.close()
    owner.close()
    assert not owner.retains(selection)
    assert owner.retained_payload_bytes == 0
    assert not owner.release_capture(capture) and not owner.release_selection(selection)
    with pytest.raises(CandidateUnavailable, match="owner_closed"):
        owner.capture(DATABASE, **CAPTURE_ARGS)
    with pytest.raises(CandidateUnavailable, match="owner_closed"):
        selected(owner, capture)


def test_invalid_association_encoding_does_not_consume_owner_budget():
    owner = make_owner(captures=1)
    with pytest.raises(CandidateUnavailable, match="build_association_unavailable"):
        owner.capture(DATABASE, **{**CAPTURE_ARGS, "declared_build_association": "\ud800"})
    assert owner.retained_payload_bytes == 0
    capture = owner.capture(DATABASE, **CAPTURE_ARGS)
    assert owner.retains(selected(owner, capture))
