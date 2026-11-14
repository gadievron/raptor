"""Declared invocation selection preserves raw argument material."""

from dataclasses import FrozenInstanceError

import pytest

from core.audit.prepared_invocation_candidate import CandidateUnavailable, select_candidate


RAW = b'{ "directory": "/declared/build", "file": "src/a.cpp", "arguments": ["clang++", "@flags.rsp", "-DNAME=a b", "src/a.cpp"] }'


def select(entries=(RAW,), **kwargs):
    return select_candidate(entries, "src/a.cpp", max_entry_bytes=4096, max_entries=16, **kwargs)


def test_exact_declarations_remain_untrusted_and_immutable():
    candidate = select()
    assert candidate.selected_entry_bytes == RAW
    assert candidate.translation_unit == "src/a.cpp"
    assert candidate.declared_directory == "/declared/build"
    assert candidate.ordered_arguments == ("clang++", "@flags.rsp", "-DNAME=a b", "src/a.cpp")
    assert candidate.response_file_references == ((1, "@flags.rsp"),)
    assert candidate.authenticated_build is False
    with pytest.raises(FrozenInstanceError):
        candidate.translation_unit = "other.cpp"


@pytest.mark.parametrize("entries", [(), (RAW, RAW), (RAW.replace(b"src/a.cpp", b"src/./a.cpp"),)])
def test_missing_duplicate_and_unproven_path_aliases_refuse(entries):
    with pytest.raises(CandidateUnavailable, match="missing_or_ambiguous_selection"):
        select(entries)


@pytest.mark.parametrize("raw", [
    b'{"file":"src/a.cpp","directory":"/b","command":"clang++ src/a.cpp"}',
    b'{"file":"src/a.cpp","directory":"/b","arguments":["cc", 7]}',
    b'{"file":"src/a.cpp","file":"other.cpp"}',
    b'null', b'\xff',
    b'{"file":"src/a.cpp","directory":"/b","arguments":["cc", "@"]}',
])
def test_no_shell_coercion_duplicate_keys_or_malformed_selection(raw):
    with pytest.raises(CandidateUnavailable):
        select((raw,))


def test_unknown_entry_cannot_be_silently_ignored():
    with pytest.raises(CandidateUnavailable, match="malformed_entry"):
        select((RAW, b'{'))


@pytest.mark.parametrize("constant", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_json_constants_in_unselected_metadata_refuse(constant):
    raw = RAW[:-1] + b', "metadata": ' + constant + b'}'
    with pytest.raises(CandidateUnavailable, match="non_json_constant"):
        select((raw,))


def test_deep_json_refuses_without_leaking_recursion_error():
    raw = b'[' * 2000 + b'0' + b']' * 2000
    with pytest.raises(CandidateUnavailable):
        select_candidate((raw,), "src/a.cpp", max_entry_bytes=8192, max_entries=1)


def test_large_integer_metadata_has_no_selected_command_authority():
    # Python configurations may accept this integer or refuse it at decoding.
    # Neither outcome can make an entry without a TU association selectable.
    raw = b'{"metadata":' + b'9' * 5000 + b'}'
    with pytest.raises(CandidateUnavailable):
        select_candidate((raw,), "src/a.cpp", max_entry_bytes=8192, max_entries=1)


def test_byte_and_count_budgets_refuse_before_selection():
    with pytest.raises(CandidateUnavailable, match="entry_bytes_unavailable"):
        select_candidate((RAW,), "src/a.cpp", max_entry_bytes=1, max_entries=1)
    with pytest.raises(CandidateUnavailable, match="entry_count_unavailable"):
        select_candidate((RAW, RAW), "src/a.cpp", max_entry_bytes=4096, max_entries=1)
