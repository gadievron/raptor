"""Inert declared invocation selection; no measured build authority or IO."""

from dataclasses import dataclass
import json


class CandidateUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class InvocationCandidate:
    selected_entry_bytes: bytes
    translation_unit: str
    declared_directory: str
    ordered_arguments: tuple[str, ...]
    response_file_references: tuple[tuple[int, str], ...]

    @property
    def authenticated_build(self) -> bool:
        return False


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CandidateUnavailable("duplicate_entry_key")
        result[key] = value
    return result


def _constant(value):
    raise CandidateUnavailable("non_json_constant")


def select_candidate(entries: tuple[bytes, ...], translation_unit: str, *,
                     max_entry_bytes: int, max_entries: int) -> InvocationCandidate:
    """Select an exact declared file spelling from separately captured entries.

    The caller must preserve actual entry slices, not reserialised dictionaries.
    This draft cannot authenticate that custody. Paths are declaration strings:
    no filesystem resolution, response expansion, environment or execution occurs.
    Malformed entries prevent selection because their TU association is unknown.
    """
    if (type(max_entry_bytes) is not int or max_entry_bytes < 1
            or type(max_entries) is not int or max_entries < 1):
        raise CandidateUnavailable("invalid_selection_budget")
    if type(entries) is not tuple or len(entries) > max_entries:
        raise CandidateUnavailable("entry_count_unavailable")
    if not isinstance(translation_unit, str) or not translation_unit or "\0" in translation_unit:
        raise CandidateUnavailable("invalid_translation_unit")
    matches = []
    for raw in entries:
        if type(raw) is not bytes or not raw or len(raw) > max_entry_bytes:
            raise CandidateUnavailable("entry_bytes_unavailable")
        try:
            entry = json.loads(raw.decode("utf-8"), object_pairs_hook=_object,
                               parse_constant=_constant)
        except CandidateUnavailable:
            raise
        except (ValueError, RecursionError) as exc:
            raise CandidateUnavailable("malformed_entry") from exc
        if (not isinstance(entry, dict) or not isinstance(entry.get("file"), str)
                or not entry["file"] or "\0" in entry["file"]):
            raise CandidateUnavailable("entry_association_unavailable")
        if entry["file"] == translation_unit:
            matches.append((raw, entry))
    if len(matches) != 1:
        raise CandidateUnavailable("missing_or_ambiguous_selection")
    raw, entry = matches[0]
    directory = entry.get("directory")
    arguments = entry.get("arguments")
    if not isinstance(directory, str) or not directory or "\0" in directory:
        raise CandidateUnavailable("declared_directory_unavailable")
    if (type(arguments) is not list or not arguments
            or any(not isinstance(arg, str) or "\0" in arg for arg in arguments)
            or not arguments[0]):
        # The existing macro-config helper coerces arguments and falls back
        # from shlex errors to whitespace splitting. Neither is exact custody.
        raise CandidateUnavailable("exact_arguments_array_unavailable")
    refs = tuple((index, arg) for index, arg in enumerate(arguments) if arg.startswith("@"))
    if any(arg == "@" for _, arg in refs):
        raise CandidateUnavailable("empty_response_reference")
    return InvocationCandidate(raw, translation_unit, directory, tuple(arguments), refs)
