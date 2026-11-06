"""Bounded compiler control-flow evidence; never a taint or reachability proof.

Keep whole paths or omit them with a reason. Filtering individual events could
invent an edge across an invalid or out-of-scope location.
"""
from __future__ import annotations

from collections.abc import Callable
from typing import Any
import sys
from urllib.parse import urlsplit, unquote, quote

from core.security.log_sanitisation import escape_nonprintable

MAX_PATHS = 8
MAX_EVENTS = 64
MAX_BYTES = 32 * 1024
PATH_KIND = "compiler-control-flow"


def _positive(value):
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value < 2**31


def valid_diagnostic_location(diag: dict[str, Any]) -> bool:
    """Only a real filename and a positive integer line can carry evidence."""
    filename = diag.get("file")
    return (isinstance(filename, str) and bool(filename) and len(filename) <= 4096
            and not filename.startswith("<") and _positive(diag.get("line"))
            and not any(ord(char) < 32 for char in filename))


def local_uri_path(uri: Any) -> str:
    """Decode one local SARIF URI once; filesystem names must bypass this.

    Callers apply their own target containment and relative-path policy.
    Ambiguous or non-local locations cannot establish diagnostic silence.
    """
    if not isinstance(uri, str) or not uri or len(uri) > 4096:
        raise ValueError("invalid compiler location URI")
    if uri.startswith(" ") or any(ord(char) < 32 or ord(char) == 127 for char in uri):
        raise ValueError("invalid compiler location URI")
    parsed = urlsplit(uri)
    if parsed.scheme not in ("", "file") or parsed.netloc not in ("", "localhost") or parsed.query or parsed.fragment:
        raise ValueError("non-local compiler location URI")
    path = unquote(parsed.path, errors="strict")
    if (not path or path.startswith(("//", "\\\\"))
            or any(ord(char) < 32 or ord(char) == 127 for char in path)):
        raise ValueError("invalid compiler location path")
    return path


def normalize_paths(raw: Any, locate: Callable[[str], str | None] | None = None,
                    *, resolve_uri: Callable[[dict[str, Any]], str | None] | None = None,
                    resolve_event: Callable[[Any], dict[str, Any] | None] | None = None
                    ) -> tuple[list[dict[str, Any]], list[str]]:
    """Copy bounded codeFlows; a bad event reference still omits its whole path."""
    if not raw:
        return [], []
    if not isinstance(raw, list):
        return [], ["malformed compiler path collection omitted"]
    paths: list[dict[str, Any]] = []
    notes: list[str] = []
    used = 0
    inspected = 0
    for flow in raw[:MAX_PATHS]:
        threads = flow.get("threadFlows") if isinstance(flow, dict) else None
        if not isinstance(threads, list):
            notes.append("malformed compiler path omitted")
            continue
        for thread in threads[:MAX_PATHS]:
            inspected += 1
            if inspected > MAX_PATHS:
                notes.append("additional compiler paths omitted at the path limit")
                break
            events = thread.get("locations") if isinstance(thread, dict) else None
            if not isinstance(events, list) or not events or len(events) > MAX_EVENTS:
                notes.append("malformed or over-limit compiler event path omitted")
                continue
            normalized: list[dict[str, Any]] = []
            size = 0
            try:
                for event in events:
                    if resolve_event is not None:
                        event = resolve_event(event)
                    elif isinstance(event, dict) and "index" in event:
                        index = event["index"]
                        if type(index) is not int or index != -1:
                            raise ValueError("compiler event reference requires run context")
                    location = event["location"]
                    physical = location["physicalLocation"]
                    artifact = physical["artifactLocation"]
                    uri = resolve_uri(artifact) if resolve_uri is not None else artifact["uri"]
                    region = physical["region"]
                    line = region["startLine"]
                    message = location.get("message", {}).get("text", "")
                    if not isinstance(uri, str) or not uri or len(uri) > 4096 or not _positive(line):
                        raise ValueError("invalid compiler event location")
                    if not isinstance(message, str) or len(message) > 2048:
                        raise ValueError("invalid compiler event description")
                    uri = local_uri_path(uri)
                    mapped = locate(uri) if locate is not None else uri
                    if mapped is None:
                        raise ValueError("compiler event outside target")
                    clean_region = {"startLine": line}
                    # File/line attribution is portable across GCC output
                    # modes; display/byte/Unicode column units are not.
                    clean_loc: dict[str, Any] = {
                        "physicalLocation": {"artifactLocation": {"uri": quote(mapped, safe="/")}, "region": clean_region},
                        "message": {"text": escape_nonprintable(message)},
                    }
                    logical = location.get("logicalLocations", [])
                    if not isinstance(logical, list):
                        raise ValueError("invalid compiler function location")
                    function = ""
                    if logical:
                        function = logical[0].get("fullyQualifiedName") or logical[0].get("name") or ""
                        if not isinstance(function, str) or len(function) > 256:
                            raise ValueError("invalid compiler function name")
                        clean_loc["logicalLocations"] = [{"name": escape_nonprintable(function), "kind": "function"}]
                    clean_event: dict[str, Any] = {"location": clean_loc, "executionOrder": len(normalized) + 1}
                    depth = event.get("nestingLevel")
                    if depth is not None:
                        if not isinstance(depth, int) or isinstance(depth, bool) or not 0 <= depth <= 256:
                            raise ValueError("invalid compiler call depth")
                        clean_event["nestingLevel"] = depth
                    size += len(mapped.encode("utf-8")) + len(clean_loc["message"]["text"].encode("utf-8")) + len(escape_nonprintable(function).encode("utf-8")) + 128
                    normalized.append(clean_event)
            except (KeyError, TypeError, AttributeError, ValueError, OSError):
                notes.append("invalid, out-of-target or over-limit compiler path omitted")
                continue
            path = {"threadFlows": [{"locations": normalized}]}
            if path not in paths:
                if used + size > MAX_BYTES:
                    notes.append("compiler path byte limit reached; whole path omitted")
                    continue
                used += size
                paths.append(path)
        if len(threads) > MAX_PATHS or inspected > MAX_PATHS:
            notes.append("additional compiler paths omitted at the path limit")
    if len(raw) > MAX_PATHS:
        notes.append("additional compiler paths omitted at the path limit")
    return paths, list(dict.fromkeys(notes))


def json_paths(raw: Any) -> tuple[list[dict[str, Any]], list[str]]:
    """Adapt GCC 10–12's JSON event path to the same bounded representation."""
    if not raw:
        return [], []
    if not isinstance(raw, list) or len(raw) > MAX_EVENTS:
        return [], ["malformed or over-limit compiler event path omitted"]
    events = []
    for event in raw:
        if not isinstance(event, dict):
            return [], ["malformed compiler event omitted with its path"]
        location = event.get("location")
        if not isinstance(location, dict):
            return [], ["malformed compiler event omitted with its path"]
        filename = location.get("file")
        if not isinstance(filename, str):
            return [], ["malformed compiler event omitted with its path"]
        loc = {"physicalLocation": {
                   "artifactLocation": {"uri": quote(filename, safe="/")},
                   "region": {"startLine": location.get("line"), "startColumn": location.get("column")}},
               "message": {"text": event.get("description", "")},
               "logicalLocations": [{"name": event.get("function", ""), "kind": "function"}]}
        events.append({"location": loc, "nestingLevel": event.get("depth", 0)})
    return normalize_paths([{"threadFlows": [{"locations": events}]}])


def attach_paths(destination: dict[str, Any], source: dict[str, Any],
                 locate: Callable[[str], str | None] | None = None) -> None:
    """Merge alternative observations at one diagnostic point without reruns."""
    paths, notes = normalize_paths(source.get("code_flows"), locate)
    existing = destination.get("code_flows")
    merged_notes: list[str] = []
    if existing:
        previous, previous_notes = normalize_paths(existing)
        unique = list(previous)
        for path in paths:
            if path not in unique:
                unique.append(path)
        combined, merged_notes = normalize_paths(unique)
        merged_notes.extend(previous_notes)
    else:
        combined = paths  # Fresh recipients need no second normalization pass.
    destination.pop("code_flows", None)
    if combined:
        destination["code_flows"] = combined
    all_notes: list[str] = []
    for values in (destination.get("compiler_path_notes"), source.get("compiler_path_notes"), notes, merged_notes):
        if isinstance(values, list):
            all_notes.extend(escape_nonprintable(v) for v in values[:8] if isinstance(v, str) and len(v) <= 256)
    if all_notes:
        destination["compiler_path_notes"] = list(dict.fromkeys(all_notes))[:8]


class PathBudget:
    """Conservative retained-memory ceiling per parsed translation unit/file."""

    def __init__(self, max_bytes: int = 256 * 1024):
        self.remaining = max_bytes

    def retain(self, destination: dict[str, Any], paths: list[dict[str, Any]], notes: list[str]) -> None:
        cost = 0

        def fits(value):
            nonlocal cost
            cost += sys.getsizeof(value)
            if cost > self.remaining:
                return False
            children = value.values() if isinstance(value, dict) else value if isinstance(value, list) else ()
            return all(fits(child) for child in children)

        # Stop sizing a rejected path at the first known overflow. Successful
        # admission retains the same conservative accounting as a full walk.
        admitted = fits(paths) if paths else cost <= self.remaining
        destination.pop("code_flows", None)
        if not admitted:
            paths = []
            notes = [*notes, "compiler path retention budget reached; paths omitted"]
        else:
            self.remaining -= cost
        if paths:
            destination["code_flows"] = paths
        if notes:
            destination["compiler_path_notes"] = list(dict.fromkeys(notes))[:8]
