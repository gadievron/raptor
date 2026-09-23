"""Drift pins for the per-consumer extension→language maps.

Three /audit maps route file extensions for three DIFFERENT
consumers — tree-sitter grammar names (condition_extraction),
pattern-file keys (context), and CodeQL extractor languages
(codeql_dbs) — so they legitimately diverge from the inventory's
LANGUAGE_MAP where consumer semantics differ (CodeQL's cpp extractor
covers C, the C family shares one pattern file). What must NOT
happen silently is drift: an extension one map knows and the
inventory does not (invisible to the checklist but routed by a
consumer), or a value divergence nobody adjudicated. Every extra key
and every value divergence below is enumerated with its reason;
changing a map means updating the corresponding pin deliberately.
"""

from __future__ import annotations

from core.audit.codeql_dbs import CODEQL_EXT_LANGUAGE
from core.audit.condition_extraction import _EXT_TO_LANG
from core.audit.context import _LANG_PATTERN_EXT_MAP
from core.inventory.languages import LANGUAGE_MAP

# Extensions a map may know beyond the inventory, with the reason.
_EXTRA_KEYS: dict[str, dict[str, str]] = {
    "tree_sitter": {
        ".pyw": "Windows GUI Python — same grammar as .py",
    },
    "pattern_files": {},
    "codeql": {
        ".pyi": "Python stub files — the python extractor reads them",
        ".erb": "Rails templates — the ruby extractor reads them",
    },
}

# (extension, map_value) pairs that deliberately diverge from the
# inventory language for shared keys, with the reason.
_VALUE_DIVERGENCES: dict[str, dict[tuple[str, str], str]] = {
    "tree_sitter": {},
    "pattern_files": {
        (".cpp", "c"): "C family shares tiers/patterns/c.md",
        (".cc", "c"): "C family shares tiers/patterns/c.md",
        (".cxx", "c"): "C family shares tiers/patterns/c.md",
        (".hpp", "c"): "C family shares tiers/patterns/c.md",
        (".hxx", "c"): "C family shares tiers/patterns/c.md",
        (".ts", "javascript"): "TS shares javascript.md",
        (".tsx", "javascript"): "TSX shares javascript.md",
    },
    "codeql": {
        (".c", "cpp"): "CodeQL's cpp extractor covers C",
        (".h", "cpp"): "CodeQL's cpp extractor covers C",
        (".kt", "java"): "Kotlin analyses under the java extractor",
        (".kts", "java"): "Kotlin analyses under the java extractor",
        (".ts", "javascript"): "TS analyses under the js extractor",
        (".tsx", "javascript"): "TSX analyses under the js extractor",
    },
}

_MAPS = {
    "tree_sitter": _EXT_TO_LANG,
    "pattern_files": _LANG_PATTERN_EXT_MAP,
    "codeql": CODEQL_EXT_LANGUAGE,
}


class TestExtensionMapAlignment:
    def test_every_key_is_inventory_known_or_enumerated(self):
        for name, mapping in _MAPS.items():
            extras = _EXTRA_KEYS[name]
            for ext in mapping:
                assert ext in LANGUAGE_MAP or ext in extras, (
                    f"{name} map routes {ext!r} but the inventory's "
                    f"LANGUAGE_MAP does not know it — add it to the "
                    f"inventory (checklist visibility) or enumerate "
                    f"it in _EXTRA_KEYS with a reason"
                )

    def test_value_divergences_are_enumerated(self):
        for name, mapping in _MAPS.items():
            divergences = _VALUE_DIVERGENCES[name]
            for ext, value in mapping.items():
                canonical = LANGUAGE_MAP.get(ext)
                if canonical is None or value == canonical:
                    continue
                assert (ext, value) in divergences, (
                    f"{name} map routes {ext!r} -> {value!r} but the "
                    f"inventory says {canonical!r} — adjudicate the "
                    f"divergence into _VALUE_DIVERGENCES with a "
                    f"reason, or fix the map"
                )

    def test_enumerated_pins_are_live(self):
        # Reverse direction: a stale pin (map changed, pin kept) is
        # drift too.
        for name, mapping in _MAPS.items():
            for ext in _EXTRA_KEYS[name]:
                assert ext in mapping, (
                    f"stale extra-key pin {ext!r} for {name}"
                )
            for (ext, value) in _VALUE_DIVERGENCES[name]:
                assert mapping.get(ext) == value, (
                    f"stale divergence pin ({ext!r}, {value!r}) "
                    f"for {name}"
                )
