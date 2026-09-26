"""Seed-pack content pins: curation discipline, provenance/rationale
presence, framework alignment with the route-model extractor, and
CWE/sink-class coherence with the sanitizer catalog."""

from __future__ import annotations

from collections import Counter

import pytest

from core.analysis.route_models import (
    FRAMEWORK_DJANGO,
    FRAMEWORK_FASTAPI,
    FRAMEWORK_FLASK,
)
from core.dataflow.sanitizer_catalog import sink_classes_for_cwe
from core.taint.packs import (
    PackSet,
    default_pack_names,
    load_packs,
)

FRAMEWORK_PACKS = {
    FRAMEWORK_FLASK: "python/frameworks-flask",
    FRAMEWORK_DJANGO: "python/frameworks-django",
    FRAMEWORK_FASTAPI: "python/frameworks-fastapi",
}

#: known-safe-calls key → this format's class spelling (the loader's
#: curated translation, restated here so drift is a red test).
CURATED_CLASS_SPELLING = {
    "cmdi": "command-injection",
    "sqli": "sql-injection",
    "xss": "xss",
    "pathtrav": "path-traversal",
}


@pytest.fixture(scope="module")
def seed_packs() -> PackSet:
    return load_packs(default_pack_names("python"))


def test_all_framework_packs_ship(seed_packs):
    shipped = set(default_pack_names("python"))
    assert set(FRAMEWORK_PACKS.values()) <= shipped
    assert "python/web-injection-core" in shipped


def test_seed_discipline_max_nine_per_role_per_class(seed_packs):
    for pack in seed_packs.packs:
        source_classes = Counter(
            c for s in pack.sources for c in s.taint_classes)
        sink_classes = Counter(s.sink_class for s in pack.sinks)
        sanitizer_classes = Counter(
            c for s in pack.sanitizers for c in s.sink_classes)
        propagators = len(pack.propagators)
        for census in (source_classes, sink_classes, sanitizer_classes):
            for cls, n in census.items():
                assert n <= 9, f"{pack.name}: {n} seed entries for {cls}"
        assert propagators <= 9, f"{pack.name}: {propagators} propagator seeds"


def test_every_entry_carries_provenance_and_rationale(seed_packs):
    entries = [
        *seed_packs.sources, *seed_packs.sinks,
        *seed_packs.sanitizers, *seed_packs.propagators,
    ]
    assert entries
    for entry in entries:
        assert entry.provenance, f"missing provenance: {entry}"
        assert entry.rationale.strip(), f"missing rationale: {entry}"


def test_framework_fields_align_with_route_model_extractor(seed_packs):
    """route_param sources bind to route records by framework name —
    the pack's framework value must be a spelling the extractor
    actually emits."""
    by_name = {p.name: p for p in seed_packs.packs}
    for framework, pack_name in FRAMEWORK_PACKS.items():
        pack = by_name[pack_name.split("/", 1)[1]]
        assert pack.framework == framework
        route_sources = [s for s in pack.sources if s.kind == "route_param"]
        assert route_sources, f"{pack_name} must seed route params"


def test_every_sink_carries_a_cwe(seed_packs):
    assert all(s.cwe.startswith("CWE-") for s in seed_packs.sinks)


def test_sink_classes_cohere_with_sanitizer_catalog(seed_packs):
    """Where a sink's CWE has curated sanitizer classes, the pack's
    sink_class must be the translation of one of them — otherwise the
    curated kill/tag entries could never pair with the sink."""
    checked = 0
    for sink in seed_packs.sinks:
        curated_classes = sink_classes_for_cwe(sink.cwe)
        translated = {
            CURATED_CLASS_SPELLING.get(c, c) for c in curated_classes
        }
        if not translated:
            continue
        checked += 1
        assert sink.sink_class in translated, (
            f"{sink.pack}: {sink.match or sink.kind} declares "
            f"{sink.sink_class} but {sink.cwe} maps to {sorted(translated)}"
        )
    assert checked > 0


def test_method_name_sinks_are_heuristic_with_hints(seed_packs):
    method_sinks = [s for s in seed_packs.sinks if s.kind == "method_name"]
    assert method_sinks
    for sink in method_sinks:
        assert sink.confidence == "heuristic"
        assert sink.receiver_hint


def test_shell_sinks_carry_literal_unless_kwargs(seed_packs):
    subprocess_sinks = [
        s for s in seed_packs.sinks if s.match.startswith("subprocess.")
    ]
    assert subprocess_sinks
    for sink in subprocess_sinks:
        assert ("shell", "False") in sink.unless_kwargs


def test_redirect_and_file_sinks_carry_keyword_spellings(seed_packs):
    """These APIs are routinely called with the keyword form
    (RedirectResponse(url=...), FileResponse(path=...)) — a
    positional-only sink spec would miss them."""
    expected = {
        "fastapi.responses.RedirectResponse": "url",
        "starlette.responses.RedirectResponse": "url",
        "fastapi.responses.FileResponse": "path",
        "starlette.responses.FileResponse": "path",
        "fastapi.responses.HTMLResponse": "content",
        "flask.redirect": "location",
        "flask.send_file": "path_or_file",
        "django.http.HttpResponseRedirect": "redirect_to",
    }
    by_match = {s.match: s for s in seed_packs.sinks if s.match in expected}
    assert set(by_match) == set(expected)
    for match, keyword in expected.items():
        assert keyword in by_match[match].kwargs, match
        assert 0 in by_match[match].args, match


def test_no_kill_sanitizer_is_wildcard(seed_packs):
    for sanitizer in seed_packs.sanitizers:
        if sanitizer.semantics == "kill":
            assert not sanitizer.is_wildcard


def test_no_pack_entry_narrows_propagation(seed_packs):
    """Seed propagators are floor-widening only; a narrowing seed
    would need its own review-visible justification."""
    assert all(not p.narrowing for p in seed_packs.propagators)


def test_vocabulary_covers_core_injection_classes(seed_packs):
    vocab = seed_packs.taint_class_vocabulary()
    assert {
        "user-input", "command-injection", "sql-injection",
        "code-injection", "path-traversal", "template-injection", "xss",
    } <= vocab
