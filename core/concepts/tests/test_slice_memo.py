"""Equivalence and bound tests for audit_bridge's derivation caches.

The domain-slice fingerprint (verdict-reuse key) must be byte-identical
whether its inputs are derived fresh or served from a cache — a cached
value that drifts from the fresh derivation silently changes which
review verdicts get reused. Every cache is therefore pinned against a
frozen reference implementation (verbatim copies of the pre-cache
code), and every bound is pinned from both directions: results stay
correct under eviction, and repeat inputs are actually served from the
cache.
"""

import json
import re
from pathlib import PurePosixPath

import pytest

import core.concepts.audit_bridge as ab
from core.concepts.audit_bridge import (
    _DomainSliceMemo,
    _grep_hint_compilable,
    _grep_hint_pattern,
    _ItemStatics,
    _load_cached,
    _name_variants,
    _paths_match,
    _pp_parts,
    _relevance_score,
    _word_boundary_pattern,
    domain_slice_hash,
)
from core.concepts.tests import slice_vectors


@pytest.fixture(autouse=True)
def _clean_caches():
    """Every test starts and ends with cold model/memo state.

    The slice-memo store and the model parse cache are process-global;
    without this, one test's model content leaks derivations into the
    next test's assertions.
    """
    _load_cached.cache_clear()
    ab._slice_memos.clear()
    yield
    _load_cached.cache_clear()
    ab._slice_memos.clear()

# ---------------------------------------------------------------------------
# Frozen reference implementations (pre-cache code, verbatim).
# ---------------------------------------------------------------------------


def _ref_paths_match(a: str, b: str) -> bool:
    if a == b:
        return True
    if a.endswith("/" + b) or b.endswith("/" + a):
        return True
    pa, pb = PurePosixPath(a), PurePosixPath(b)
    if pa.name != pb.name:
        return False
    return bool(set(pa.parts[:-1]) & set(pb.parts[:-1]))


def _ref_name_variants(function_name: str) -> "tuple[str, ...]":
    for _pfx in ("sym.imp.", "sym.", "fcn.", "imp."):
        if (function_name.startswith(_pfx)
                and len(function_name) > len(_pfx)):
            return (function_name, function_name[len(_pfx):])
    return (function_name,)


def _ref_grep_hit(grep_hint: str, source: str) -> bool:
    """The pre-cache domain_bug_patterns hint-match block, verbatim."""
    if not _grep_hint_compilable.__wrapped__(grep_hint):
        return grep_hint.lower() in source.lower()
    try:
        return re.search(grep_hint, source, re.IGNORECASE) is not None
    except re.error:
        return grep_hint.lower() in source.lower()


def _new_grep_hit(grep_hint: str, source: str) -> bool:
    """The cached hint-match block as domain_bug_patterns now runs it."""
    pattern = (
        _grep_hint_pattern(grep_hint)
        if _grep_hint_compilable(grep_hint) else None
    )
    if pattern is None:
        return grep_hint.lower() in source.lower()
    return pattern.search(source) is not None


# ---------------------------------------------------------------------------
# Equivalence matrices
# ---------------------------------------------------------------------------

_PATH_MATRIX = [
    ("a.c", "a.c"),
    ("crypto/algif_aead.c", "src/crypto/algif_aead.c"),
    ("src/crypto/algif_aead.c", "crypto/algif_aead.c"),
    ("net/frame.c", "drivers/net/frame.c"),
    ("a/b/x.c", "c/d/x.c"),
    ("a/b/x.c", "b/d/x.c"),
    ("x.c", "y.c"),
    ("", ""),
    ("", "x.c"),
    ("x.c", ""),
    ("deep/er/path/x.c", "other/deep/x.c"),
    ("x.c", "sub/x.c/"),
    ("./x.c", "x.c"),
    ("/abs/net/frame.c", "net/frame.c"),
    ("dir.with.dots/x.c", "dir.with.dots/y/x.c"),
    ("café/été.c", "src/café/été.c"),
]


class TestPathsMatchEquivalence:
    @pytest.mark.parametrize("a,b", _PATH_MATRIX)
    def test_matches_reference(self, a, b):
        assert _paths_match(a, b) == _ref_paths_match(a, b)

    def test_correct_after_eviction(self):
        # Direction 1 for _PATH_PARTS_CACHE_MAX: a working set larger
        # than the bound must only cost recompute time — every answer
        # stays equal to the fresh derivation while the cache
        # thrashes. (Exercised against a shrunken clone of the cached
        # helper so the test does not need to generate a working set
        # larger than the real bound.)
        from functools import lru_cache

        import core.concepts.audit_bridge as ab

        small = lru_cache(maxsize=4)(ab._pp_parts.__wrapped__)
        paths = [f"m{i}/sub{i % 3}/f{i}.c" for i in range(64)]
        for _ in range(2):  # second pass re-queries evicted entries
            for i, a in enumerate(paths):
                b = paths[(i * 7 + 3) % len(paths)]
                got_a, got_b = small(a), small(b)
                p_a, p_b = PurePosixPath(a), PurePosixPath(b)
                assert got_a == (p_a.name, frozenset(p_a.parts[:-1]))
                assert got_b == (p_b.name, frozenset(p_b.parts[:-1]))

    def test_repeat_queries_hit_the_cache(self):
        # Direction 2: the bound must not be effectively zero — a
        # repeated path is served from the cache, not re-derived.
        _pp_parts.cache_clear()
        _paths_match("one/two/three.c", "zero/two/three.c")
        before = _pp_parts.cache_info().hits
        _paths_match("one/two/three.c", "zero/two/three.c")
        assert _pp_parts.cache_info().hits > before


class TestNameVariantsEquivalence:
    @pytest.mark.parametrize("name", [
        "main", "sym.main", "sym.imp.strcpy", "fcn.00401000", "imp.read",
        "sym.", "imp.", "fcn.", "sym.imp.",
        "Class.method", "sym.Class.method", "a", "",
    ])
    def test_matches_reference(self, name):
        assert _name_variants(name) == _ref_name_variants(name)

    def test_repeat_queries_hit_the_cache(self):
        _name_variants.cache_clear()
        _name_variants("sym.frame_parse")
        before = _name_variants.cache_info().hits
        _name_variants("sym.frame_parse")
        assert _name_variants.cache_info().hits > before


_HINT_MATRIX = [
    # (hint, source) — compiling, non-compiling, refused, case games
    (r"memcpy\s*\(", "x = memcpy (dst, src, n);"),
    (r"memcpy\s*\(", "no such call here"),
    ("MEMCPY", "a memcpy( call"),               # IGNORECASE via regex
    ("(unbalanced", "text with (unbalanced paren"),   # re.error path
    ("(unbalanced", "TEXT WITH (UNBALANCED PAREN"),   # fallback lowers
    ("(a+)+$", "aaaa"),                          # ReDoS shape refused
    ("(a+)+$", "literal (a+)+$ in source"),      # refused → substring
    ("x" * 300, "x" * 400),                      # over-length refused
    (r"\bfree\b", "kfree(p); free(q);"),
    ("café", "un CAFÉ noir"),          # non-ASCII casefold
]


class TestGrepHintEquivalence:
    @pytest.mark.parametrize("hint,source", _HINT_MATRIX)
    def test_matches_reference(self, hint, source):
        assert _new_grep_hit(hint, source) == _ref_grep_hit(hint, source)

    def test_correct_after_eviction(self):
        # Direction 1 for _PATTERN_CACHE_MAX (shrunken clone, as
        # above): eviction never changes a match result.
        from functools import lru_cache

        import core.concepts.audit_bridge as ab

        small = lru_cache(maxsize=4)(ab._grep_hint_pattern.__wrapped__)
        hints = [f"tok_{i}" for i in range(32)] + ["(bad", "(a+)+$"]
        source = "tok_3 tok_17 (bad"
        for _ in range(2):
            for hint in hints:
                pat = (
                    small(hint)
                    if ab._grep_hint_compilable(hint) else None
                )
                if pat is None:
                    got = hint.lower() in source.lower()
                else:
                    got = pat.search(source) is not None
                assert got == _ref_grep_hit(hint, source), hint

    def test_repeat_queries_hit_the_cache(self):
        _grep_hint_pattern.cache_clear()
        _grep_hint_compilable.cache_clear()
        _new_grep_hit(r"alloc\s*\(", "no")
        hits0 = _grep_hint_pattern.cache_info().hits
        comp0 = _grep_hint_compilable.cache_info().hits
        _new_grep_hit(r"alloc\s*\(", "yes alloc (")
        assert _grep_hint_pattern.cache_info().hits > hits0
        assert _grep_hint_compilable.cache_info().hits > comp0


class TestWordBoundaryPattern:
    @pytest.mark.parametrize("word,source,expected", [
        ("spin_lock", "calls spin_lock(&l);", True),
        ("spin_lock", "calls spin_lock_irqsave(&l);", False),  # \b honoured
        ("free", "kfree(p)", False),
        ("free", "free(p)", True),
        ("a+b", "x a+b y", True),                # re.escape honoured
        ("a+b", "x aab y", False),
    ])
    def test_matches_inline_construction(self, word, source, expected):
        got = _word_boundary_pattern(word).search(source) is not None
        ref = re.search(
            r"\b" + re.escape(word) + r"\b", source) is not None
        assert got == ref == expected

    def test_repeat_queries_hit_the_cache(self):
        _word_boundary_pattern.cache_clear()
        _word_boundary_pattern("frame_ref_get")
        before = _word_boundary_pattern.cache_info().hits
        _word_boundary_pattern("frame_ref_get")
        assert _word_boundary_pattern.cache_info().hits > before

# ---------------------------------------------------------------------------
# _relevance_score equivalence: memoised statics vs the historical
# inline derivation (frozen verbatim below).
# ---------------------------------------------------------------------------


def _ref_relevance_score(
    item: dict,
    file_path: str,
    function_name: str,
    source: str,
) -> float:
    """The pre-statics _relevance_score, verbatim."""
    score = 0.0
    variants = _name_variants(function_name)
    fn_lowers = tuple(v.lower() for v in variants)
    source_lower = source.lower() if source else ""

    desc = " ".join(
        s for s in (
            item.get("description"), item.get("statement"),
            item.get("negation"),
        ) if s
    ).lower()
    item_id = (
        item.get("id") or item.get("concept") or item.get("name") or ""
    ).lower()

    if any(v in desc or v in item_id for v in fn_lowers):
        score += 5.0

    for ev in item.get("evidence", []):
        if isinstance(ev, dict):
            ev_file = ev.get("file", "")
            if ev_file and _paths_match(file_path, ev_file):
                ev_item = ev.get("item", "")
                if ev_item and ev_item in variants:
                    score += 6.0
                else:
                    score += 1.5
                break

    if item.get("function") in variants:
        score += 8.0
    item_file = item.get("file") or item.get("source") or ""
    item_file = re.split(r":\d", item_file, maxsplit=1)[0]
    if item_file and _paths_match(file_path, item_file):
        score += 2.0

    id_parts = re.split(r"[_\-.]", item_id)
    for part in id_parts:
        if len(part) > 4 and part in source_lower:
            score += 0.5

    if source_lower and desc:
        named = set(re.findall(r"[a-z_][a-z0-9_]{5,}", desc))
        hits = sum(
            1 for tok in named if "_" in tok and tok in source_lower
        )
        score += min(3.0, 1.5 * hits)

    conf = item.get("confidence", "inferred")
    conf_bonus = {
        "tested": 0.5, "documented": 0.4, "corroborated": 0.3,
        "traced": 0.2, "inferred": 0.0,
    }
    score += conf_bonus.get(conf, 0.0)

    return score


_SCORE_ITEMS = [
    {"id": "frame_layout", "description": "frame_checksum_verify guards "
     "the frame_layout header", "confidence": "tested",
     "evidence": [{"file": "net/frame.c", "item": "frame_checksum_verify"}]},
    {"id": "frame_layout", "description": "same concept, file-only anchor",
     "evidence": [{"file": "net/frame.c"}]},
    {"concept": "queue_index_bound", "statement": "queue_push masks the "
     "index_bound before table_access happens", "negation": "oob write",
     "provenance": "llm_prior", "confidence": "inferred"},
    {"function": "frame_checksum_verify", "file": "net/frame.c:120",
     "input_semantics": "buf >= 4 bytes", "confidence": "documented"},
    {"function": "frame_checksum_verify", "file": "drivers/other/x.c"},
    {"name": "spin.lock-pairing", "description": "spin_lock spin_unlock "
     "must pair", "confidence": "bogus-tier"},
    {"id": "with-dash-and.dot_parts", "description": ""},
    {},  # nothing to score on at all
    {"description": "evidence list carries drifted shapes",
     "evidence": ["stringy", 7, {"item": "frame_checksum_verify"},
                  {"file": "net/frame.c", "item": "frame_checksum_verify"}]},
    {"id": "café_señal", "description": "accented café_señal identifiers",
     "confidence": "corroborated"},
]

_SCORE_CALLS = [
    ("net/frame.c", "frame_checksum_verify", slice_vectors._SRC_MATCH),
    ("src/linux/net/frame.c", "sym.frame_checksum_verify",
     slice_vectors._SRC_MATCH),
    ("lib/other.c", "helper", slice_vectors._SRC_PLAIN),
    ("net/frame.c", "frame_checksum_verify", ""),
    ("", "", ""),
]


class TestRelevanceScoreEquivalence:
    @pytest.mark.parametrize("item_i", range(len(_SCORE_ITEMS)))
    @pytest.mark.parametrize("call_i", range(len(_SCORE_CALLS)))
    def test_matches_reference(self, item_i, call_i):
        item = _SCORE_ITEMS[item_i]
        fp, fn, src = _SCORE_CALLS[call_i]
        ref = _ref_relevance_score(item, fp, fn, src)
        # Statics derived inline...
        assert _relevance_score(item, fp, fn, src) == ref
        # ...and statics passed by a memo-backed caller: same value.
        st = _ItemStatics(item)
        assert _relevance_score(item, fp, fn, src, statics=st) == ref

    def test_memo_statics_are_per_item_and_reused(self):
        memo = _DomainSliceMemo({"concepts": list(_SCORE_ITEMS)})
        first = memo.statics_for(_SCORE_ITEMS[0])
        assert memo.statics_for(_SCORE_ITEMS[0]) is first
        assert memo.statics_for(_SCORE_ITEMS[1]) is not first


# ---------------------------------------------------------------------------
# End-to-end fingerprint goldens.
# ---------------------------------------------------------------------------

# Minted by running slice_vectors through domain_slice_hash on the tree
# as it stood BEFORE the memo/caching work, then verified byte-identical
# on the memoised tree. Their job is to catch ACCIDENTAL fingerprint
# drift: the fingerprint is the verdict-reuse key, so a silent change
# re-buys (or wrongly reuses) settled review verdicts across the whole
# journal. After an INTENTIONAL prompt-content change, regenerate every
# hash from slice_vectors and say so in the change description.
_GOLDEN_HASHES = {
    "full-match":
        "19c98111bbd02ad48138a2805a92e97a3ce7cfa6c455b1582b45b66c0aa4001b",
    "full-match-deep-path":
        "19c98111bbd02ad48138a2805a92e97a3ce7cfa6c455b1582b45b66c0aa4001b",
    "full-sym-prefixed":
        "19c98111bbd02ad48138a2805a92e97a3ce7cfa6c455b1582b45b66c0aa4001b",
    "full-unrelated-fn":
        "f0750486de108735a09d419e26dbe8197d4d9c16811ff8cf5ea4f1c78276ec40",
    "full-no-source":
        "e3ba2cf88faf1e4ea8cf32dd294c96b1328758b1f6eff9deedf795fc86989b38",
    "security-only":
        "eeefe247d3ecb706cfc421cf89eecf802960cf8cbbe08a30a3bd5de3f686376c",
    "empty-selection":
        "450c4dac4973a47047cd37ebb4cddf06203206bcc6f671fbf709ef9c3c30c25f",
    "drifted-match":
        "5efad54cdc66c080c4ed8ac559eb27d800d824a77cf912249e95e2f8ee797bbc",
    "drifted-no-source":
        "e36222d33a68cb8cbbc8db6b0eb184562814877a84ec0d17f4c53332b1fb8468",
    "hostile-hints":
        "407bbdf9bd3a0a32b16a077974b62dacb9ff94ac81208f703ca2916b935b5241",
    "hostile-hints-no-source":
        "271f055553fda48fa031ad4d5320ca92243e8d139e355bef8257f233a0b17d03",
    "unicode-paired":
        "0986a7dffce72c06599f582aafa32b3cdc58d779b21b52d4248beabd84d18f06",
}


def _write_model(dirpath, model) -> None:
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / "domain-model.json").write_text(
        json.dumps(model), encoding="utf-8")


class TestGoldenVectors:
    @pytest.mark.parametrize("vid", sorted(slice_vectors.VECTORS))
    def test_hash_matches_golden(self, vid, tmp_path):
        builder, fp, fn, src = slice_vectors.VECTORS[vid]
        out_dir = tmp_path / vid
        _write_model(out_dir, slice_vectors.build_model(builder))
        assert domain_slice_hash(out_dir, fp, fn, src) == \
            _GOLDEN_HASHES[vid], vid

    def test_every_vector_has_a_golden(self):
        assert sorted(_GOLDEN_HASHES) == sorted(slice_vectors.VECTORS)

    def test_warm_equals_cold(self, tmp_path):
        # The memoised (warm) fingerprint must be byte-identical to a
        # cold one computed with an empty memo store.
        out_dir = tmp_path / "run"
        _write_model(out_dir, slice_vectors.build_model("_model_full"))
        args = (out_dir, "net/frame.c", "frame_checksum_verify",
                slice_vectors._SRC_MATCH)
        cold = domain_slice_hash(*args)
        warm = domain_slice_hash(*args)
        ab._slice_memos.clear()
        recold = domain_slice_hash(*args)
        assert cold == warm == recold


# ---------------------------------------------------------------------------
# Memo staleness: the memo keys on model CONTENT, never object identity.
# ---------------------------------------------------------------------------


class TestMemoStaleness:
    def test_file_content_change_invalidates(self, tmp_path):
        out_dir = tmp_path / "run"
        _write_model(out_dir, slice_vectors.build_model("_model_full"))
        args = (out_dir, "net/frame.c", "frame_checksum_verify",
                slice_vectors._SRC_MATCH)
        before = domain_slice_hash(*args)

        _write_model(
            out_dir, slice_vectors.build_model("_model_security_only"))
        _load_cached.cache_clear()  # the parse cache is mtime-blind
        after = domain_slice_hash(*args)

        assert before == _GOLDEN_HASHES["full-match"]
        assert after != before
        # ...and equals the same model computed from fully cold state.
        _load_cached.cache_clear()
        ab._slice_memos.clear()
        assert domain_slice_hash(*args) == after

    def test_inplace_mutation_rekeys_the_memo(self, tmp_path):
        # The loaded model dict is served by object from the parse
        # cache and nothing forbids consumers mutating it in place —
        # this is exactly why the store keys on a content digest. An
        # object-identity key would keep serving the OLD derivations
        # here and the assertion below would fail.
        out_dir = tmp_path / "run"
        _write_model(out_dir, slice_vectors.build_model("_model_full"))
        args = (out_dir, "net/frame.c", "frame_checksum_verify",
                slice_vectors._SRC_MATCH)
        before = domain_slice_hash(*args)

        model = ab._find_domain_model(out_dir)
        model["security_context"]["privilege_level"] = "unprivileged"
        after = domain_slice_hash(*args)
        assert after != before

        # Byte-equal to a cold compute of the mutated content.
        cold_dir = tmp_path / "cold"
        _write_model(cold_dir, model)
        ab._slice_memos.clear()
        assert domain_slice_hash(
            cold_dir, *args[1:]) == after


# ---------------------------------------------------------------------------
# Memo store bound (_SLICE_MEMO_MAX), both directions.
# ---------------------------------------------------------------------------


class TestMemoStoreBound:
    def test_eviction_stays_correct(self, tmp_path):
        # Direction 1: a working set one over the bound forces
        # eviction on every rotation; every hash must still equal its
        # cold value (a miss only recomputes).
        n = ab._SLICE_MEMO_MAX + 1
        dirs, expected = [], []
        for i in range(n):
            model = slice_vectors.build_model("_model_full")
            # Vary content that renders (the security block quotes the
            # attack surface), so each model gets a distinct hash.
            model["security_context"]["attack_surface"] = f"surface {i}"
            d = tmp_path / f"m{i}"
            _write_model(d, model)
            dirs.append(d)
            expected.append(domain_slice_hash(
                d, "net/frame.c", "frame_checksum_verify",
                slice_vectors._SRC_MATCH))
        assert len(set(expected)) == n  # distinct content, distinct keys
        for _ in range(2):
            for d, want in zip(dirs, expected):
                got = domain_slice_hash(
                    d, "net/frame.c", "frame_checksum_verify",
                    slice_vectors._SRC_MATCH)
                assert got == want
        assert len(ab._slice_memos) <= ab._SLICE_MEMO_MAX

    def test_within_capacity_memo_is_reused(self, tmp_path, monkeypatch):
        # Direction 2: the bound must not be effectively zero — the
        # per-function calls the memo exists for are served by ONE
        # memo per model content.
        built = []
        real = ab._DomainSliceMemo

        class _Spy(real):
            def __init__(self, model):
                built.append(1)
                super().__init__(model)

        monkeypatch.setattr(ab, "_DomainSliceMemo", _Spy)
        out_dir = tmp_path / "run"
        _write_model(out_dir, slice_vectors.build_model("_model_full"))
        h1 = domain_slice_hash(out_dir, "net/frame.c",
                               "frame_checksum_verify",
                               slice_vectors._SRC_MATCH)
        h2 = domain_slice_hash(out_dir, "lib/other.c", "helper",
                               slice_vectors._SRC_PLAIN)
        assert h1 != h2  # different functions, different slices
        assert sum(built) == 1

    def test_cross_model_isolation(self, tmp_path):
        # Alternating models never bleed derivations into each other.
        d1, d2 = tmp_path / "a", tmp_path / "b"
        _write_model(d1, slice_vectors.build_model("_model_full"))
        _write_model(d2, slice_vectors.build_model("_model_security_only"))
        args = ("net/frame.c", "frame_checksum_verify",
                slice_vectors._SRC_MATCH)
        h1a = domain_slice_hash(d1, *args)
        h2a = domain_slice_hash(d2, *args)
        h1b = domain_slice_hash(d1, *args)
        h2b = domain_slice_hash(d2, *args)
        assert h1a == h1b == _GOLDEN_HASHES["full-match"]
        assert h2a == h2b
        assert h1a != h2a


# ---------------------------------------------------------------------------
# Aliased content: a memo hit must be a pure function of the looked-up
# content. Content-equal model objects can coexist (same bytes parsed
# for two run dirs; the parse cache evicting and re-parsing a path the
# memo outlives), and a caller-held object mutated in place after the
# memo was built must never leak into a hit those OTHER objects take.
# ---------------------------------------------------------------------------

_ALIAS_ARGS = (
    "net/frame.c", "frame_checksum_verify", slice_vectors._SRC_MATCH)


class TestAliasedContent:
    def test_second_dir_same_bytes_hit_matches_cold(self, tmp_path):
        # Two run dirs carry byte-identical models: hashing run1
        # builds the memo; run1's parse-cached object then mutates in
        # place (nothing forbids consumers doing so). run2's fresh
        # parse still digests to the stored key — that hit must render
        # run2's ACTUAL content (equal the pre-mutation hash), never a
        # mix of memo-cached fields and the mutated object.
        text = json.dumps(slice_vectors.build_model("_model_full"))
        d1, d2 = tmp_path / "run1", tmp_path / "run2"
        for d in (d1, d2):
            d.mkdir()
            (d / "domain-model.json").write_text(text, encoding="utf-8")
        h1 = domain_slice_hash(d1, *_ALIAS_ARGS)

        live = ab._find_domain_model(d1)
        # Poison both a memo-derived field (security context) and a
        # field the renderers read straight off the model dict
        # (bug-pattern text).
        live["security_context"]["privilege_level"] = "unprivileged"
        live["bug_patterns"][0]["description"] = "mutated pattern text"

        h2 = domain_slice_hash(d2, *_ALIAS_ARGS)
        assert h2 == h1 == _GOLDEN_HASHES["full-match"]

    def test_parse_cache_eviction_then_hit_matches_cold(self, tmp_path):
        # Same path, one file, unchanged on disk: parse-only consumers
        # (the key-files reader, the token-map projector) advance the
        # parse lru without touching the memo store, so the memo can
        # outlive the parse-cache entry it was built from. Mutating
        # the evicted object must not leak into the hit a fresh
        # re-parse of the unchanged file takes.
        d = tmp_path / "run"
        _write_model(d, slice_vectors.build_model("_model_full"))
        h1 = domain_slice_hash(d, *_ALIAS_ARGS)

        live = ab._find_domain_model(d)
        live["security_context"]["privilege_level"] = "unprivileged"
        live["bug_patterns"][0]["description"] = "mutated pattern text"
        # Deterministic stand-in for lru eviction: the next
        # _find_domain_model re-parses the unchanged file.
        _load_cached.cache_clear()

        h2 = domain_slice_hash(d, *_ALIAS_ARGS)
        assert h2 == h1 == _GOLDEN_HASHES["full-match"]

    def test_aliased_lookups_are_hits_not_misses(self, tmp_path,
                                                 monkeypatch):
        # Premise guard for the two tests above: the aliased lookups
        # must be served by the ONE stored memo (a miss recomputes
        # from scratch and would pass them trivially).
        built = []
        real = ab._DomainSliceMemo

        class _Spy(real):
            def __init__(self, model):
                built.append(1)
                super().__init__(model)

        monkeypatch.setattr(ab, "_DomainSliceMemo", _Spy)
        text = json.dumps(slice_vectors.build_model("_model_full"))
        d1, d2 = tmp_path / "run1", tmp_path / "run2"
        for d in (d1, d2):
            d.mkdir()
            (d / "domain-model.json").write_text(text, encoding="utf-8")
        domain_slice_hash(d1, *_ALIAS_ARGS)
        domain_slice_hash(d2, *_ALIAS_ARGS)
        _load_cached.cache_clear()
        domain_slice_hash(d1, *_ALIAS_ARGS)
        assert sum(built) == 1


# ---------------------------------------------------------------------------
# Statics keying: sound by construction (each entry pins the exact dict
# it keyed), never by id-reachability reasoning.
# ---------------------------------------------------------------------------


def _walk(obj: object) -> list[object]:
    """Every dict and list reachable from *obj* (identity harvest)."""
    stack, seen, out = [obj], set(), []
    while stack:
        o = stack.pop()
        if id(o) in seen or not isinstance(o, (dict, list)):
            continue
        seen.add(id(o))
        out.append(o)
        stack.extend(o.values() if isinstance(o, dict) else o)
    return out


class TestStaticsKeying:
    def test_store_memo_owns_a_private_snapshot(self, tmp_path):
        d = tmp_path / "run"
        _write_model(d, slice_vectors.build_model("_model_full"))
        domain_slice_hash(d, *_ALIAS_ARGS)
        live = ab._find_domain_model(d)
        (memo,) = ab._slice_memos.values()
        assert memo.model is not live
        # No container anywhere in the snapshot is shared with the
        # live model: mutating any live sub-object can never reach
        # the memo.
        live_ids = {id(o) for o in _walk(live)}
        assert live_ids.isdisjoint({id(o) for o in _walk(memo.model)})

    def test_every_statics_entry_pins_its_keyed_item(self, tmp_path):
        d = tmp_path / "run"
        _write_model(d, slice_vectors.build_model("_model_full"))
        domain_slice_hash(d, *_ALIAS_ARGS)
        (memo,) = ab._slice_memos.values()
        assert memo._statics  # scoring ran; the structure is populated
        snapshot_ids = {id(o) for o in _walk(memo.model)}
        for key, (item, statics) in memo._statics.items():
            # The pair holds the exact object the key names — the
            # strong reference makes id recycling for that key
            # impossible while the entry lives.
            assert id(item) == key
            assert isinstance(statics, _ItemStatics)
            # ...and every scored item is memo-held (a snapshot dict),
            # never a live-model dict.
            assert id(item) in snapshot_ids

    def test_identity_mismatch_recomputes_never_serves(self):
        # The stored-object identity check: even if an entry's key
        # somehow named a different dict, the hit is refused, the
        # statics recomputed, and the slot repaired.
        memo = _DomainSliceMemo({"concepts": []})
        item_a = {"id": "alpha_beta_gamma", "description": "one"}
        item_b = {"id": "delta_epsilon", "description": "two"}
        st_a = memo.statics_for(item_a)
        memo._statics[id(item_b)] = (item_a, st_a)  # forged slot
        st_b = memo.statics_for(item_b)
        assert st_b is not st_a
        assert st_b.item_id == "delta_epsilon"
        stored_item, stored_st = memo._statics[id(item_b)]
        assert stored_item is item_b and stored_st is st_b
