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

import re
from pathlib import PurePosixPath

import pytest

from core.concepts.audit_bridge import (
    _grep_hint_compilable,
    _grep_hint_pattern,
    _name_variants,
    _paths_match,
    _pp_parts,
    _word_boundary_pattern,
)

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
        # helper so the test does not need to generate 4096+ paths.)
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
