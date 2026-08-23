"""b45: the shared threat-model authority — the invariant that made
the b44 stop-ship's contradiction structurally impossible.

These tests FAIL THE BUILD if either consumer stops deriving from
:mod:`core.analysis.threat_model_java`, or if any API ever appears as
both a taint source (postpass locator) and a taint-free fold
(const_fold_java). The b44 counterexample: ``System.getenv`` was
taint-free in the fold tier and an environment source in the locator;
enforcement then dropped six real Juliet findings.
"""
from __future__ import annotations

import re

from core.analysis import threat_model_java as tm


class TestAuthorityInvariant:
    def test_source_and_taint_free_sets_disjoint(self):
        overlap = (tm.ENVIRONMENT_SOURCE_SYSTEM_READS
                   & tm.NON_SOURCE_SYSTEM_READS)
        assert not overlap, sorted(overlap)

    def test_environment_reads_are_sources_under_current_model(self):
        # The decided semantics (threat-model local / Juliet): the
        # environment is attacker-influenced. Loosening this requires
        # revisiting the b44 stop-ship record in the enforcement
        # dossier, not just editing the set.
        assert "getenv" in tm.ENVIRONMENT_SOURCE_SYSTEM_READS
        assert "getProperty" in tm.ENVIRONMENT_SOURCE_SYSTEM_READS
        assert "getenv" not in tm.NON_SOURCE_SYSTEM_READS
        assert "getProperty" not in tm.NON_SOURCE_SYSTEM_READS


class TestConsumersDerive:
    def test_fold_tier_derives_from_authority(self):
        from core.analysis import const_fold_java as cf
        assert cf._TF_SYSTEM_READS is tm.NON_SOURCE_SYSTEM_READS
        assert cf._TF_FILE_FIELDS is tm.NON_SOURCE_JVM_CONSTANT_FIELDS

    def test_locator_derives_from_authority(self):
        from core.analysis.sanitizer_cut_postpass import _SOURCE_KINDS
        assert (_SOURCE_KINDS["java"]["environment"]["patterns"]
                == tm.environment_source_patterns())

    def test_every_source_api_matches_a_locator_pattern(self):
        # Belt and braces: each source API name must be recognisable
        # by at least one derived pattern (a rename in one place
        # cannot silently orphan the other).
        patterns = [re.compile(p)
                    for p in tm.environment_source_patterns()]
        for name in tm.ENVIRONMENT_SOURCE_SYSTEM_READS:
            probe = f"System.{name}(\"k\")"
            assert any(p.search(probe) for p in patterns), name

    def test_no_source_api_folds_taint_free(self):
        # End-to-end: fold each source API with every opt-in enabled —
        # the result must never be TAINT_FREE (REFUSE expected).
        import pytest
        pytest.importorskip("tree_sitter_java")
        from core.analysis.cfg_builder_java import _get_parser
        from core.analysis.const_fold_java import (
            REFUSE,
            fold_expr,
        )
        for name in sorted(tm.ENVIRONMENT_SOURCE_SYSTEM_READS):
            src = ("public class T { void m() { "
                   f"Object r = System.{name}(\"k\"); }} }}")
            tree = _get_parser().parse(src.encode())
            nodes = []

            def find(n):
                if n.type == "variable_declarator":
                    nodes.append(n.child_by_field_name("value"))
                for c in n.children:
                    find(c)

            find(tree.root_node)
            assert nodes
            v = fold_expr(nodes[0], lambda _n, _d: REFUSE,
                          allow_taint_free=True)
            assert v is REFUSE, name
