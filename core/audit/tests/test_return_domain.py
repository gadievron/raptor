"""Return-domain mismatch witness.

A decision edge compares a callee's result against exactly ``-1``
while the callee's derived return domain provably contains another
negative error value — those errors take the fall-through path. The
witness is constructive (body-derived proof or silence): no name
lists, no LLM, no guesswork. Hermetic — ``tmp_path`` fixture trees
throughout; synthetic names simulate targets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.return_domain import (
    ReturnDomainMismatch,
    clear_cache,
    derive_return_domain,
    detect_return_domain_mismatches,
    sentinel_comparison_sites,
)
from core.testing import ts_parser_available

pytestmark = pytest.mark.skipif(
    not ts_parser_available("c"),
    reason="no tree-sitter c grammar installed",
)


@pytest.fixture(autouse=True)
def _fresh_caches():
    clear_cache()
    yield
    clear_cache()


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "src"
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


_CALLER = (
    "int handle_peer(int fd) {\n"
    "    if (do_check(fd) == -1)\n"
    "        return -1;\n"
    "    return 0;\n"
    "}\n"
)


# ── sentinel comparison sites ────────────────────────────────────────


class TestSentinelSites:
    def test_uncaptured_eq_site(self):
        sites = sentinel_comparison_sites(_CALLER, "a.c", language="c")
        assert len(sites) == 1
        s = sites[0]
        assert (s.callee, s.op, s.line) == ("do_check", "==", 2)
        assert s.enclosing_function == "handle_peer"
        assert s.shape == "== -1"

    def test_neq_polarity_site(self):
        src = (
            "int f(int x) {\n"
            "    if (do_check(x) != -1)\n"
            "        return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sentinel_comparison_sites(src, "a.c", language="c")
        assert [s.op for s in sites] == ["!="]

    def test_negation_flips_the_comparison(self):
        src = (
            "int f(int x) {\n"
            "    if (!(do_check(x) == -1))\n"
            "        return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        sites = sentinel_comparison_sites(src, "a.c", language="c")
        assert [s.op for s in sites] == ["!="]

    def test_literal_on_the_left(self):
        src = (
            "int f(int x) {\n"
            "    if (-1 == do_check(x))\n"
            "        return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        sites = sentinel_comparison_sites(src, "a.c", language="c")
        assert [s.op for s in sites] == ["=="]

    def test_captured_result_is_not_a_site(self):
        # A captured result can be re-tested later — the uncaptured
        # direct comparison is the precision anchor.
        src = (
            "int f(int x) {\n"
            "    int r = do_check(x);\n"
            "    if (r == -1)\n"
            "        return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        assert sentinel_comparison_sites(src, "a.c", language="c") == []

    def test_while_loop_is_not_a_decision_edge(self):
        src = (
            "void f(int x) {\n"
            "    while (do_check(x) == -1)\n"
            "        retry(x);\n"
            "}\n"
        )
        assert sentinel_comparison_sites(src, "a.c", language="c") == []

    def test_pointer_call_is_excluded(self):
        src = (
            "int f(struct ops *o) {\n"
            "    if (o->check(o) == -1)\n"
            "        return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        assert sentinel_comparison_sites(src, "a.c", language="c") == []

    def test_other_sentinels_are_out_of_scope(self):
        src = (
            "int f(int x) {\n"
            "    if (do_check(x) == -2)\n"
            "        return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        assert sentinel_comparison_sites(src, "a.c", language="c") == []

    def test_callee_filter(self):
        sites = sentinel_comparison_sites(
            _CALLER, "a.c", language="c", callee="something_else",
        )
        assert sites == []


# ── domain derivation ────────────────────────────────────────────────


class TestDeriveReturnDomain:
    def test_direct_literal_returns(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": (
            "int do_check(int x) {\n"
            "    if (x < 0)\n"
            "        return -2;\n"
            "    return 0;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert dom.proven_values == {-2, 0}
        assert dom.wider_values == [-2]
        assert dom.proven_wider
        assert any("lib.c:3" in p.chain for p in dom.proofs)

    def test_constant_return_resolves_through_include_guard(
        self, tmp_path,
    ):
        # The error-code family lives in a guarded header — the
        # include guard must not read as a conditional definition.
        root = _tree(tmp_path, {
            "err.h": (
                "#ifndef ERR_H\n"
                "#define ERR_H\n"
                "#define ERR_IO\t-5\n"
                "#endif\n"
            ),
            "lib.c": (
                '#include "err.h"\n'
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return ERR_IO;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        dom = derive_return_domain("do_check", [root])
        assert dom is not None and dom.proven_wider
        assert -5 in dom.proven_values
        assert any("ERR_IO" in p.chain for p in dom.proofs)

    def test_conditionally_defined_constant_is_rejected(self, tmp_path):
        root = _tree(tmp_path, {
            "err.h": (
                "#ifndef ERR_H\n"
                "#define ERR_H\n"
                "#ifdef LEGACY\n"
                "#define ERR_IO\t-5\n"
                "#endif\n"
                "#endif\n"
            ),
            "lib.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return ERR_IO;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert not dom.proven_wider

    def test_binary_domain_never_fires(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": (
            "int do_check(int x) {\n"
            "    if (x < 0)\n"
            "        return -1;\n"
            "    return 0;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert dom.proven_values == {-1, 0}
        assert not dom.proven_wider

    def test_positive_payload_domain_never_fires(self, tmp_path):
        # read()-style: payload plus -1. The extra value is positive,
        # not an error-family code — silence.
        root = _tree(tmp_path, {"lib.c": (
            "int do_check(int x) {\n"
            "    if (x < 0)\n"
            "        return -1;\n"
            "    return 7;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert 7 in dom.proven_values
        assert not dom.proven_wider

    def test_assignment_with_adjacent_jump_proves(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": (
            "int do_check(int x) {\n"
            "    int rc = 0;\n"
            "    if (x < 0) {\n"
            "        rc = -3;\n"
            "        goto out;\n"
            "    }\n"
            "out:\n"
            "    return rc;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -3 in dom.proven_values
        assert dom.proven_wider

    def test_plain_assignment_without_jump_is_not_proof(self, tmp_path):
        # Normalisation safety: a later unconditional overwrite may
        # narrow the domain; without an adjacent jump the value is
        # not provably returnable.
        root = _tree(tmp_path, {"lib.c": (
            "int do_check(int x) {\n"
            "    int rc = 0;\n"
            "    rc = -3;\n"
            "    if (x < 0)\n"
            "        rc = -1;\n"
            "    return rc;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -3 not in dom.proven_values
        assert not dom.proven_wider

    def test_tail_call_propagation(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": (
            "int inner(int x) {\n"
            "    if (x < 0)\n"
            "        return -4;\n"
            "    return 0;\n"
            "}\n"
            "int do_check(int x) {\n"
            "    return inner(x);\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -4 in dom.proven_values
        assert dom.proven_wider

    def test_guarded_capture_goto_propagation(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": (
            "int inner(int x) {\n"
            "    if (x < 0)\n"
            "        return -4;\n"
            "    return 0;\n"
            "}\n"
            "int do_check(int x) {\n"
            "    int rc = 0;\n"
            "    if ((rc = inner(x)) != 0)\n"
            "        goto fail;\n"
            "    rc = 0;\n"
            "fail:\n"
            "    return rc;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -4 in dom.proven_values
        assert dom.proven_wider

    def test_guard_operator_filters_propagated_values(self, tmp_path):
        # `== -1` guard: only -1 can jump out — the wide value never
        # propagates through it.
        root = _tree(tmp_path, {"lib.c": (
            "int inner(int x) {\n"
            "    if (x < 0)\n"
            "        return -4;\n"
            "    return -1;\n"
            "}\n"
            "int do_check(int x) {\n"
            "    int rc;\n"
            "    if ((rc = inner(x)) == -1)\n"
            "        return rc;\n"
            "    return 0;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -4 not in dom.proven_values
        assert not dom.proven_wider

    def test_label_region_reassignment_kills_propagation(
        self, tmp_path,
    ):
        root = _tree(tmp_path, {"lib.c": (
            "int inner(int x) {\n"
            "    if (x < 0)\n"
            "        return -4;\n"
            "    return 0;\n"
            "}\n"
            "int do_check(int x) {\n"
            "    int rc = 0;\n"
            "    if ((rc = inner(x)) != 0)\n"
            "        goto fail;\n"
            "    return 0;\n"
            "fail:\n"
            "    rc = -1;\n"
            "    return rc;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -4 not in dom.proven_values
        assert not dom.proven_wider

    def test_shielded_conditional_reassignment_keeps_the_proof(
        self, tmp_path,
    ):
        # A region reassignment dominated by a success-shape guard
        # (`rc == 0`) provably cannot alter a negative error return.
        root = _tree(tmp_path, {"lib.c": (
            "int inner(int x) {\n"
            "    if (x < 0)\n"
            "        return -4;\n"
            "    return 0;\n"
            "}\n"
            "int refresh(int x);\n"
            "int do_check(int x) {\n"
            "    int rc = 0;\n"
            "    if ((rc = inner(x)) != 0)\n"
            "        goto fail;\n"
            "fail:\n"
            "    if (rc == 0 && x > 0)\n"
            "        rc = refresh(x);\n"
            "    return rc;\n"
            "}\n"
        )})
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert -4 in dom.proven_values
        assert dom.proven_wider

    def test_multiple_definitions_need_unanimous_wideness(
        self, tmp_path,
    ):
        # Two definitions of the same name (portability copies): the
        # wider claim needs EVERY definition to prove it — a
        # linked-copy ambiguity must not manufacture a witness.
        root = _tree(tmp_path, {
            "a.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return -2;\n"
                "    return 0;\n"
                "}\n"
            ),
            "compat/a.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        dom = derive_return_domain("do_check", [root])
        assert dom is not None
        assert not dom.proven_wider

    def test_no_definition_yields_none(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": "int unrelated(void) { return 0; }\n"})
        assert derive_return_domain("do_check", [root]) is None

    def test_truncated_derivation_is_not_cached(self, tmp_path):
        root = _tree(tmp_path, {"lib.c": (
            "int do_check(int x) {\n"
            "    if (x < 0)\n"
            "        return -2;\n"
            "    return 0;\n"
            "}\n"
        )})
        starved = derive_return_domain("do_check", [root], budget_s=0.0)
        assert starved is None or not starved.proven_wider
        dom = derive_return_domain("do_check", [root])
        assert dom is not None and dom.proven_wider


# ── detector entry point ─────────────────────────────────────────────


class TestDetector:
    def test_mismatch_emitted_with_constructive_receipt(self, tmp_path):
        root = _tree(tmp_path, {
            "caller.c": _CALLER,
            "lib.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return -2;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        finds = detect_return_domain_mismatches(
            {"caller.c": (root / "caller.c").read_text()},
            roots=[root],
        )
        assert len(finds) == 1
        f = finds[0]
        assert isinstance(f, ReturnDomainMismatch)
        assert (f.file, f.function, f.callee) == (
            "caller.c", "handle_peer", "do_check",
        )
        assert f.shape == "== -1"
        assert "-2" in f.description
        assert "lib.c:3" in f.description

    def test_definition_found_under_a_second_root(self, tmp_path):
        # The audited tree may be an excerpt; the definition arrives
        # through a wider source root supplied second.
        excerpt = _tree(tmp_path, {"caller.c": _CALLER})
        wide = tmp_path / "wide"
        (wide / "lib").mkdir(parents=True)
        (wide / "lib" / "impl.c").write_text(
            "int do_check(int x) {\n"
            "    if (x < 0)\n"
            "        return -2;\n"
            "    return 0;\n"
            "}\n"
        )
        finds = detect_return_domain_mismatches(
            {"caller.c": (excerpt / "caller.c").read_text()},
            roots=[excerpt, wide],
        )
        assert len(finds) == 1
        assert finds[0].callee == "do_check"

    def test_binary_callee_stays_silent(self, tmp_path):
        root = _tree(tmp_path, {
            "caller.c": _CALLER,
            "lib.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return -1;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        finds = detect_return_domain_mismatches(
            {"caller.c": (root / "caller.c").read_text()},
            roots=[root],
        )
        assert finds == []

    def test_undefined_callee_stays_silent(self, tmp_path):
        root = _tree(tmp_path, {"caller.c": _CALLER})
        finds = detect_return_domain_mismatches(
            {"caller.c": (root / "caller.c").read_text()},
            roots=[root],
        )
        assert finds == []

    def test_exhausted_budget_fails_toward_silence(self, tmp_path):
        root = _tree(tmp_path, {
            "caller.c": _CALLER,
            "lib.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return -2;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        finds = detect_return_domain_mismatches(
            {"caller.c": (root / "caller.c").read_text()},
            roots=[root],
            budget_s=0.0,
        )
        assert finds == []

    def test_peer_full_domain_checks_ride_as_corroboration(
        self, tmp_path,
    ):
        peer = (
            "int other_path(int x) {\n"
            "    if (do_check(x) != 0)\n"
            "        return -1;\n"
            "    return 0;\n"
            "}\n"
        )
        root = _tree(tmp_path, {
            "caller.c": _CALLER,
            "peer.c": peer,
            "lib.c": (
                "int do_check(int x) {\n"
                "    if (x < 0)\n"
                "        return -2;\n"
                "    return 0;\n"
                "}\n"
            ),
        })
        finds = detect_return_domain_mismatches(
            {
                "caller.c": (root / "caller.c").read_text(),
                "peer.c": peer,
            },
            roots=[root],
        )
        assert len(finds) == 1
        assert any("!= 0" in p for p in finds[0].peer_checks)
