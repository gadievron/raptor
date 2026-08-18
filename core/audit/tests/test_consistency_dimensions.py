"""Flag/mode + error-path cleanup consistency comparators (§3.7, §3.2).

One fixture pair per shape, real-world-shaped, hermetic.
"""

from __future__ import annotations

import textwrap

from core.audit.consistency_dimensions import (
    detect_flag_mode_deviations,
)
from core.testing import requires_ts


def _open_fixture(deviant_flags: str) -> dict[str, str]:
    parts = []
    for i in range(4):
        parts.append(textwrap.dedent(f"""\
            int writer_{i}(const char *p) {{
                int fd = open(p, O_WRONLY|O_CREAT|O_NOFOLLOW, 0600);
                return fd;
            }}
        """))
    parts.append(textwrap.dedent(f"""\
        int writer_dev(const char *p) {{
            int fd = open(p, {deviant_flags}, 0600);
            return fd;
        }}
    """))
    return {"src/writers.c": "\n".join(parts)}


class TestBitmaskLeg:
    @requires_ts('c')
    def test_missing_nofollow_flagged_and_graded(self):
        devs = detect_flag_mode_deviations(
            _open_fixture("O_WRONLY|O_CREAT"),
        )
        nofollow = [
            d for d in devs
            if d.kind == "bitmask" and "O_NOFOLLOW" in d.majority_repr
        ]
        assert len(nofollow) == 1
        d = nofollow[0]
        assert d.callee == "open"
        assert d.enclosing_function == "writer_dev"
        assert d.n == 5
        assert d.conforming == 4
        # Tier-A grading from the single shared registry.
        assert d.security is not None
        assert d.security.role == "fs_isolation"
        assert d.cwe == "CWE-59"
        pe = d.peer_evidence
        assert pe.dimension == "flag-mode"
        assert pe.contract_source == "majority"
        assert pe.rule_id == "consistency:flag-mode-majority"
        assert len(pe.exhibits) == 3

    def test_conforming_twin_not_flagged(self):
        devs = detect_flag_mode_deviations(
            _open_fixture("O_WRONLY|O_CREAT|O_NOFOLLOW"),
        )
        assert not [d for d in devs if "O_NOFOLLOW" in d.majority_repr]

    def test_per_bit_majority_not_set_equality(self):
        """An extra harmless flag at one site must not create a
        deviation for the sites lacking it when it is minority-only."""
        texts = _open_fixture("O_WRONLY|O_CREAT|O_NOFOLLOW|O_APPEND")
        devs = detect_flag_mode_deviations(texts)
        # O_APPEND is present at 1/5 — the four others are NOT deviant.
        assert not [d for d in devs if "O_APPEND" in d.majority_repr]

    def test_below_min_sites_no_group(self):
        texts = {"src/w.c": textwrap.dedent("""\
            int a(const char *p) {
                return open(p, O_WRONLY|O_NOFOLLOW, 0600);
            }
            int b(const char *p) {
                return open(p, O_WRONLY, 0600);
            }
        """)}
        assert detect_flag_mode_deviations(texts) == []


@requires_ts('c')
class TestValueLeg:
    def test_permissive_mode_deviant_graded(self):
        parts = []
        for i in range(4):
            parts.append(textwrap.dedent(f"""\
                void m{i}(const char *p) {{
                    chmod(p, 0600);
                }}
            """))
        parts.append(textwrap.dedent("""\
            void m_dev(const char *p) {
                chmod(p, 0666);
            }
        """))
        devs = detect_flag_mode_deviations({"src/m.c": "\n".join(parts)})
        value_devs = [d for d in devs if d.kind == "value"]
        assert len(value_devs) == 1
        d = value_devs[0]
        assert d.enclosing_function == "m_dev"
        assert d.majority_repr == "0o600"
        assert d.cwe == "CWE-732"

    def test_named_constant_resolved(self):
        parts = []
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                void m{i}(const char *p) {{
                    chmod(p, SAFE_MODE);
                }}
            """))
        parts.append("void m_dev(const char *p) {\n    chmod(p, 0777);\n}\n")
        devs = detect_flag_mode_deviations(
            {"src/m.c": "\n".join(parts)},
            constants={"SAFE_MODE": 0o600},
        )
        value_devs = [d for d in devs if d.kind == "value"]
        assert len(value_devs) == 1
        assert value_devs[0].enclosing_function == "m_dev"

    def test_unresolvable_position_skipped(self):
        parts = []
        for i in range(4):
            parts.append(textwrap.dedent(f"""\
                void m{i}(const char *p, int mode{i}) {{
                    chmod(p, mode{i});
                }}
            """))
        assert detect_flag_mode_deviations(
            {"src/m.c": "\n".join(parts)},
        ) == []


class TestKwargLeg:
    def _requests_fixture(self, deviant_value: str) -> dict[str, str]:
        parts = []
        for i in range(4):
            parts.append(textwrap.dedent(f"""\
                def fetch_{i}(url):
                    return requests.get(url, verify=True)
            """))
        parts.append(textwrap.dedent(f"""\
            def fetch_dev(url):
                return requests.get(url, verify={deviant_value})
        """))
        return {"client.py": "\n".join(parts)}

    @requires_ts('python')
    def test_verify_false_among_true_peers(self):
        devs = detect_flag_mode_deviations(self._requests_fixture("False"))
        kw = [d for d in devs if d.kind == "kwarg"]
        assert len(kw) == 1
        d = kw[0]
        assert d.position == "kwarg:verify"
        assert d.deviant_repr == "verify=False"
        assert d.majority_repr == "verify=True"
        assert d.security is not None and d.cwe == "CWE-295"
        assert d.enclosing_function == "fetch_dev"

    def test_conforming_twin_not_flagged(self):
        devs = detect_flag_mode_deviations(self._requests_fixture("True"))
        assert not [d for d in devs if d.kind == "kwarg"]


class TestTierAFlagRegistryPolicy:
    def test_budget_lint_still_clean(self):
        from core.audit.fail_open_roles import registry_budget_violations

        assert registry_budget_violations() == []

    @requires_ts('c')
    def test_grading_is_grading_only(self):
        """An ungraded (non-Tier-A) flag deviation is still detected —
        the comparator is vocabulary-free (§3.7)."""
        parts = []
        for i in range(4):
            parts.append(textwrap.dedent(f"""\
                int w{i}(const char *p) {{
                    return open(p, MYAPP_SAFE|MYAPP_SYNC, 0600);
                }}
            """))
        parts.append(textwrap.dedent("""\
            int w_dev(const char *p) {
                return open(p, MYAPP_SYNC, 0600);
            }
        """))
        devs = detect_flag_mode_deviations({"src/w.c": "\n".join(parts)})
        mine = [d for d in devs if "MYAPP_SAFE" in d.majority_repr]
        assert len(mine) == 1
        assert mine[0].security is None
        assert mine[0].cwe == ""


# ── error-path cleanup (§3.2) ───────────────────────────────────────


_CLEANUP_MODEL = {
    "paired_operations": [
        {"acquire": "grab_lock", "release": "drop_lock", "kind": "mutex"},
    ],
}


def _cleanup_intra_fixture(deviant_returns_holding: bool) -> dict[str, str]:
    tail = (
        "    if (c < 0)\n        return -3;\n"
        if deviant_returns_holding else
        "    if (c < 0) {\n        drop_lock(lk);\n        return -3;\n    }\n"
    )
    src = (
        "int worker(int a, int b, int c) {\n"
        "    lock_t *lk = grab_lock();\n"
        "    if (a < 0) {\n"
        "        drop_lock(lk);\n"
        "        return -1;\n"
        "    }\n"
        "    if (b < 0) {\n"
        "        drop_lock(lk);\n"
        "        return -2;\n"
        "    }\n"
        + tail +
        "    drop_lock(lk);\n"
        "    return 0;\n"
        "}\n"
    )
    return {"src/worker.c": src}


class TestCleanupPairs:
    def test_pairs_from_domain_model(self):
        from core.audit.consistency_dimensions import learned_cleanup_pairs

        pairs = learned_cleanup_pairs(_CLEANUP_MODEL)
        assert len(pairs) == 1
        assert pairs[0].acquire == "grab_lock"
        assert pairs[0].release == "drop_lock"
        assert pairs[0].source == "domain_model"
        assert pairs[0].provenance == "paired_operations:mutex"

    def test_pairs_from_project_verbs(self):
        from core.audit.consistency_dimensions import learned_cleanup_pairs

        names = {
            "begin_transaction", "end_transaction",
            "begin_session", "end_session",
            "handle_request",
        }
        pairs = learned_cleanup_pairs(None, names)
        keys = {(p.acquire, p.release) for p in pairs}
        assert ("begin_transaction", "end_transaction") in keys
        assert ("begin_session", "end_session") in keys
        assert all(p.source == "project_verbs" for p in pairs)

    def test_no_learned_input_no_pairs(self):
        """Vocabulary policy: without a learned surface there are NO
        pairs — no hardcoded fallback list."""
        from core.audit.consistency_dimensions import learned_cleanup_pairs

        assert learned_cleanup_pairs(None, None) == []
        assert learned_cleanup_pairs({}, set()) == []


class TestCleanupIntraLeg:
    @requires_ts('c')
    def test_deviant_error_path_confirms(self):
        from core.audit.consistency_dimensions import (
            detect_cleanup_deviations,
            learned_cleanup_pairs,
        )
        from core.audit.consistency_verify import cleanup_verdict

        pairs = learned_cleanup_pairs(_CLEANUP_MODEL)
        devs = detect_cleanup_deviations(
            _cleanup_intra_fixture(True), pairs,
        )
        intra = [d for d in devs if d.leg == "intra_path"]
        assert len(intra) == 1
        d = intra[0]
        assert d.enclosing_function == "worker"
        assert d.n == 4
        assert d.conforming == 3
        assert d.binding == "lk"
        assert not d.ownership_transfer
        res = cleanup_verdict(d)
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:cleanup"
        assert res.contract["grade"] == "registry"
        pe = res.peer_evidence
        assert pe.dimension == "cleanup"
        assert pe.formation == "branch"
        assert pe.n == 4 and pe.conforming == 3

    def test_conforming_twin_clean(self):
        from core.audit.consistency_dimensions import (
            detect_cleanup_deviations,
            learned_cleanup_pairs,
        )

        pairs = learned_cleanup_pairs(_CLEANUP_MODEL)
        devs = detect_cleanup_deviations(
            _cleanup_intra_fixture(False), pairs,
        )
        assert [d for d in devs if d.leg == "intra_path"] == []


@requires_ts('c')
class TestCleanupCrossLeg:
    def _cross_fixture(self, *, transfer: bool) -> dict[str, str]:
        parts = []
        for i in range(3):
            parts.append(
                f"int user_{i}(void) {{\n"
                f"    res_t *r{i} = grab_lock();\n"
                f"    use(r{i});\n"
                f"    drop_lock(r{i});\n"
                f"    return 0;\n}}\n"
            )
        if transfer:
            parts.append(
                "res_t *maker(void) {\n"
                "    res_t *r = grab_lock();\n"
                "    return r;\n}\n"
            )
        else:
            parts.append(
                "int leaker(void) {\n"
                "    res_t *r = grab_lock();\n"
                "    use(r);\n"
                "    return 0;\n}\n"
            )
        return {"src/users.c": "\n".join(parts)}

    def test_missing_release_confirms(self):
        from core.audit.consistency_dimensions import (
            detect_cleanup_deviations,
            learned_cleanup_pairs,
        )
        from core.audit.consistency_verify import cleanup_verdict

        pairs = learned_cleanup_pairs(_CLEANUP_MODEL)
        devs = detect_cleanup_deviations(
            self._cross_fixture(transfer=False), pairs,
        )
        cross = [d for d in devs if d.leg == "cross_function"]
        assert len(cross) == 1
        d = cross[0]
        assert d.enclosing_function == "leaker"
        assert d.n == 4 and d.conforming == 3
        res = cleanup_verdict(d)
        assert res.outcome == "confirmed"

    def test_ownership_transfer_is_inconclusive(self):
        from core.audit.consistency_dimensions import (
            detect_cleanup_deviations,
            learned_cleanup_pairs,
        )
        from core.audit.consistency_verify import (
            REASON_OWNERSHIP_UNRESOLVED,
            cleanup_verdict,
        )

        pairs = learned_cleanup_pairs(_CLEANUP_MODEL)
        devs = detect_cleanup_deviations(
            self._cross_fixture(transfer=True), pairs,
        )
        cross = [d for d in devs if d.leg == "cross_function"]
        assert len(cross) == 1
        assert cross[0].ownership_transfer is True
        res = cleanup_verdict(cross[0])
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_OWNERSHIP_UNRESOLVED)
