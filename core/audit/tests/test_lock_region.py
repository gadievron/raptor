"""lock_region channel tests (five-channel programme §5).

Anchor: the OpenSSL ssl_sess session-cache flush shape — the remove
callback fired under ``ctx->lock`` (no crisp public CVE for this
exact class; the in-tree flush comment is the anchor, stated as such
rather than inventing one). Fixture pairs assert full receipts on the
deviant form and the exact enumerated reason string on the twin.
Hermetic: the cocci corroboration leg is stubbed (one optional live
test runs only when spatch is installed).
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.audit import lock_region as lr
from core.audit.lock_region import (
    COCCI_STAMP,
    DETECTION_VARIANT_SUFFIX,
    LOCK_REGION_CWES,
    RULE_CALLBACK_UNDER_LOCK,
    cocci_corroboration,
    is_detection_rule_id,
    is_lock_region_hypothesis,
    lock_region_applicable,
    run_lock_region_check,
    run_lock_region_prepass,
    status_for,
)


def _ts_available() -> bool:
    from core.audit.callsite_consistency import parse_source_cached
    tree, _ = parse_source_cached("probe.c", "int f(void) { return 0; }")
    return tree is not None


requires_ts = pytest.mark.skipif(
    not _ts_available(), reason="tree-sitter C grammar unavailable",
)


class _Vocab:
    def __init__(self, lock_pairs=(), callback_registers=(),
                 callback_cancels=()):
        self.lock_pairs = frozenset(lock_pairs)
        self.callback_registers = frozenset(callback_registers)
        self.callback_cancels = frozenset(callback_cancels)
        self.deallocators = frozenset()


SSL_SESS = """
void SSL_CTX_sess_set_remove_cb(struct SSL_CTX *ctx, void (*cb)(int)) {
    ctx->remove_cb = cb;
}
void flush_sessions(struct SSL_CTX *ctx) {
    CRYPTO_THREAD_write_lock(ctx->lock);
    /* the remove callback fires while the lock is held */
    ctx->remove_cb(1);
    CRYPTO_THREAD_unlock(ctx->lock);
}
"""

SSL_SESS_UNLOCK_FIRST = """
void SSL_CTX_sess_set_remove_cb(struct SSL_CTX *ctx, void (*cb)(int)) {
    ctx->remove_cb = cb;
}
void flush_sessions(struct SSL_CTX *ctx) {
    CRYPTO_THREAD_write_lock(ctx->lock);
    CRYPTO_THREAD_unlock(ctx->lock);
    ctx->remove_cb(1);
}
"""

HYP = "the remove callback is invoked while the session lock is held"


def _entry_ctx(function: str, file: str):
    from core.audit.fail_open_roles import RoleContext
    return RoleContext(context_map={"entry_points": [
        {"function": function, "file": file},
    ]})


class TestClassifier:
    @pytest.mark.parametrize("text", [
        "callback invoked while holding the lock",
        "the handler runs inside the lock region",
        "function pointer fired with the mutex lock held",
        "lock held across the remove callback",
        "reentrancy through cb while under lock",
        "deadlock if the callback re-enters the same lock",
    ])
    def test_accepts(self, text):
        assert is_lock_region_hypothesis(text)

    @pytest.mark.parametrize("text", [
        "",
        "unchecked memcpy overflow",
        "stale pointer cached in the port field",     # ptr_lifecycle
        "9/10 callers check do_auth()'s return",       # consistency
        "lock imbalance: error path returns without unlock",  # CWE-667
    ])
    def test_rejects(self, text):
        assert not is_lock_region_hypothesis(text)

    def test_cwe_membership(self):
        assert LOCK_REGION_CWES == {"CWE-833", "CWE-667"}
        assert lock_region_applicable("CWE-833")
        assert lock_region_applicable("667")
        assert not lock_region_applicable("CWE-416")

    def test_detection_rule_id(self):
        assert is_detection_rule_id(
            RULE_CALLBACK_UNDER_LOCK + DETECTION_VARIANT_SUFFIX,
        )
        assert not is_detection_rule_id(RULE_CALLBACK_UNDER_LOCK)


@requires_ts
class TestAdjudication:
    def test_ssl_sess_shape_registry_confirm_both_escalators(self):
        res = run_lock_region_check(
            Path("/nonexistent"), "ssl/s.c", "flush_sessions", HYP,
            source_texts={"ssl/s.c": SSL_SESS},
            context=_entry_ctx("flush_sessions", "ssl/s.c"),
        )
        assert res.outcome == "confirmed"
        # Seed pair (CRYPTO_THREAD) + exported setter ⇒ registry.
        assert res.rule_id == RULE_CALLBACK_UNDER_LOCK
        d = res.to_dict()
        assert d["lock"]["acquire"] == "CRYPTO_THREAD_write_lock"
        assert d["lock"]["pair_source"] == "seed"
        assert d["region"]["span"] == [6, 9]
        assert d["callback"]["expr"] == "ctx->remove_cb"
        assert d["callback"]["registered_by"] == \
            "SSL_CTX_sess_set_remove_cb"
        assert d["callback"]["setter_exported"] is True
        # Documented-behaviour receipt: the in-region comment.
        assert "lock is held" in d["comment"]
        # Both escalators present ⇒ finding.
        assert res.reachability["status"] == "entry_reachable"
        assert status_for(res) == "finding"

    def test_unlock_before_cb_twin_refutes_with_path_receipt(self):
        res = run_lock_region_check(
            Path("/nonexistent"), "ssl/s.c", "flush_sessions", HYP,
            source_texts={"ssl/s.c": SSL_SESS_UNLOCK_FIRST},
        )
        assert res.outcome == "refuted"
        assert "precedes every callback-shaped invocation" in res.reason

    def test_naming_only_lock_is_detection_variant(self):
        src = (
            "void f(struct s *s) {\n"
            "    table_lock(s->m);\n"
            "    s->cb(1);\n"
            "    table_unlock(s->m);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == \
            RULE_CALLBACK_UNDER_LOCK + DETECTION_VARIANT_SUFFIX
        assert res.to_dict()["lock"]["pair_source"] == "naming"

    def test_learned_pair_with_exported_setter_is_registry(self):
        src = (
            "void set_hook(struct s *x, void (*h)(int)) {\n"
            "    x->hook = h;\n"
            "}\n"
            "void f(struct s *s) {\n"
            "    ossl_acquire(s->m);\n"
            "    s->hook(1);\n"
            "    ossl_drop(s->m);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
            domain_vocab=_Vocab(
                lock_pairs={("ossl_acquire", "ossl_drop")},
            ),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_CALLBACK_UNDER_LOCK
        assert res.to_dict()["lock"]["pair_source"] == "learned"

    def test_internal_only_setter_caps_at_suspicious(self):
        src = (
            "static void set_cb(struct s *x, void (*cb)(int)) {\n"
            "    x->remove_cb = cb;\n"
            "}\n"
            "void f(struct s *s) {\n"
            "    pthread_mutex_lock(s->m);\n"
            "    s->remove_cb(1);\n"
            "    pthread_mutex_unlock(s->m);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
            context=_entry_ctx("f", "a.c"),
        )
        assert res.outcome == "confirmed"
        # Escalator test: entry-reachable but internal-only setter —
        # detection variant AND suspicious cap.
        assert res.rule_id == \
            RULE_CALLBACK_UNDER_LOCK + DETECTION_VARIANT_SUFFIX
        assert res.to_dict()["callback"]["setter_exported"] is False
        assert status_for(res) == "suspicious"

    def test_cancel_verb_in_region_refutes(self):
        src = (
            "void f(struct s *s) {\n"
            "    pthread_mutex_lock(s->m);\n"
            "    tasklet_kill(&s->t);\n"
            "    pthread_mutex_unlock(s->m);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
        )
        assert res.outcome == "refuted"
        assert "teardown-safe tasklet_kill()" in res.reason

    def test_registered_name_shape_confirms(self):
        src = (
            "void setup(struct s *s) {\n"
            "    hook_register(s, my_handler);\n"
            "}\n"
            "void f(struct s *s) {\n"
            "    pthread_mutex_lock(s->m);\n"
            "    my_handler(1);\n"
            "    pthread_mutex_unlock(s->m);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
            domain_vocab=_Vocab(callback_registers={"hook_register"}),
        )
        assert res.outcome == "confirmed"
        assert res.to_dict()["callback"]["shape"] == "named"

    def test_release_in_callee_is_phase_two(self):
        src = (
            "void do_unlock(struct s *s) {\n"
            "    pthread_mutex_unlock(s->m);\n"
            "}\n"
            "void f(struct s *s) {\n"
            "    pthread_mutex_lock(s->m);\n"
            "    s->cb(1);\n"
            "    do_unlock(s);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(lr.REASON_REGION_SPANS_CALLEE)
        assert "do_unlock" in res.reason

    def test_missing_release_is_pair_unresolved(self):
        src = (
            "void f(struct s *s) {\n"
            "    pthread_mutex_lock(s->m);\n"
            "    s->cb(1);\n"
            "}\n"
        )
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": src},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(lr.REASON_PAIR_UNRESOLVED)
        assert "lock-imbalance" in res.reason

    def test_no_lock_shape_is_unbindable(self):
        res = run_lock_region_check(
            Path("/nonexistent"), "a.c", "f", HYP,
            source_texts={"a.c": "void f(struct s *s) { s->cb(1); }\n"},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(lr.REASON_HYPOTHESIS_UNBINDABLE)

    def test_language_unsupported(self):
        res = run_lock_region_check(
            Path("/nonexistent"), "a.go", "f", HYP,
            source_texts={"a.go": "func f() {}\n"},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(lr.REASON_LANGUAGE_UNSUPPORTED)


class TestCocciCorroboration:
    def _confirmed(self):
        return lr.LockRegionEvidence(
            outcome="confirmed",
            reason="r",
            lock={"acquire": "my_lock", "release": "my_unlock"},
        )

    def test_stub_match_returns_independent_namespace_stamp(
        self, monkeypatch, tmp_path,
    ):
        import packages.coccinelle.runner as runner

        class _Res:
            matches = [object()]

        monkeypatch.setattr(runner, "is_available", lambda: True)
        monkeypatch.setattr(
            runner, "run_rule", lambda *a, **kw: _Res(),
        )
        stamp = cocci_corroboration(tmp_path, self._confirmed())
        assert stamp == COCCI_STAMP
        assert stamp.split(":")[0] == "coccinelle"

    def test_stub_no_match_returns_none(self, monkeypatch, tmp_path):
        import packages.coccinelle.runner as runner

        class _Res:
            matches = []

        monkeypatch.setattr(runner, "is_available", lambda: True)
        monkeypatch.setattr(
            runner, "run_rule", lambda *a, **kw: _Res(),
        )
        assert cocci_corroboration(tmp_path, self._confirmed()) is None

    def test_never_runs_on_non_confirmed(self, monkeypatch, tmp_path):
        import packages.coccinelle.runner as runner

        def _explode():
            raise AssertionError("must not run")

        monkeypatch.setattr(runner, "is_available", _explode)
        res = lr.LockRegionEvidence(outcome="refuted", reason="r")
        assert cocci_corroboration(tmp_path, res) is None

    def test_rejects_non_identifier_defines(self, monkeypatch, tmp_path):
        import packages.coccinelle.runner as runner

        def _explode():
            raise AssertionError("must not run")

        monkeypatch.setattr(runner, "is_available", _explode)
        res = lr.LockRegionEvidence(
            outcome="confirmed", reason="r",
            lock={"acquire": "my_lock; rm -rf", "release": "u"},
        )
        assert cocci_corroboration(tmp_path, res) is None

    def test_detection_role_and_aggregation(self):
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
            _is_detection_only,
        )
        # The stock rule is @role: detection — the stamp corroborates
        # but never promotes alone; naming-variant channel receipt +
        # cocci stamp = two independent namespaces ⇒ aggregation.
        assert _is_detection_only(COCCI_STAMP)
        channels, _ = _aggregate_channel_confirmations([
            RULE_CALLBACK_UNDER_LOCK + DETECTION_VARIANT_SUFFIX,
            COCCI_STAMP,
        ])
        assert channels == ["coccinelle", "lock_region"]

    @pytest.mark.skipif(
        shutil.which("spatch") is None, reason="spatch not installed",
    )
    def test_live_spatch_match(self, tmp_path):
        (tmp_path / "s.c").write_text(
            "void f(struct s *p, void *l) {\n"
            "    my_lock(l);\n"
            "    p->cb(1);\n"
            "    my_unlock(l);\n"
            "}\n",
        )
        assert cocci_corroboration(
            tmp_path, self._confirmed(),
        ) == COCCI_STAMP

    @pytest.mark.skipif(
        shutil.which("spatch") is None, reason="spatch not installed",
    )
    def test_live_spatch_no_match_after_release(self, tmp_path):
        (tmp_path / "s.c").write_text(
            "void f(struct s *p, void *l) {\n"
            "    my_lock(l);\n"
            "    my_unlock(l);\n"
            "    p->cb(1);\n"
            "}\n",
        )
        assert cocci_corroboration(
            tmp_path, self._confirmed(),
        ) is None


@requires_ts
class TestPrepass:
    def test_prepass_emits_candidates_and_handoffs(self):
        out = run_lock_region_prepass({"ssl/s.c": SSL_SESS})
        assert len(out["mechanical"]) == 1
        mf = out["mechanical"][0]
        assert mf["detector"] == "callback_under_lock"
        assert mf["cwe"] == "CWE-833"
        assert mf["rule_id"] == RULE_CALLBACK_UNDER_LOCK
        assert out["handoffs"][0]["function"] == "flush_sessions"
        assert "callback invoked while lock held" in \
            out["handoffs"][0]["mechanism"]
        assert out["telemetry"]["candidates"] == 1

    def test_prepass_skips_lockless_files(self):
        out = run_lock_region_prepass(
            {"a.c": "void f(struct s *s) { s->cb(1); }\n"},
        )
        assert out["mechanical"] == []
        assert out["telemetry"]["candidates"] == 0

    def test_budget_overrun_sets_telemetry(self):
        out = run_lock_region_prepass(
            {"ssl/s.c": SSL_SESS}, budget_s=0.0,
        )
        assert out["telemetry"]["budget_exceeded"]


class TestSeedPolicy:
    def test_seed_pairs_stay_seed_sized(self):
        assert len(lr._SEED_LOCK_PAIRS) <= 9

    def test_stem_pairing_never_matches_unlock_names(self):
        assert lr._STEM_LOCK_RE.match("foo_lock").group(1) == "foo"
        assert not lr._STEM_LOCK_RE.match("foo_unlock")
        assert not lr._STEM_LOCK_RE.match("unlock")
        # Bare "lock" yields an empty stem — the scanner skips it.
        assert lr._STEM_LOCK_RE.match("lock").group(1) == ""
