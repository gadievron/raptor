"""Tests for callback_lifetime — Lever 6 callback-context awareness."""

from core.audit.callback_lifetime import (
    CallbackLifetimeResult,
    CallbackLifetimeViolation,
    _check_rcu_kfree,
    _extract_struct_var,
    check_callback_lifetime_local,
)


class TestCallbackLifetimeLocal:
    """Tier 1: single-function free-without-cancel."""

    def test_timer_setup_then_kfree_no_cancel(self):
        src = (
            "void release(struct foo *f) {\n"
            "    timer_setup(&f->timer, callback, 0);\n"
            "    kfree(f);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert r.violation_found
        assert r.cancel_missing
        assert r.register_line == 2
        assert r.free_line == 3

    def test_timer_setup_with_cancel_sync(self):
        src = (
            "void release(struct foo *f) {\n"
            "    timer_setup(&f->timer, callback, 0);\n"
            "    del_timer_sync(&f->timer);\n"
            "    kfree(f);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert not r.violation_found

    def test_work_init_then_free_no_cancel(self):
        src = (
            "void cleanup(struct priv *p) {\n"
            "    INIT_WORK(&p->work, worker_fn);\n"
            "    do_stuff();\n"
            "    kfree(p);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert r.violation_found

    def test_work_init_with_flush(self):
        src = (
            "void cleanup(struct priv *p) {\n"
            "    INIT_WORK(&p->work, worker_fn);\n"
            "    flush_work(&p->work);\n"
            "    kfree(p);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert not r.violation_found

    def test_free_before_register_ignored(self):
        src = (
            "void init(struct foo *f) {\n"
            "    kfree(old);\n"
            "    timer_setup(&f->timer, callback, 0);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert not r.violation_found

    def test_no_registration_no_violation(self):
        src = (
            "void cleanup(struct foo *f) {\n"
            "    kfree(f);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert not r.violation_found

    def test_delayed_work_without_cancel(self):
        src = (
            "void teardown(struct ctx *c) {\n"
            "    INIT_DELAYED_WORK(&c->dwork, handler);\n"
            "    vfree(c);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert r.violation_found

    def test_tasklet_init_with_tasklet_kill(self):
        src = (
            "void release(struct dev *d) {\n"
            "    tasklet_init(&d->tlet, tasklet_fn, 0);\n"
            "    tasklet_kill(&d->tlet);\n"
            "    kfree(d);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert not r.violation_found


class TestRcuKfree:
    """Sub-pattern 6c: kfree on rcu_dereference variable."""

    def test_kfree_on_rcu_var(self):
        src = (
            "void release(struct list *head) {\n"
            "    rcu_read_lock();\n"
            "    p = rcu_dereference(head->first);\n"
            "    rcu_read_unlock();\n"
            "    kfree(p);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert r.violation_found
        assert r.rcu_kfree_mismatch
        assert "kfree_rcu" in r.reasoning

    def test_kfree_rcu_is_fine(self):
        lines = [
            "void release(struct list *head) {",
            "    rcu_read_lock();",
            "    p = rcu_dereference(head->first);",
            "    rcu_read_unlock();",
            "    kfree_rcu(p, rcu);",
            "}",
        ]
        r = _check_rcu_kfree(lines)
        assert r is None

    def test_kfree_on_non_rcu_var(self):
        lines = [
            "void release(struct foo *f) {",
            "    p = rcu_dereference(head->first);",
            "    kfree(f);",
            "}",
        ]
        r = _check_rcu_kfree(lines)
        assert r is None

    def test_no_rcu_deref(self):
        lines = [
            "void release(struct foo *f) {",
            "    kfree(f);",
            "}",
        ]
        r = _check_rcu_kfree(lines)
        assert r is None


class TestExtractStructVar:
    """Struct variable extraction from member expressions."""

    def test_simple(self):
        assert _extract_struct_var("&foo->timer") == "foo"

    def test_with_prefix(self):
        assert _extract_struct_var("&priv->work") == "priv"

    def test_no_arrow(self):
        assert _extract_struct_var("foo.timer") is None

    def test_empty(self):
        assert _extract_struct_var("") is None


class TestCallbackLifetimeResultToDict:
    """Serialisation of results."""

    def test_basic_violation(self):
        r = CallbackLifetimeResult(
            violation_found=True,
            register_line=10,
            free_line=20,
            cancel_missing=True,
            reasoning="test",
        )
        d = r.to_dict()
        assert d["violation_found"] is True
        assert d["register_line"] == 10
        assert d["cancel_missing"] is True

    def test_no_violation(self):
        r = CallbackLifetimeResult(reasoning="clean")
        d = r.to_dict()
        assert d["violation_found"] is False
        assert "register_line" not in d

    def test_rcu_mismatch(self):
        r = CallbackLifetimeResult(
            violation_found=True,
            rcu_kfree_mismatch=True,
            reasoning="test",
        )
        d = r.to_dict()
        assert d["rcu_kfree_mismatch"] is True

    def test_cross_function_violations(self):
        v = CallbackLifetimeViolation(
            register_func="init",
            register_line=5,
            free_func="release",
            free_line=15,
            callback="timer_cb",
            struct_member="&foo->timer",
            reasoning="cross-function",
        )
        r = CallbackLifetimeResult(
            violation_found=True,
            violations=[v],
            reasoning="1 violation",
        )
        d = r.to_dict()
        assert len(d["violations"]) == 1
        assert d["violations"][0]["register_func"] == "init"
        assert d["violations"][0]["free_func"] == "release"


# Pre-shrink name tuples (captured against the hardcoded-list build) —
# the equivalence baselines for the seeds + linux_kernel pack union.
_PRE_SHRINK_REGISTER = {
    "timer_setup", "setup_timer", "INIT_WORK", "INIT_DELAYED_WORK",
    "init_waitqueue_func_entry", "tasklet_init",
    "hrtimer_init", "mod_timer", "add_timer",
    "schedule_work", "schedule_delayed_work", "queue_work",
}

_PRE_SHRINK_CANCEL = {
    "del_timer_sync", "del_timer", "timer_delete_sync",
    "cancel_work_sync", "cancel_delayed_work_sync", "flush_work",
    "flush_delayed_work", "tasklet_kill", "hrtimer_cancel",
    "cancel_work", "remove_wait_queue",
}


def _kernel_pack():
    from core.audit.vocab_packs import load_pack

    pack = load_pack("linux_kernel")
    assert pack is not None
    return pack


class TestSeedShrinkEquivalence:
    """Seeds + linux_kernel pack reproduce the pre-shrink vocabulary.

    The kernel facility bulk moved to the pack's callback_registers /
    callback_cancels; on kernel targets (pack supplied) both tiers see
    exactly the names the hardcoded tuples used to carry.
    """

    def test_register_names_with_pack_match_pre_shrink(self):
        from core.audit.callback_lifetime import _register_names

        assert set(_register_names(_kernel_pack())) == _PRE_SHRINK_REGISTER

    def test_cancel_names_with_pack_match_pre_shrink(self):
        from core.audit.callback_lifetime import _cancel_names

        assert set(_cancel_names(_kernel_pack())) == _PRE_SHRINK_CANCEL

    def test_pack_tier_verdict_matches_pre_shrink(self):
        # mod_timer / del_timer are pack-tier names: with the pack the
        # pre-shrink verdict (registered, cancelled, freed → clean and
        # registered, freed → violation) is reproduced.
        armed = (
            "void teardown(struct foo *f) {\n"
            "    mod_timer(&f->timer, jiffies + 1);\n"
            "    kfree(f);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(armed, _kernel_pack())
        assert r.violation_found and r.cancel_missing

        cancelled = (
            "void teardown(struct foo *f) {\n"
            "    mod_timer(&f->timer, jiffies + 1);\n"
            "    del_timer(&f->timer);\n"
            "    kfree(f);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(cancelled, _kernel_pack())
        assert not r.violation_found


class TestSeedsOnlyFloor:
    """Without vocab, pack-tier names are no longer recognised
    (proving the shrink is real) while seed exemplars still fire."""

    def test_pack_tier_register_not_recognised_without_vocab(self):
        src = (
            "void teardown(struct foo *f) {\n"
            "    mod_timer(&f->timer, jiffies + 1);\n"
            "    kfree(f);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src)
        assert not r.violation_found

    def test_seed_sets_stay_seed_sized(self):
        from core.audit import callback_lifetime as cl

        assert len(cl._SEED_REGISTER_NAMES) <= 9
        assert len(cl._SEED_CANCEL_NAMES) <= 9
        assert len(cl._SEED_FREE_NAMES) <= 9


class TestLearnedVocabCoverageGain:
    """Study-learned register/cancel pairs extend both tiers —
    coverage the seeds and the pack lack."""

    @staticmethod
    def _learned():
        from core.audit.condition_smt import DomainVocabulary

        return DomainVocabulary.from_domain_model({
            "paired_operations": [
                {
                    "acquire": "proj_arm_watchdog",
                    "release": "proj_disarm_watchdog",
                    "kind": "callback",
                },
            ],
            "security_fields": [],
        })

    def test_learned_register_without_cancel_fires(self):
        src = (
            "void teardown(struct proj *p) {\n"
            "    proj_arm_watchdog(&p->wd, cb);\n"
            "    kfree(p);\n"
            "}\n"
        )
        assert not check_callback_lifetime_local(src).violation_found
        r = check_callback_lifetime_local(src, self._learned())
        assert r.violation_found and r.cancel_missing

    def test_learned_cancel_suppresses_violation(self):
        src = (
            "void teardown(struct proj *p) {\n"
            "    proj_arm_watchdog(&p->wd, cb);\n"
            "    proj_disarm_watchdog(&p->wd);\n"
            "    kfree(p);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src, self._learned())
        assert not r.violation_found

    def test_learned_deallocator_extends_free_set(self):
        from core.audit.condition_smt import DomainVocabulary

        vocab = DomainVocabulary.from_domain_model({
            "paired_operations": [
                {
                    "acquire": "proj_arm_watchdog",
                    "release": "proj_disarm_watchdog",
                    "kind": "callback",
                },
                {
                    "acquire": "proj_alloc_ctx",
                    "release": "proj_release_ctx",
                    "kind": "alloc",
                },
            ],
        })
        src = (
            "void teardown(struct proj *p) {\n"
            "    proj_arm_watchdog(&p->wd, cb);\n"
            "    proj_release_ctx(p);\n"
            "}\n"
        )
        r = check_callback_lifetime_local(src, vocab)
        assert r.violation_found and r.cancel_missing


class TestSingleSourcedNameAuthority:
    """Drift guard: both tiers derive from the same merged name sets.

    The Tier 2 Joern query used to hand-copy the Tier 1 regex
    alternations as string literals; these pins keep the derived
    forms equivalent so an edit to one tier cannot silently diverge
    from the other.
    """

    def test_tier1_regexes_derive_from_merged_sets(self):
        from core.audit import callback_lifetime as cl

        pack = _kernel_pack()
        for name in cl._register_names(pack):
            assert cl._call_re(cl._register_names(pack)).search(
                f"{name}(&f->w, cb);"
            )
        for name in cl._cancel_names(pack):
            assert cl._call_re(cl._cancel_names(pack)).search(f"{name}(&f->w);")
        for name in cl._free_names(pack):
            assert cl._call_re(cl._free_names(pack)).search(f"{name}(f);")

    def test_regex_requires_call_shape(self):
        from core.audit import callback_lifetime as cl

        re_ = cl._call_re(cl._register_names())
        assert not re_.search("my_timer_setup_helper(x);")
        assert not re_.search("timer_setup_count = 3;")

    def test_joern_alternations_cover_pre_split_literals_with_pack(self):
        from core.audit import callback_lifetime as cl

        pack = _kernel_pack()
        joern_reg = set(cl._register_names(pack)) - cl._JOERN_REGISTER_EXCLUDE
        joern_cancel = set(cl._cancel_names(pack))
        joern_free = set(cl._free_names(pack)) - cl._JOERN_FREE_EXCLUDE

        assert joern_reg == _PRE_SHRINK_REGISTER - {
            "init_waitqueue_func_entry",
        }
        assert joern_cancel == _PRE_SHRINK_CANCEL
        # Free superset: pack deallocators extend the pre-split free
        # list; the documented exclusions stay excluded.
        assert {"kfree", "vfree", "kvfree", "kfree_sensitive",
                "devm_kfree"} <= joern_free
        assert "free" not in joern_free
        assert "kfree_rcu" not in joern_free


class _ScriptedJoern:
    """Fake Joern handle: answers queries in order from a script.

    Each script entry is either a value (returned) or an Exception
    instance (raised).
    """

    def __init__(self, script):
        self._script = list(script)
        self.queries = []

    def query(self, q):
        self.queries.append(q)
        item = self._script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


_REG = [(10, "&foo->timer", "timer_cb", "init_foo")]
_FREE = [("release_foo", 42)]


class TestCrossCancelQueryError:
    """A failed cancel (refuter) query is a tool error — it must never
    fabricate a violation."""

    def test_cancel_query_exception_is_inconclusive_not_violation(self):
        from core.audit.callback_lifetime import (
            check_callback_lifetime_cross,
        )
        joern = _ScriptedJoern([_REG, _FREE, RuntimeError("cancelled")])
        r = check_callback_lifetime_cross(joern, "drv.c", "init_foo")
        assert r.violation_found is False
        assert not r.violations
        assert "inconclusive" in r.reasoning
        assert "unverified" in r.reasoning

    def test_cancel_query_empty_result_still_violates(self):
        from core.audit.callback_lifetime import (
            check_callback_lifetime_cross,
        )
        joern = _ScriptedJoern([_REG, _FREE, []])
        r = check_callback_lifetime_cross(joern, "drv.c", "init_foo")
        assert r.violation_found is True
        assert len(r.violations) == 1
        assert r.violations[0].free_func == "release_foo"

    def test_cancel_query_error_does_not_mask_other_violations(self):
        """One errored pair degrades that pair only; a genuinely
        unverified-cancel pair on another free site still reports."""
        from core.audit.callback_lifetime import (
            check_callback_lifetime_cross,
        )
        two_frees = [("release_a", 42), ("release_b", 77)]
        joern = _ScriptedJoern(
            [_REG, two_frees, RuntimeError("cancelled"), []],
        )
        r = check_callback_lifetime_cross(joern, "drv.c", "init_foo")
        assert r.violation_found is True
        assert len(r.violations) == 1
        assert r.violations[0].free_func == "release_b"
