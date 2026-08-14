"""Tests for callback_lifetime — Lever 6 callback-context awareness."""

from core.audit.callback_lifetime import (
    check_callback_lifetime_local,
    _check_rcu_kfree,
    _extract_struct_var,
    CallbackLifetimeResult,
    CallbackLifetimeViolation,
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
