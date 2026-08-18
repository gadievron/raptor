"""Seed-shrink pins for the condition_smt mechanical checkers.

The checkers' hardcoded kernel vocabulary moved to the linux_kernel
vocab pack (routed through DomainVocabulary). Three properties pinned
here:

1. SAME-INPUT EQUIVALENCE — with the kernel pack supplied, each
   checker reproduces the exact pre-shrink verdict on kernel fixtures
   (baselines were captured against the hardcoded-list build).
2. SEEDS-ONLY FLOOR — without any vocab, pack-tier names are no
   longer recognised (proving the shrink is real), while universal
   seeds still work.
3. VOCAB COVERAGE GAIN — a fixture vocabulary with made-up project
   names gives every checker coverage the seeds lack.
"""

from __future__ import annotations

from core.audit.condition_smt import (
    _SECURITY_FIELDS,
    DomainVocabulary,
    check_auth_bypass,
    check_lock_discipline,
    check_lock_domain,
    check_null_propagation,
    check_resource_leak,
)
from core.audit.vocab_packs import load_pack

LOCK_FIXTURE = """\
static int foo_ioctl(struct foo *f)
{
    down_read(&f->sem);
    if (f->bad)
        return -EINVAL;
    up_read(&f->sem);
    return 0;
}
"""

LOCK_SOCK_FIXTURE = """\
static int foo_setsockopt(struct sock *sk, int val)
{
    lock_sock(sk);
    if (val < 0)
        return -EINVAL;
    release_sock(sk);
    return 0;
}
"""

LEAK_FIXTURE = """\
static int foo_probe(struct device *dev)
{
    struct sk_buff *skb;
    int err;
    skb = alloc_skb(len, GFP_KERNEL);
    if (!skb)
        return -ENOMEM;
    err = foo_setup(skb);
    if (err)
        return err;
    kfree_skb(skb);
    return 0;
}
"""

NULLABLE_FIXTURE = """\
static int foo_probe(struct platform_device *pdev)
{
    struct foo *priv = dev_get_drvdata(&pdev->dev);
    priv->state = 1;
    return 0;
}
"""

AUTH_FIXTURE = """\
static int foo_setattr(struct inode *inode)
{
    if (fast_path)
        return 0;
    if (!ns_capable(ns, CAP_SYS_ADMIN))
        return -EPERM;
    return do_setattr(inode);
}
"""

FIELDS_FIXTURE = """\
static int foo_check(struct task_struct *task)
{
    int ok;
    rcu_read_lock();
    ok = task->cred->cap_effective;
    rcu_read_unlock();
    task_lock(task);
    dump = task->dumpable;
    task_unlock(task);
    if (ok && dump)
        return 1;
    return 0;
}
"""


def _pack():
    pack = load_pack("linux_kernel")
    assert pack is not None
    return pack


class TestPackEquivalence:
    """Pack-supplied names reproduce the pre-shrink verdicts exactly."""

    def test_lock_discipline_down_read(self):
        r = check_lock_discipline(LOCK_FIXTURE, _pack())
        assert r.violation_found
        assert r.lock_type == "down_read"
        assert r.return_line == 5

    def test_lock_discipline_lock_sock(self):
        r = check_lock_discipline(LOCK_SOCK_FIXTURE, _pack())
        assert r.violation_found
        assert r.lock_type == "lock_sock"
        assert r.return_line == 5

    def test_resource_leak_alloc_skb(self):
        r = check_resource_leak(LEAK_FIXTURE, _pack())
        assert r.leak_found
        assert (r.alloc_var, r.alloc_func) == ("skb", "alloc_skb")
        assert (r.alloc_line, r.return_line) == (5, 10)

    def test_null_propagation_driver_getter(self):
        r = check_null_propagation(NULLABLE_FIXTURE, _pack())
        assert r.null_deref_found
        assert (r.var_name, r.source_func) == ("priv", "dev_get_drvdata")
        assert (r.assign_line, r.deref_line) == (3, 4)

    def test_auth_bypass_ns_capable(self):
        r = check_auth_bypass(AUTH_FIXTURE, _pack())
        assert r.bypass_found
        assert r.bypassed_checks == [
            "capability:ns_capable(ns, CAP_SYS_ADMIN)",
        ]

    def test_correlated_security_fields(self):
        r = check_lock_domain(FIELDS_FIXTURE, _pack())
        d = r.to_dict()
        assert d["mismatch_found"]
        assert d["field"] == "cred + dumpable"
        assert d["lock1"] == "rcu_read_lock"
        assert d["lock2"] == "task_lock"


class TestSeedsOnlyFloor:
    """Without vocab, pack-tier names are gone; seeds still work."""

    def test_pack_tier_names_not_recognised(self):
        assert not check_lock_discipline(LOCK_FIXTURE).violation_found
        assert not check_lock_discipline(LOCK_SOCK_FIXTURE).violation_found
        assert not check_resource_leak(LEAK_FIXTURE).leak_found
        assert not check_null_propagation(NULLABLE_FIXTURE).null_deref_found
        assert not check_auth_bypass(AUTH_FIXTURE).bypass_found

    def test_universal_and_exemplar_seeds_still_fire(self):
        lock_src = LOCK_FIXTURE.replace("down_read", "mutex_lock").replace(
            "up_read", "mutex_unlock",
        )
        assert check_lock_discipline(lock_src).violation_found

        leak_src = LEAK_FIXTURE.replace("alloc_skb", "malloc").replace(
            "kfree_skb", "free",
        )
        assert check_resource_leak(leak_src).leak_found

        null_src = NULLABLE_FIXTURE.replace("dev_get_drvdata", "kzalloc")
        assert check_null_propagation(null_src).null_deref_found

        auth_src = AUTH_FIXTURE.replace("ns_capable", "capable")
        assert check_auth_bypass(auth_src).bypass_found

    def test_seed_sets_stay_seed_sized(self):
        from core.audit.condition_smt import (
            _ALLOC_PATTERNS,
            _AUTH_CHECK_PATTERNS,
            _FREE_NAMES,
            _LOCK_PAIRS,
            _NULLABLE_CALL_NAMES,
        )

        assert len(_LOCK_PAIRS) <= 9
        assert len(_ALLOC_PATTERNS) <= 9
        assert len(_FREE_NAMES) <= 9
        assert len(_NULLABLE_CALL_NAMES) <= 9
        assert len(_AUTH_CHECK_PATTERNS) <= 9
        assert len(_SECURITY_FIELDS) <= 9


class TestFixtureVocabCoverageGain:
    """Learned/pack vocab gives coverage the seeds lack."""

    _VOCAB = DomainVocabulary(
        lock_pairs=frozenset({("acme_bus_claim", "acme_bus_yield")}),
        lock_acquires=frozenset({"acme_bus_claim"}),
        lock_releases=frozenset({"acme_bus_yield"}),
        allocators=frozenset({"acme_buf_make"}),
        deallocators=frozenset({"acme_buf_drop"}),
        nullable_returns=frozenset({"acme_find_port"}),
        auth_predicates=frozenset({("acme_may_write", "domain")}),
        security_fields=frozenset({"acl_mask"}),
    )

    def test_lock_pairs_extend_discipline_check(self):
        src = (
            "int f(struct a *a){\n"
            "    acme_bus_claim(a);\n"
            "    if (a->bad)\n"
            "        return -1;\n"
            "    acme_bus_yield(a);\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_lock_discipline(src, self._VOCAB).violation_found
        assert not check_lock_discipline(src).violation_found

    def test_allocator_extends_leak_check(self):
        src = (
            "int g(void){\n"
            "    b = acme_buf_make(64);\n"
            "    if (!b)\n"
            "        return -1;\n"
            "    fill(b);\n"
            "    mark(b);\n"
            "    if (setup(b))\n"
            "        return -2;\n"
            "    acme_buf_drop(b);\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_resource_leak(src, self._VOCAB).leak_found
        assert not check_resource_leak(src).leak_found

    def test_nullable_return_extends_null_check(self):
        src = (
            "int h(void){\n"
            "    p = acme_find_port(dev);\n"
            "    p->x = 1;\n"
            "    return 0;\n"
            "}\n"
        )
        assert check_null_propagation(src, self._VOCAB).null_deref_found
        assert not check_null_propagation(src).null_deref_found

    def test_auth_predicate_extends_bypass_check(self):
        src = (
            "int k(void){\n"
            "    if (fast)\n"
            "        return 0;\n"
            "    if (!acme_may_write(req))\n"
            "        return -1;\n"
            "    return do_write(req);\n"
            "}\n"
        )
        r = check_auth_bypass(src, self._VOCAB)
        assert r.bypass_found
        assert r.bypassed_checks == ["domain:acme_may_write(req)"]
        assert not check_auth_bypass(src).bypass_found
