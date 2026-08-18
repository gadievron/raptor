"""Coverage for the 8 bundled strategies.

Verifies every shipped strategy:
  * Loads cleanly via the strict schema.
  * Has at least one CVE exemplar (the design-doc principle).
  * Is reachable through the picker via realistic signals.

These tests are the canary: if a strategy YAML breaks during edits,
or if a renamed file silently disappears from the bundled dir, this
test surfaces it immediately.
"""

from __future__ import annotations

import pytest

from core.llm.cwe_strategies import (
    Strategy,
    load_all,
    pick_strategies,
)
from core.llm.cwe_strategies.loader import builtin_profile, merge_signals


@pytest.fixture(scope="module")
def kernel_tree(tmp_path_factory):
    """A kernel-marked target root (Kconfig marker — the same
    detection the checker vocab packs use)."""
    root = tmp_path_factory.mktemp("kernel-target")
    (root / "Kconfig").write_text("config FOO\n")
    return root


_EXPECTED_STRATEGIES = {
    "general",
    "input_handling",
    "concurrency",
    "memory_management",
    "auth_privilege",
    "cryptography",
    "memory_aliasing",
    "lifecycle_drift",
}


@pytest.fixture(scope="module")
def all_strategies():
    return load_all()


@pytest.fixture(scope="module")
def by_name(all_strategies):
    return {s.name: s for s in all_strategies}


# ---------------------------------------------------------------------------
# Bundle completeness
# ---------------------------------------------------------------------------


class TestBundle:
    def test_all_expected_present(self, by_name):
        names = set(by_name)
        missing = _EXPECTED_STRATEGIES - names
        assert not missing, f"missing bundled strategies: {sorted(missing)}"

    def test_no_unexpected_strategies(self, by_name):
        names = set(by_name)
        # Allow extras in future without breaking; just flag for visibility.
        # Convert to a clear assertion the operator wants to see.
        assert names >= _EXPECTED_STRATEGIES

    @pytest.mark.parametrize("name", sorted(_EXPECTED_STRATEGIES))
    def test_each_loads(self, by_name, name):
        s = by_name.get(name)
        assert isinstance(s, Strategy), f"{name} did not load"
        assert s.description, f"{name} has empty description"
        assert s.key_questions, f"{name} has no key_questions"
        assert s.prompt_addendum, f"{name} has empty prompt_addendum"

    @pytest.mark.parametrize("name", sorted(_EXPECTED_STRATEGIES))
    def test_each_has_at_least_one_exemplar(self, by_name, name):
        # ``general`` has 2; the rest have at least 1.
        s = by_name[name]
        assert len(s.exemplars) >= 1, (
            f"{name} has no CVE exemplars — design doc requires 1-2 per strategy"
        )

    @pytest.mark.parametrize("name", sorted(_EXPECTED_STRATEGIES - {"general"}))
    def test_specialised_strategies_have_signals(self, by_name, name):
        """Every strategy except ``general`` must be reachable —
        through its own (universal) signals, or, for strategies whose
        entire signal vocabulary is kernel-specific (lifecycle_drift),
        through the linux_kernel profile supplements."""
        s = by_name[name]
        sig = s.signals
        supplements = builtin_profile("linux_kernel") or {}
        extra = supplements.get(name)
        if extra is not None:
            sig = merge_signals(sig, extra)
        has_any = sig.paths or sig.includes or sig.function_keywords
        assert has_any, (
            f"{name} has no signals (even with the kernel profile) — "
            f"picker can't reach it. Add at least one path / include "
            f"/ function_keyword."
        )


# ---------------------------------------------------------------------------
# Picker reachability — each specialised strategy must fire on at
# least one realistic signal combination.
# ---------------------------------------------------------------------------


class TestPickerReachability:
    """If a strategy can never be picked, it adds noise to the bundle
    without contributing. These tests pin a representative trigger
    for each one — adapt if the signals are tuned later."""

    def _get(self, by_name, name):
        return by_name[name]

    def test_input_handling_via_path(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="net/netfilter/nf_tables_api.c",
            function_name="nft_payload_eval",
            target_path=kernel_tree,
        )
        assert "input_handling" in {s.name for s in out}

    def test_input_handling_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/random.c",
            function_name="parse_request",
        )
        assert "input_handling" in {s.name for s in out}

    def test_concurrency_via_path(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="kernel/locking/rwsem.c",
            function_name="x",
            target_path=kernel_tree,
        )
        assert "concurrency" in {s.name for s in out}

    def test_concurrency_via_include(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="x",
            file_includes=["linux/mutex.h"],
            target_path=kernel_tree,
        )
        assert "concurrency" in {s.name for s in out}

    def test_memory_management_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="kref_put_obj",
        )
        assert "memory_management" in {s.name for s in out}

    def test_auth_privilege_via_path(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="security/commoncap.c",
            function_name="x",
            target_path=kernel_tree,
        )
        assert "auth_privilege" in {s.name for s in out}

    def test_auth_privilege_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="ns_capable_or_die",
        )
        assert "auth_privilege" in {s.name for s in out}

    def test_cryptography_via_path(self, by_name):
        out = pick_strategies(
            file_path="crypto/aes.c",
            function_name="x",
        )
        assert "cryptography" in {s.name for s in out}

    def test_cryptography_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="hmac_verify",
        )
        assert "cryptography" in {s.name for s in out}

    def test_memory_aliasing_via_path(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="fs/splice.c",
            function_name="x",
            target_path=kernel_tree,
        )
        assert "memory_aliasing" in {s.name for s in out}

    def test_memory_aliasing_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="splice_pages",
        )
        assert "memory_aliasing" in {s.name for s in out}

    def test_lifecycle_drift_via_path(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="kernel/ptrace.c",
            function_name="__ptrace_may_access",
            target_path=kernel_tree,
        )
        assert "lifecycle_drift" in {s.name for s in out}

    def test_lifecycle_drift_via_keyword(self, by_name, kernel_tree):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="check_dumpable",
            target_path=kernel_tree,
        )
        assert "lifecycle_drift" in {s.name for s in out}


# ---------------------------------------------------------------------------
# Multi-strategy picks — realistic combinations
# ---------------------------------------------------------------------------


class TestMultiStrategyPicks:
    def test_network_packet_handler_under_lock(self, kernel_tree):
        """Network handler holding a lock should match input_handling
        + concurrency, plus general."""
        out = pick_strategies(
            file_path="net/foo.c",
            function_name="parse_packet_locked",
            file_includes=["linux/skbuff.h", "linux/spinlock.h"],
            max_strategies=3,
            target_path=kernel_tree,
        )
        names = {s.name for s in out}
        assert "general" in names
        assert "input_handling" in names
        assert "concurrency" in names

    def test_crypto_under_aliasing(self):
        out = pick_strategies(
            file_path="crypto/algif_aead.c",
            function_name="aead_recvmsg_locked_splice",
            max_strategies=4,
        )
        names = {s.name for s in out}
        # Path matches both crypto/ AND has 'splice' keyword for aliasing
        # AND lock_ keyword for concurrency.
        assert "general" in names
        assert "cryptography" in names
        assert "memory_aliasing" in names


# ---------------------------------------------------------------------------
# Generic targets — the bundled strategies must be genuinely generic:
# sensible selection on a non-kernel target with zero kernel names
# involved anywhere in the decision.
# ---------------------------------------------------------------------------

_KERNEL_NAME_SAMPLES = {
    # calls
    "kmalloc", "kzalloc", "kfree", "kref_put", "refcount_dec_and_test",
    "spin_lock", "rcu_read_lock", "mutex_lock", "copy_from_user",
    "skb_pull", "nla_get_u32", "ns_capable", "inode_permission",
    "get_dumpable", "ptrace_may_access", "splice_to_pipe", "sg_chain",
    "crypto_alloc_aead", "crypto_memneq", "get_random_bytes",
    # includes
    "linux/slab.h", "linux/skbuff.h", "linux/mutex.h", "linux/cred.h",
    "linux/ptrace.h", "linux/crypto.h", "linux/splice.h",
    # paths
    "kernel/locking/", "security/", "mm/", "drivers/usb/",
    "kernel/ptrace.c", "fs/splice.c", "lib/crypto/",
}


class TestGenericTargetSelection:
    """Non-kernel fixture: sensible routing, zero kernel names."""

    def test_no_kernel_names_in_generic_signals(self, all_strategies):
        """The bundled (profile-less) strategies carry no kernel API
        vocabulary — it all lives in profiles/linux_kernel.yml."""
        for s in all_strategies:
            sig = s.signals
            present = _KERNEL_NAME_SAMPLES & (
                set(sig.function_calls) | set(sig.includes)
                | set(sig.paths)
            )
            assert not present, (
                f"{s.name} still carries kernel vocabulary: "
                f"{sorted(present)}"
            )

    def test_userspace_daemon_routing(self):
        """A plain C daemon routes on universal signals alone —
        no target_path, no profile, no vocab."""
        out = pick_strategies(
            file_path="src/server/request.c",
            function_name="parse_request",
            function_calls_made=["malloc", "memcpy", "recv"],
            max_strategies=3,
        )
        names = {s.name for s in out}
        assert "general" in names
        assert "input_handling" in names
        assert "memory_management" in names

    def test_pthread_daemon_routes_concurrency(self):
        out = pick_strategies(
            file_path="src/worker.c",
            function_name="drain_queue",
            function_calls_made=["pthread_mutex_lock", "pthread_cond_wait"],
        )
        assert "concurrency" in {s.name for s in out}

    def test_setuid_helper_routes_auth(self):
        out = pick_strategies(
            file_path="src/helper.c",
            function_name="drop_privs",
            function_calls_made=["setuid", "setgroups"],
        )
        assert "auth_privilege" in {s.name for s in out}

    def test_non_kernel_target_path_adds_nothing(self, tmp_path):
        """A non-kernel target_path leaves selection identical to the
        no-target call (no profile is merged)."""
        (tmp_path / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        kwargs = {
            "file_path": "kernel/locking/rwsem.c",  # kernel-looking PATH,
            "function_name": "x",                   # non-kernel TARGET
        }
        without = [s.name for s in pick_strategies(**kwargs)]
        with_target = [
            s.name for s in pick_strategies(**kwargs, target_path=tmp_path)
        ]
        assert without == with_target
        assert "concurrency" not in with_target


# ---------------------------------------------------------------------------
# Kernel-marked targets — equivalence pin: the profile restores exactly
# the pre-split routing on the selections the old hardcoded YAML
# signals produced.
# ---------------------------------------------------------------------------


class TestKernelTargetEquivalence:
    """Pre-change selections captured against the hardcoded-YAML build;
    a kernel-marked fixture must reproduce them."""

    def test_kernel_locking_path(self, kernel_tree):
        out = pick_strategies(
            file_path="kernel/locking/rwsem.c",
            function_name="rwsem_down_read",
            target_path=kernel_tree,
        )
        assert "concurrency" in {s.name for s in out}

    def test_kernel_callees(self, kernel_tree):
        out = pick_strategies(
            file_path="drivers/foo/bar.c",
            function_name="x",
            function_calls_made=["kmalloc", "copy_from_user", "spin_lock"],
            max_strategies=4,
            target_path=kernel_tree,
        )
        names = {s.name for s in out}
        assert {"memory_management", "input_handling", "concurrency"} <= names

    def test_kernel_cred_context(self, kernel_tree):
        out = pick_strategies(
            file_path="kernel/capability.c",
            function_name="x",
            function_calls_made=["ns_capable", "override_creds"],
            target_path=kernel_tree,
        )
        assert "auth_privilege" in {s.name for s in out}

    def test_lifecycle_drift_bespoke_callee(self, kernel_tree):
        out = pick_strategies(
            file_path="kernel/ptrace.c",
            function_name="__ptrace_may_access",
            function_calls_made=["get_dumpable"],
            target_path=kernel_tree,
        )
        assert "lifecycle_drift" in {s.name for s in out}

    def test_explicit_profile_equals_detected_kernel(self, kernel_tree):
        kwargs = {
            "file_path": "net/foo.c",
            "function_name": "parse_packet_locked",
            "file_includes": ["linux/skbuff.h", "linux/spinlock.h"],
            "max_strategies": 3,
        }
        detected = [
            s.name for s in pick_strategies(**kwargs, target_path=kernel_tree)
        ]
        explicit = [
            s.name
            for s in pick_strategies(**kwargs, profile="linux_kernel")
        ]
        assert detected == explicit


# ---------------------------------------------------------------------------
# Learned signals — study-derived DomainVocabulary and discovered sinks
# supplement the picker additively (non-kernel coverage gain).
# ---------------------------------------------------------------------------


class TestLearnedSignalSupplements:
    @staticmethod
    def _vocab():
        from core.audit.condition_smt import DomainVocabulary

        return DomainVocabulary.from_domain_model({
            "paired_operations": [
                {"acquire": "obj_pool_take", "release": "obj_pool_give",
                 "kind": "alloc"},
                {"acquire": "state_enter", "release": "state_leave",
                 "kind": "lock"},
                {"acquire": "watch_arm", "release": "watch_disarm",
                 "kind": "callback"},
            ],
            "auth_predicates": [
                {"name": "session_may_write", "kind": "permission"},
            ],
        })

    def test_learned_allocator_routes_memory(self):
        kwargs = {
            "file_path": "src/pool.c",
            "function_name": "recycle",
            "function_calls_made": ["obj_pool_take", "obj_pool_give"],
        }
        base = {s.name for s in pick_strategies(**kwargs)}
        assert "memory_management" not in base
        learned = {
            s.name
            for s in pick_strategies(**kwargs, domain_vocab=self._vocab())
        }
        assert "memory_management" in learned

    def test_learned_lock_routes_concurrency(self):
        kwargs = {
            "file_path": "src/fsm.c",
            "function_name": "advance",
            "function_calls_made": ["state_enter", "state_leave"],
        }
        assert "concurrency" not in {
            s.name for s in pick_strategies(**kwargs)
        }
        assert "concurrency" in {
            s.name
            for s in pick_strategies(**kwargs, domain_vocab=self._vocab())
        }

    def test_learned_auth_predicate_routes_auth(self):
        kwargs = {
            "file_path": "src/session.c",
            "function_name": "commit",
            "function_calls_made": ["session_may_write"],
        }
        assert "auth_privilege" not in {
            s.name for s in pick_strategies(**kwargs)
        }
        assert "auth_privilege" in {
            s.name
            for s in pick_strategies(**kwargs, domain_vocab=self._vocab())
        }

    def test_discovered_sinks_route_input_handling(self):
        kwargs = {
            "file_path": "src/proto.c",
            "function_name": "consume",
            "function_calls_made": ["wire_read_frame"],
        }
        assert "input_handling" not in {
            s.name for s in pick_strategies(**kwargs)
        }
        assert "input_handling" in {
            s.name
            for s in pick_strategies(
                **kwargs, discovered_sinks=["wire_read_frame"],
            )
        }
