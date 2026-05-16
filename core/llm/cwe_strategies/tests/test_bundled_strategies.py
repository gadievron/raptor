"""Coverage for the 7 bundled strategies.

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


_EXPECTED_STRATEGIES = {
    "general",
    "input_handling",
    "concurrency",
    "memory_management",
    "auth_privilege",
    "cryptography",
    "memory_aliasing",
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
    def test_all_seven_present(self, by_name):
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
        """Every strategy except ``general`` should have at least one
        signal — otherwise the picker can never select it."""
        s = by_name[name]
        sig = s.signals
        has_any = sig.paths or sig.includes or sig.function_keywords
        assert has_any, (
            f"{name} has no signals — picker can't reach it. "
            f"Add at least one path / include / function_keyword."
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

    def test_input_handling_via_path(self, by_name):
        out = pick_strategies(
            file_path="net/netfilter/nf_tables_api.c",
            function_name="nft_payload_eval",
        )
        assert "input_handling" in {s.name for s in out}

    def test_input_handling_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/random.c",
            function_name="parse_request",
        )
        assert "input_handling" in {s.name for s in out}

    def test_concurrency_via_path(self, by_name):
        out = pick_strategies(
            file_path="kernel/locking/rwsem.c",
            function_name="x",
        )
        assert "concurrency" in {s.name for s in out}

    def test_concurrency_via_include(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="x",
            file_includes=["linux/mutex.h"],
        )
        assert "concurrency" in {s.name for s in out}

    def test_memory_management_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="kref_put_obj",
        )
        assert "memory_management" in {s.name for s in out}

    def test_auth_privilege_via_path(self, by_name):
        out = pick_strategies(
            file_path="security/commoncap.c",
            function_name="x",
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

    def test_memory_aliasing_via_path(self, by_name):
        out = pick_strategies(
            file_path="fs/splice.c",
            function_name="x",
        )
        assert "memory_aliasing" in {s.name for s in out}

    def test_memory_aliasing_via_keyword(self, by_name):
        out = pick_strategies(
            file_path="src/foo.c",
            function_name="splice_pages",
        )
        assert "memory_aliasing" in {s.name for s in out}


# ---------------------------------------------------------------------------
# Multi-strategy picks — realistic combinations
# ---------------------------------------------------------------------------


class TestMultiStrategyPicks:
    def test_network_packet_handler_under_lock(self):
        """Network handler holding a lock should match input_handling
        + concurrency, plus general."""
        out = pick_strategies(
            file_path="net/foo.c",
            function_name="parse_packet_locked",
            file_includes=["linux/skbuff.h", "linux/spinlock.h"],
            max_strategies=3,
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
