"""Tests for /audit review pipeline features.

Covers: wrapper prefilter, verification tiers, confidence propagation,
spec inference (assertions + preconditions), convergence dispatch,
concurrency hypothesis mapping, learning loop.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

# ── Feature 1: Wrapper auto-clean ─────────────────────────────────

class TestWrapperAutoClean:

    def test_trivial_c_wrapper_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
int setkey(struct crypto_aead *aead, const u8 *key, unsigned int keylen) {
    return crypto_aead_setkey(aead, key, keylen);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="wrapper.c",
            function_name="setkey",
            source=source,
            line_start=1,
        )
        assert result.skip_llm
        assert result.skip_reason

    def test_wrapper_with_cast_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
int process(void *data, int len) {
    return handle_data((char *)data, len);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="cast.c",
            function_name="process",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_wrapper_with_array_indexing_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
int get_val(int *arr, int idx) {
    return arr[idx];
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="index.c",
            function_name="get_val",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_wrapper_with_assertion_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
void cleanup(struct obj *o) {
    BUG_ON(!o);
    kfree(o);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="assert.c",
            function_name="cleanup",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_multistatement_not_wrapper(self):
        from core.audit.prefilter import run_prefilter
        source = """\
int do_work(int x) {
    int result = compute(x);
    log_result(result);
    return result;
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="multi.c",
            function_name="do_work",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_wrapper_python_delegate(self):
        from core.audit.prefilter import run_prefilter
        source = """\
def get_config(key):
    return lookup_config(key)
"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="wrap.py",
            function_name="get_config",
            source=source,
            line_start=1,
        )
        assert result.skip_llm
        assert "trivial wrapper" in result.skip_reason

    def test_crypto_wrapper_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
void hash_input(char *buf, int len) {
    sha256(buf, len, out);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="crypto.c",
            function_name="hash_input",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_dangerous_api_wrapper_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
void copy_data(char *dst, char *src, int len) {
    return memcpy(dst, src, len);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="copy.c",
            function_name="copy_data",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_guard_then_delegate_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
int check_range(int n) {
    if (n > MAX) return -1;
    return process(n);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="guard.c",
            function_name="check_range",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_variable_pointer_offset_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
int probe(struct device *dev, int reg) {
    return read_register(dev->mmio + reg);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="probe.c",
            function_name="probe",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm

    def test_kernel_malloc_wrapper_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
void *alloc_obj(size_t n) {
    return kmalloc(n, GFP_KERNEL);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="alloc.c",
            function_name="alloc_obj",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm


# ── Multi-language prefilter patterns ─────────────────────────────

class TestMultiLanguagePrefilter:

    def test_php_eval_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function process($input) {
    $result = eval($input);
    return $result;
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="handler.php",
            function_name="process",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "php-eval-variable" for h in result.hits)

    def test_php_accessor_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function getName() {
    return $this->name;
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="model.php",
            function_name="getName",
            source=source,
            line_start=1,
        )
        assert result.skip_llm

    def test_java_runtime_exec_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
public void runCommand(String cmd) {
    Process p = Runtime.getRuntime().exec(cmd);
    p.waitFor();
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="Runner.java",
            function_name="runCommand",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "java-runtime-exec" for h in result.hits)

    def test_java_accessor_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
public int getId() {
    return this.id;
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="Entity.java",
            function_name="getId",
            source=source,
            line_start=1,
        )
        assert result.skip_llm

    def test_js_eval_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function compute(expr) {
    return eval(expr);
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="calc.js",
            function_name="compute",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "js-eval" for h in result.hits)

    def test_ts_dom_xss_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function render(html: string): void {
    document.getElementById('out').innerHTML = html;
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="render.ts",
            function_name="render",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "js-xss-dom" for h in result.hits)

    def test_lua_loadstring_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function run_code(code)
    local fn = loadstring(code)
    return fn()
end"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="sandbox.lua",
            function_name="run_code",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "lua-loadstring" for h in result.hits)

    def test_perl_system_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
sub run_cmd {
    my ($cmd) = @_;
    system("$cmd");
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="util.pl",
            function_name="run_cmd",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "perl-command-exec" for h in result.hits)

    def test_perl_accessor_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
sub name {
    return $self->{name};
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="Obj.pm",
            function_name="name",
            source=source,
            line_start=1,
        )
        assert result.skip_llm

    def test_js_accessor_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
getCount() {
    return this.count;
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="counter.js",
            function_name="getCount",
            source=source,
            line_start=1,
        )
        assert result.skip_llm

    def test_lua_accessor_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function get_value(self)
    return self.value
end"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="obj.lua",
            function_name="get_value",
            source=source,
            line_start=1,
        )
        assert result.skip_llm

    def test_php_unserialize_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
function load_data($raw) {
    $data = unserialize($raw);
    return $data['key'];
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="loader.php",
            function_name="load_data",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "php-unserialize" for h in result.hits)

    def test_java_deserialization_detected(self):
        from core.audit.prefilter import run_prefilter
        source = """\
public Object deserialize(InputStream in) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(in);
    return ois.readObject();
}"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="Deserialize.java",
            function_name="deserialize",
            source=source,
            line_start=1,
        )
        assert not result.skip_llm
        assert any(h.rule_id == "java-deserialization" for h in result.hits)


# ── Feature 2: Verification tiers ─────────────────────────────────

class TestVerificationTiers:

    def test_enum_values(self):
        from core.audit.pipeline import VerificationTier
        assert VerificationTier.CONFIRMED.value == "confirmed"
        assert VerificationTier.TOOL_BACKED.value == "tool_backed"
        assert VerificationTier.LLM_ONLY.value == "llm_only"
        assert VerificationTier.SPECULATIVE.value == "speculative"

    def test_severity_caps(self):
        from core.audit.pipeline import VerificationTier
        assert VerificationTier.CONFIRMED.max_severity == "critical"
        assert VerificationTier.TOOL_BACKED.max_severity == "high"
        assert VerificationTier.LLM_ONLY.max_severity == "medium"
        assert VerificationTier.SPECULATIVE.max_severity == "low"

    def test_tier_tool_backed(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="overflow", evidence_tool="semgrep:overflow",
            tools_dispatched={"semgrep"},
        )
        assert o.compute_tier() == "tool_backed"

    def test_tier_no_evidence(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="suspicious",
            body="maybe", evidence_tool="",
        )
        assert o.compute_tier() == "speculative"

    def test_tier_clean_is_speculative(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="clean",
            body="safe", evidence_tool="semgrep:check",
        )
        assert o.compute_tier() == "speculative"

    def test_tier_llm_only(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="vuln", evidence_tool="llm_analysis",
            tools_dispatched={"semgrep"},
        )
        assert o.compute_tier() == "llm_only"


# ── Feature 3: Confidence propagation ─────────────────────────────

@dataclass
class _MockOutcome:
    file: str
    function: str
    status: str
    verification_tier: str = "speculative"
    hypotheses: list[dict[str, Any]] | None = None


class TestConfidencePropagation:

    def test_all_callers_clean_demotes(self):
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller1", "clean", "tool_backed"),
            _MockOutcome("a.c", "caller2", "clean", "confirmed"),
            _MockOutcome("b.c", "target", "suspicious", hypotheses=[
                {"mechanism": "if the caller passes invalid length",
                 "confidence": "medium", "counter": "trusts its caller"},
            ]),
        ]
        edge_index = {
            "a.c:caller1": [{"caller_file": "a.c", "caller": "caller1",
                             "callee_file": "b.c", "callee": "target"}],
            "a.c:caller2": [{"caller_file": "a.c", "caller": "caller2",
                             "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller1",
                            "callee_file": "b.c", "callee": "target"},
                           {"caller_file": "a.c", "caller": "caller2",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 1
        assert demotions[0].file == "b.c"
        assert demotions[0].function == "target"

    def test_demotion_log_entry_carries_source_functions(self):
        """The audit-log record must carry the full evidentiary basis
        for the verdict flip, not just the (truncated) prose reason."""
        from core.audit.orchestrator import _demotion_log_entry
        from core.audit.propagation import ConfidenceDemotion

        d = ConfidenceDemotion(
            file="b.c",
            function="target",
            reason="all 7 callers verified clean: c1, c2, c3, c4, c5",
            source_functions=["c1", "c2", "c3", "c4", "c5", "c6", "c7"],
        )
        entry = _demotion_log_entry(d)
        assert entry["action"] == "sweep_promotion"
        assert entry["key"] == "b.c:target:0"
        assert entry["evidence_tool"] == "confidence_propagation"
        assert entry["hypothesis"] == d.reason
        assert entry["source_functions"] == [
            "c1", "c2", "c3", "c4", "c5", "c6", "c7",
        ]

    def test_one_caller_not_clean_keeps(self):
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller1", "clean", "tool_backed"),
            _MockOutcome("a.c", "caller2", "suspicious"),
            _MockOutcome("b.c", "target", "suspicious", hypotheses=[
                {"mechanism": "caller could provide null",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "a.c:caller1": [{"caller_file": "a.c", "caller": "caller1",
                             "callee_file": "b.c", "callee": "target"}],
            "a.c:caller2": [{"caller_file": "a.c", "caller": "caller2",
                             "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller1",
                            "callee_file": "b.c", "callee": "target"},
                           {"caller_file": "a.c", "caller": "caller2",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0

    def test_no_propagation_from_llm_only(self):
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller1", "clean", "llm_only"),
            _MockOutcome("b.c", "target", "suspicious", hypotheses=[
                {"mechanism": "caller passes tainted data",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "a.c:caller1": [{"caller_file": "a.c", "caller": "caller1",
                             "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller1",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0

    def test_no_transitive_demotion(self):
        """Propagation-demoted outcomes must not seed further demotions.

        root and root2 are confirmed clean callers of fn0 (meeting min_callers=2).
        fn0 gets demoted, but it must NOT seed demotion of fn1 (only 1 caller: fn0).
        Even with min_callers=1 fn1 should not demote because fn0 was only
        propagation-demoted, not tool-confirmed.
        """
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "root", "clean", "confirmed"),
            _MockOutcome("a.c", "root2", "clean", "tool_backed"),
            _MockOutcome("a.c", "fn0", "suspicious", hypotheses=[
                {"mechanism": "caller provides bad data",
                 "confidence": "medium", "counter": ""},
            ]),
            _MockOutcome("a.c", "fn1", "suspicious", hypotheses=[
                {"mechanism": "caller provides bad data",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "a.c:root": [{"caller_file": "a.c", "caller": "root",
                          "callee_file": "a.c", "callee": "fn0"}],
            "a.c:root2": [{"caller_file": "a.c", "caller": "root2",
                           "callee_file": "a.c", "callee": "fn0"}],
            "a.c:fn0": [{"caller_file": "a.c", "caller": "root",
                         "callee_file": "a.c", "callee": "fn0"},
                        {"caller_file": "a.c", "caller": "root2",
                         "callee_file": "a.c", "callee": "fn0"},
                        {"caller_file": "a.c", "caller": "fn0",
                         "callee_file": "a.c", "callee": "fn1"}],
            "a.c:fn1": [{"caller_file": "a.c", "caller": "fn0",
                         "callee_file": "a.c", "callee": "fn1"}],
        }
        demotions = propagate_confidence(
            outcomes, edge_index, max_iterations=5, min_callers=1,
        )
        assert len(demotions) == 1
        assert demotions[0].function == "fn0"

    def test_vacuous_callee_not_demoted(self):
        """Callee not in edge index must not cause vacuous demotion."""
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "func", "suspicious", hypotheses=[
                {"mechanism": "callee malloc returns NULL",
                 "confidence": "medium",
                 "counter": "malloc could fail"},
            ]),
        ]
        edge_index = {
            "a.c:func": [{"caller_file": "a.c", "caller": "func",
                          "callee_file": "libc.so", "callee": "free"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0

    def test_no_hypotheses_no_demotion(self):
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller", "clean", "confirmed"),
            _MockOutcome("b.c", "target", "suspicious", hypotheses=[]),
        ]
        edge_index = {
            "a.c:caller": [{"caller_file": "a.c", "caller": "caller",
                            "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0


# ── Feature 4: Coccinelle concurrency rules ───────────────────────

class TestConcurrencyHypothesisMapping:

    def test_lock_scope_routes(self):
        from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
        result = hypothesis_to_cocci_check("lock scope gap after spinlock release")
        assert result is not None
        assert "lock_scope_gap" in result

    def test_deadlock_routes(self):
        from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
        result = hypothesis_to_cocci_check("ABBA deadlock between mutex A and B")
        assert result is not None
        assert "lock_order_violation" in result

    def test_memory_barrier_routes(self):
        from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
        result = hypothesis_to_cocci_check("missing memory barrier smp_wmb")
        assert result is not None
        assert "missing_memory_barrier" in result

    def test_atomic_race_routes(self):
        from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
        result = hypothesis_to_cocci_check("atomic_read race condition in refcount")
        assert result is not None
        assert "atomic_check_then_act" in result

    def test_cwe_362_covered_when_coccinelle_ran(self):
        from core.audit.tool_coverage import is_class_covered
        assert is_class_covered(
            "CWE-362", "race condition", "",
            {"coccinelle": True},
            ran_tools={"coccinelle"},
        )

    def test_cwe_362_not_covered_when_coccinelle_never_ran(self):
        """Installed-but-never-dispatched is NOT coverage."""
        from core.audit.tool_coverage import is_class_covered
        assert not is_class_covered(
            "CWE-362", "race condition", "",
            {"coccinelle": True},
        )

    def test_cwe_667_covered_when_coccinelle_ran(self):
        from core.audit.tool_coverage import is_class_covered
        assert is_class_covered(
            "CWE-667", "improper locking", "",
            {"coccinelle": True},
            ran_tools={"coccinelle"},
        )

    def test_toctou_routes_to_double_fetch_first(self):
        from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
        result = hypothesis_to_cocci_check(
            "TOCTOU vulnerability via double copy_from_user"
        )
        assert result is not None
        assert "double_fetch" in result

    def test_generic_toctou_routes_to_new_rule(self):
        from core.audit.hypothesis_mapping import hypothesis_to_cocci_check
        result = hypothesis_to_cocci_check(
            "time-of-check time-of-use in permission check"
        )
        assert result is not None
        assert "toctou" in result


# ── Feature 5: Spec inference ─────────────────────────────────────

class TestAssertionExtraction:

    def test_bug_on_extracts_invariant(self):
        from core.audit.spec_inference import infer_spec_mechanical
        gap = {
            "name": "remove_waiter",
            "file": "kernel/lock.c",
            "source": "void remove_waiter(struct waiter *w) {\n"
                       "    BUG_ON(!list_empty(&w->list));\n"
                       "    kfree(w);\n"
                       "}\n",
            "line_start": 10,
        }
        spec = infer_spec_mechanical(gap)
        assert any("list_empty" in inv for inv in spec.invariants)
        assert any(s.signal == "assertion_macro" for s in spec.sources)

    def test_lockdep_extracts_precondition(self):
        from core.audit.spec_inference import infer_spec_mechanical
        gap = {
            "name": "do_op",
            "file": "core/ops.c",
            "source": "void do_op(struct obj *o) {\n"
                       "    lockdep_assert_held(&o->lock);\n"
                       "    o->state++;\n"
                       "}\n",
            "line_start": 1,
        }
        spec = infer_spec_mechanical(gap)
        assert any("lock" in p and "held" in p for p in spec.preconditions)

    def test_assert_extracts_precondition(self):
        from core.audit.spec_inference import infer_spec_mechanical
        gap = {
            "name": "divide",
            "file": "math.c",
            "source": "int divide(int a, int b) {\n"
                       "    assert(b != 0);\n"
                       "    return a / b;\n"
                       "}\n",
            "line_start": 1,
        }
        spec = infer_spec_mechanical(gap)
        assert any("b != 0" in p for p in spec.preconditions)


class TestPreconditionVerification:

    def test_universally_satisfied(self):
        from core.audit.spec_inference import (
            InferredSpec,
            verify_preconditions_at_call_sites,
        )
        spec = InferredSpec(
            function="process",
            file="f.c",
            preconditions=["ptr != NULL"],
        )
        callers = [
            {"file": "a.c", "name": "caller1",
             "source": "if (ptr == NULL) return; process(ptr);"},
            {"file": "a.c", "name": "caller2",
             "source": "if (!ptr) return -1; process(ptr);"},
        ]
        results = verify_preconditions_at_call_sites(spec, callers)
        assert len(results) == 1
        assert results[0].is_universally_satisfied
        assert results[0].verified_sites == 2

    def test_not_universal_when_one_violates(self):
        from core.audit.spec_inference import (
            InferredSpec,
            verify_preconditions_at_call_sites,
        )
        spec = InferredSpec(
            function="process",
            file="f.c",
            preconditions=["ptr != NULL"],
        )
        callers = [
            {"file": "a.c", "name": "caller1",
             "source": "if (ptr == NULL) return; process(ptr);"},
            {"file": "a.c", "name": "caller2",
             "source": "process(ptr);"},
        ]
        results = verify_preconditions_at_call_sites(spec, callers)
        assert len(results) == 1
        assert not results[0].is_universally_satisfied

    def test_format_verification_context(self):
        from core.audit.spec_inference import (
            PreconditionVerification,
            format_precondition_verification,
        )
        v = PreconditionVerification(
            precondition="ptr != NULL",
            total_call_sites=3,
            verified_sites=3,
            violated_sites=0,
            unknown_sites=0,
            is_universally_satisfied=True,
        )
        text = format_precondition_verification([v])
        assert "UNIVERSALLY SATISFIED" in text
        assert "mechanically refuted" in text

    def test_format_verification_splits_violated_and_unknown(self):
        """'2/5 verified' is ambiguous — 3 violated is a live lead,
        3 unknown is benign. The split must be rendered."""
        from core.audit.spec_inference import (
            PreconditionVerification,
            format_precondition_verification,
        )
        v = PreconditionVerification(
            precondition="len <= BUF_SIZE",
            total_call_sites=5,
            verified_sites=2,
            violated_sites=2,
            unknown_sites=1,
            is_universally_satisfied=False,
        )
        text = format_precondition_verification([v])
        assert "2/5 callers verified" in text
        assert "(2 violated, 1 unknown)" in text
        assert "chase the violating call site(s)" in text

    def test_format_verification_no_violations_no_callout(self):
        from core.audit.spec_inference import (
            PreconditionVerification,
            format_precondition_verification,
        )
        v = PreconditionVerification(
            precondition="ptr != NULL",
            total_call_sites=4,
            verified_sites=1,
            violated_sites=0,
            unknown_sites=3,
            is_universally_satisfied=False,
        )
        text = format_precondition_verification([v])
        assert "(0 violated, 3 unknown)" in text
        assert "chase the violating" not in text


# ── Feature 6: Convergence loop ───────────────────────────────────

class TestConvergenceDispatch:

    def test_dispatch_smt_suggestion(self):
        from core.audit.refinement import dispatch_suggestion

        @dataclass
        class MockOutcome:
            file: str = "f.c"
            function: str = "fn"
            status: str = "suspicious"
            hypothesis: str = "integer overflow in allocation"

        @dataclass
        class MockConfig:
            target_path: Path = Path("/tmp")

        results = dispatch_suggestion(
            "run SMT check-overflow on the malloc size",
            MockOutcome(),
            {"file": "f.c", "function": "fn", "source": "int x = malloc(n * sizeof(int));"},
            MockConfig(),
        )
        # May or may not produce results depending on tool availability;
        # the important thing is it doesn't crash
        assert isinstance(results, list)

    def test_empty_suggestion_returns_empty(self):
        from core.audit.refinement import dispatch_suggestion
        results = dispatch_suggestion("", None, {}, None)
        assert results == []


# ── Fix 5c-1: Minimum-caller gate ───────────────────────────────

class TestMinimumCallerGate:

    def test_single_caller_not_enough(self):
        """With min_callers=2 (default), a single clean caller does not demote."""
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller1", "clean", "tool_backed"),
            _MockOutcome("b.c", "target", "suspicious", hypotheses=[
                {"mechanism": "caller passes invalid length",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "a.c:caller1": [{"caller_file": "a.c", "caller": "caller1",
                             "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller1",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0

    def test_min_callers_one_allows_single(self):
        """Explicitly setting min_callers=1 allows single-caller demotion."""
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller1", "clean", "tool_backed"),
            _MockOutcome("b.c", "target", "suspicious", hypotheses=[
                {"mechanism": "caller passes invalid length",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "a.c:caller1": [{"caller_file": "a.c", "caller": "caller1",
                             "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller1",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index, min_callers=1)
        assert len(demotions) == 1


# ── Fix 5c-2: Callee-direction propagation ──────────────────────

class TestCalleeDirectionPropagation:

    def test_callee_clean_demotes(self):
        """When a hypothesis names a callee and that callee is confirmed clean, demote."""
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("lib.c", "helper", "clean", "tool_backed"),
            _MockOutcome("main.c", "process", "suspicious", hypotheses=[
                {"mechanism": "helper() could return negative value",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "main.c:process": [{"caller_file": "main.c", "caller": "process",
                                "callee_file": "lib.c", "callee": "helper"}],
            "lib.c:helper": [{"caller_file": "main.c", "caller": "process",
                              "callee_file": "lib.c", "callee": "helper"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 1
        assert demotions[0].function == "process"

    def test_callee_not_clean_keeps(self):
        """When a hypothesis names a callee that is suspicious, no demotion."""
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("lib.c", "helper", "suspicious"),
            _MockOutcome("main.c", "process", "suspicious", hypotheses=[
                {"mechanism": "helper() could return negative value",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "main.c:process": [{"caller_file": "main.c", "caller": "process",
                                "callee_file": "lib.c", "callee": "helper"}],
            "lib.c:helper": [{"caller_file": "main.c", "caller": "process",
                              "callee_file": "lib.c", "callee": "helper"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0


# ── Fix 5c-3: Finding immune to propagation ─────────────────────

class TestFindingImmunity:

    def test_finding_not_demoted_by_propagation(self):
        """Propagation only targets suspicious outcomes, never findings."""
        from core.audit.propagation import propagate_confidence

        outcomes = [
            _MockOutcome("a.c", "caller1", "clean", "tool_backed"),
            _MockOutcome("a.c", "caller2", "clean", "confirmed"),
            _MockOutcome("b.c", "target", "finding", hypotheses=[
                {"mechanism": "caller passes invalid length",
                 "confidence": "medium", "counter": ""},
            ]),
        ]
        edge_index = {
            "a.c:caller1": [{"caller_file": "a.c", "caller": "caller1",
                             "callee_file": "b.c", "callee": "target"}],
            "a.c:caller2": [{"caller_file": "a.c", "caller": "caller2",
                             "callee_file": "b.c", "callee": "target"}],
            "b.c:target": [{"caller_file": "a.c", "caller": "caller1",
                            "callee_file": "b.c", "callee": "target"},
                           {"caller_file": "a.c", "caller": "caller2",
                            "callee_file": "b.c", "callee": "target"}],
        }
        demotions = propagate_confidence(outcomes, edge_index)
        assert len(demotions) == 0


# ── Fix 5c-4: CONFIRMED tier ────────────────────────────────────

class TestConfirmedTier:

    def test_dark_verify_confirmed(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="overflow", evidence_tool="dark_verify:confirmed",
            tools_dispatched={"smt"},
        )
        assert o.compute_tier() == "confirmed"

    def test_dynamic_crash(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="crash", evidence_tool="dynamic:crash",
        )
        assert o.compute_tier() == "confirmed"

    def test_frida_runtime(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="runtime", evidence_tool="frida:runtime",
        )
        assert o.compute_tier() == "confirmed"

    def test_smt_still_tool_backed(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="overflow", evidence_tool="smt:check-overflow",
            tools_dispatched={"smt"},
        )
        assert o.compute_tier() == "tool_backed"

    def test_smt_witness_is_confirmed(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="overflow", evidence_tool="insufficient_guard_smt:witness",
            tools_dispatched={"smt"},
        )
        assert o.compute_tier() == "confirmed"

    def test_smt_witness_in_compound_evidence(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="overflow",
            evidence_tool="semgrep:rule1+signed_mismatch_smt:witness",
            tools_dispatched={"smt", "semgrep"},
        )
        assert o.compute_tier() == "confirmed"

    def test_smt_no_witness_not_confirmed(self):
        from core.audit.orchestrator import ReviewOutcome
        o = ReviewOutcome(
            file="f.c", function="fn", status="finding",
            body="dead path", evidence_tool="dead_path_smt",
            tools_dispatched={"dead_path_smt"},
        )
        assert o.compute_tier() == "tool_backed"


# ── Fix 5c-5: Contract-delegation co-occurrence ─────────────────

class TestContractDelegationCooccurrence:

    def test_caller_specific_phrase_blocks(self):
        from core.audit.llm_review import _counter_hypothesis_is_compelling
        counter = (
            "This is a buffer overflow but the caller's responsibility "
            "is to validate the length before calling this function."
        )
        assert not _counter_hypothesis_is_compelling(counter)

    def test_subject_agnostic_without_caller_ref_is_compelling(self):
        """'fails to validate' without caller reference should NOT suppress."""
        from core.audit.llm_review import _counter_hypothesis_is_compelling
        counter = (
            "The function fails to validate the buffer length, leading "
            "to a heap overflow when processing untrusted input data."
        )
        assert _counter_hypothesis_is_compelling(counter)

    def test_subject_agnostic_with_caller_ref_blocks(self):
        """'fails to validate' with 'caller' should suppress (delegation)."""
        from core.audit.llm_review import _counter_hypothesis_is_compelling
        counter = (
            "If the caller fails to validate the buffer length, this "
            "could lead to an overflow, but that is the caller's bug."
        )
        assert not _counter_hypothesis_is_compelling(counter)


# ── Fix 5c-6: IRIS sink wrapper rejection ────────────────────────

class TestIrisSinkWrapperRejection:

    def test_wrapper_to_iris_sink_not_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
def send_query(q):
    return execute_sql(q)
"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="db.py",
            function_name="send_query",
            source=source,
            line_start=1,
            project_sinks=frozenset({"execute_sql"}),
        )
        assert not result.skip_llm

    def test_wrapper_to_non_sink_still_skipped(self):
        from core.audit.prefilter import run_prefilter
        source = """\
def get_name(obj):
    return fetch_name(obj)
"""
        result = run_prefilter(
            target_path=Path("/tmp"),
            file_path="util.py",
            function_name="get_name",
            source=source,
            line_start=1,
            project_sinks=frozenset({"execute_sql"}),
        )
        assert result.skip_llm


# ── Learning loop ────────────────────────────────────────────────

class TestLearningLoop:

    def test_extract_fp_patterns_caller_contract(self):
        from core.audit.learning import extract_fp_patterns
        results = [
            {"correct": False, "expected": "clean", "actual": "suspicious",
             "hypothesis": "caller passes null", "hypotheses": [
                 {"mechanism": "caller passes invalid length", "counter": ""}]},
            {"correct": False, "expected": "clean", "actual": "suspicious",
             "hypothesis": "upstream caller provides bad data", "hypotheses": []},
            {"correct": False, "expected": "clean", "actual": "suspicious",
             "hypothesis": "the caller could invoke with null", "hypotheses": []},
            {"correct": True, "expected": "clean", "actual": "clean",
             "hypothesis": "", "hypotheses": []},
        ]
        patterns = extract_fp_patterns(results, min_count=2)
        assert len(patterns) >= 1
        assert patterns[0]["category"] == "caller_contract"
        assert patterns[0]["count"] >= 2

    def test_no_patterns_when_all_correct(self):
        from core.audit.learning import extract_fp_patterns
        results = [
            {"correct": True, "expected": "clean", "actual": "clean",
             "hypothesis": "", "hypotheses": []},
        ]
        assert extract_fp_patterns(results) == []

    def test_save_and_load_corrections(self, tmp_path):
        from core.audit.learning import load_corrections, save_corrections
        patterns = [
            {"category": "caller_contract", "count": 5,
             "correction": "Do not flag caller contract issues.",
             "examples": ["a.c:func1", "b.c:func2"]},
        ]
        save_corrections(patterns, tmp_path, store_to_sage=False)
        corrections = load_corrections(tmp_path)
        assert len(corrections) == 1
        assert "caller contract" in corrections[0]

    def test_corpus_fallback_anchored_to_raptor_dir(self, tmp_path, monkeypatch):
        """The out/audit-corpus-* fallback must not depend on process CWD."""
        import json as _json

        from core.audit.learning import load_corrections

        repo_root = tmp_path / "repo"
        corpus = repo_root / "out" / "audit-corpus-20260101"
        corpus.mkdir(parents=True)
        (corpus / "prompt-corrections.json").write_text(_json.dumps({
            "corrections": [{"rule": "Check bounds before memcpy."}],
        }))

        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        monkeypatch.setenv("RAPTOR_DIR", str(repo_root))

        corrections = load_corrections()
        assert corrections == ["Check bounds before memcpy."]

    def test_format_corrections_for_prompt(self):
        from core.audit.learning import format_corrections_for_prompt
        corrections = [
            "Do not flag caller contract issues.",
            "Check lock scope before hypothesising races.",
        ]
        text = format_corrections_for_prompt(corrections)
        assert "LEARNED CORRECTIONS" in text
        assert "1." in text
        assert "2." in text

    def test_empty_corrections_no_output(self):
        from core.audit.learning import format_corrections_for_prompt
        assert format_corrections_for_prompt([]) == ""


# ── Ensemble merge ──────────────────────────────────────────────

class TestEnsembleMerge:

    def _make_outcome(self, file, fn, status, evidence="", cost=0.01,
                       hypothesis=""):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file=file, function=fn, status=status,
            body="test", evidence_tool=evidence, cost_usd=cost,
            hypothesis=hypothesis,
        )

    def test_max_alarm_finding_wins(self):
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome("a.c", "f", "finding", evidence="semgrep:r1")]
        merged = _merge_outcomes(sec, bf)
        assert len(merged) == 1
        assert merged[0].status == "finding"
        assert merged[0].cost_usd == 0.02

    def test_suspicious_without_agreement_demoted(self):
        """Disagree without evidence: conservative merge picks lower."""
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome("a.c", "f", "suspicious")]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "clean"

    def test_suspicious_with_detection_evidence_demoted(self):
        """Detection-only evidence is not verification — conservative merge picks lower."""
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome("a.c", "f", "suspicious", evidence="smt:check")]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "clean"

    def test_suspicious_with_verification_evidence_kept(self):
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome("a.c", "f", "suspicious", evidence="joern:xf:unchecked_return")]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "suspicious"

    def test_disjoint_functions_both_kept(self):
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f1", "finding")]
        bf = [self._make_outcome("b.c", "f2", "suspicious")]
        merged = _merge_outcomes(sec, bf)
        assert len(merged) == 2

    def test_evidence_merged_on_promotion(self):
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "suspicious", evidence="smt:x")]
        bf = [self._make_outcome("a.c", "f", "finding", evidence="semgrep:r1")]
        merged = _merge_outcomes(sec, bf)
        assert "semgrep:r1" in merged[0].evidence_tool
        assert "smt:x" in merged[0].evidence_tool

    def test_review_mode_ensemble_exists(self):
        from core.audit.pipeline import ReviewMode
        assert ReviewMode.ENSEMBLE.value == "ensemble"
        assert ReviewMode("ensemble") == ReviewMode.ENSEMBLE

    # ── Bug-class-aware disagree demotion ────────────────────────

    def test_disagree_no_evidence_picks_lower(self):
        """Disagreement without evidence: conservative merge picks lower."""
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome(
            "a.c", "f", "suspicious",
            hypothesis="race condition in refcount update",
        )]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "clean"

    def test_disagree_finding_no_evidence_picks_lower(self):
        """Finding disagreement without evidence: conservative merge picks lower."""
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome(
            "a.c", "f", "finding",
            hypothesis="privilege escalation via uid check",
        )]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "clean"

    def test_disagree_with_evidence_keeps_max(self):
        """Disagreement WITH evidence keeps higher status."""
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome("a.c", "f", "clean")]
        bf = [self._make_outcome(
            "a.c", "f", "finding",
            evidence="smt:check-lock-discipline",
            hypothesis="lock imbalance in error path",
        )]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "finding"

    def test_both_modes_agree_on_sensitive_no_demotion(self):
        """Both modes flag suspicious: no demotion regardless of hypothesis."""
        from core.audit.pipeline import _merge_outcomes
        sec = [self._make_outcome(
            "a.c", "f", "suspicious",
            hypothesis="race in refcount",
        )]
        bf = [self._make_outcome(
            "a.c", "f", "suspicious",
            hypothesis="race condition in counter",
        )]
        merged = _merge_outcomes(sec, bf)
        assert merged[0].status == "suspicious"


# ── SMT clean-refuted precision ─────────────────────────────────

class TestSmtCleanRefutedPrecision:

    def test_bare_overflow_no_longer_maps_to_verb(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("stack overflow in recursion") is None
        assert hypothesis_to_smt_verb("the buffer could overflow") is None

    def test_integer_overflow_still_maps(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("integer overflow in count * size") == "check-overflow"
        assert hypothesis_to_smt_verb("arithmetic overflow wraps uint32") == "check-overflow"

    def test_buffer_overflow_maps_to_oob(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("buffer overflow via memcpy") == "check-oob"

    def test_source_has_arithmetic_positive(self):
        from core.audit.orchestrator import _source_has_arithmetic
        assert _source_has_arithmetic("size = count * elem_size;")
        assert _source_has_arithmetic("offset = base + len;")
        assert _source_has_arithmetic("result = a - b;")

    def test_source_has_arithmetic_negative(self):
        from core.audit.orchestrator import _source_has_arithmetic
        assert not _source_has_arithmetic("return get_value(ctx);")
        assert not _source_has_arithmetic("if (ptr == NULL) return;")

    def test_arithmetic_in_comments_ignored(self):
        from core.audit.orchestrator import _source_has_arithmetic
        assert not _source_has_arithmetic('// size = count * elem_size\nreturn 0;')
        assert not _source_has_arithmetic('/* a + b */\nreturn ptr;')


# ── Language gate (Intervention A) ─────────────────────────────

class TestLanguageGate:

    def test_overflow_safe_languages_gated(self):
        from core.audit.sweep import _lang_has_overflow_safety
        assert _lang_has_overflow_safety("pkg/oci/spec_opts.go")
        assert _lang_has_overflow_safety("flask_appbuilder/manager.py")
        assert _lang_has_overflow_safety("src/main.rs")
        assert _lang_has_overflow_safety("com/example/App.java")

    def test_c_not_gated(self):
        from core.audit.sweep import _lang_has_overflow_safety
        assert not _lang_has_overflow_safety("fs/proc/base.c")
        assert not _lang_has_overflow_safety("net/ipv4/esp4.c")
        assert not _lang_has_overflow_safety("include/net/esp.h")


# ── Operand-in-arithmetic gate (Intervention B) ────────────────

class TestOperandInArithmetic:

    def test_operand_present_in_arithmetic(self):
        from core.audit.sweep import _operand_in_source_arithmetic
        assert _operand_in_source_arithmetic("count", "total = count * elem_size;")
        assert _operand_in_source_arithmetic("len", "offset = base + len;")

    def test_operand_not_in_arithmetic(self):
        from core.audit.sweep import _operand_in_source_arithmetic
        assert not _operand_in_source_arithmetic("count", "return get_count(ctx);")
        assert not _operand_in_source_arithmetic("size", "if (size == 0) return;")

    def test_operand_in_comment_not_matched(self):
        from core.audit.sweep import _operand_in_source_arithmetic
        assert not _operand_in_source_arithmetic(
            "count", "// total = count * size\nreturn 0;",
        )

    def test_extract_filters_non_arithmetic_operands(self):
        from core.audit.sweep import _extract_arithmetic_operands
        source = "return get_value(ctx);"
        ops = _extract_arithmetic_operands(
            "integer overflow in `count` times `elem_size`", source,
        )
        assert len(ops) == 0

    def test_extract_keeps_real_arithmetic_operands(self):
        from core.audit.sweep import _extract_arithmetic_operands
        source = "total = count * elem_size;"
        ops = _extract_arithmetic_operands(
            "integer overflow in `count` times `elem_size`", source,
        )
        assert "count" in ops or "elem_size" in ops


# ── Self-contradiction demotion (Intervention C) ────────────────

class TestSelfContradictionDemotion:

    def _make_outcome(self, status, hypotheses, evidence=""):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file="test.c", function="func",
            status=status, body="test body",
            hypotheses=hypotheses, evidence_tool=evidence,
        )

    def test_all_refuted_suspicious_demoted(self):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _demote_self_contradictions,
        )
        outcome = self._make_outcome("suspicious", [
            {"mechanism": "overflow", "confidence": "refuted"},
            {"mechanism": "oob", "confidence": "refuted"},
        ])
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _demote_self_contradictions(result)
        assert result.outcomes[0].status == "clean"
        assert result.suspicious == 0
        assert result.clean == 1
        assert "[self-contradiction:" in result.outcomes[0].body

    def test_mixed_confidence_not_demoted(self):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _demote_self_contradictions,
        )
        outcome = self._make_outcome("suspicious", [
            {"mechanism": "overflow", "confidence": "refuted"},
            {"mechanism": "oob", "confidence": "medium"},
        ])
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _demote_self_contradictions(result)
        assert result.outcomes[0].status == "suspicious"

    def test_evidence_backed_not_demoted(self):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _demote_self_contradictions,
        )
        outcome = self._make_outcome("suspicious", [
            {"mechanism": "overflow", "confidence": "refuted"},
        ], evidence="smt:check-overflow")
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _demote_self_contradictions(result)
        assert result.outcomes[0].status == "suspicious"

    def test_no_hypotheses_not_demoted(self):
        from core.audit.orchestrator import (
            OrchestratorResult,
            _demote_self_contradictions,
        )
        outcome = self._make_outcome("suspicious", [])
        result = OrchestratorResult()
        result.outcomes = [outcome]
        result.suspicious = 1
        _demote_self_contradictions(result)
        assert result.outcomes[0].status == "suspicious"


# ── Format-string Go gate (Intervention D) ──────────────────────

class TestFormatStringGoGate:

    def test_format_string_skipped_for_go(self):
        from core.audit.hypothesis_mapping import hypothesis_to_semgrep_rule
        result = hypothesis_to_semgrep_rule(
            "format string injection via user input", "pkg/fmt/format.go",
        )
        assert result is None

    def test_format_string_kept_for_c(self):
        from core.audit.hypothesis_mapping import hypothesis_to_semgrep_rule
        result = hypothesis_to_semgrep_rule(
            "format string injection via user input", "src/logger.c",
        )
        assert result is not None
        Path(result).unlink()


# ── Auth bypass SMT check (check-auth-bypass) ──────────────────

class TestAuthBypass:

    def test_early_return_before_auth_check(self):
        # ptrace_has_cap is pack-tier vocabulary (kernel targets get it
        # via the linux_kernel vocab pack; seeds alone no longer carry it).
        from core.audit.condition_smt import check_auth_bypass
        from core.audit.vocab_packs import load_pack
        source = (
            "int func(struct task *task) {\n"
            "    if (same_thread_group(task, current))\n"
            "        return 0;\n"
            "    if (!ptrace_has_cap(cred, tcred, mode))\n"
            "        return -EPERM;\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_auth_bypass(source, load_pack("linux_kernel"))
        assert result.bypass_found
        assert "ptrace_has_cap" in str(result.bypassed_checks)

    def test_no_bypass_when_auth_before_return(self):
        from core.audit.condition_smt import check_auth_bypass
        source = (
            "int func(struct task *task) {\n"
            "    if (!capable(CAP_SYS_ADMIN))\n"
            "        return -EPERM;\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_auth_bypass(source)
        assert not result.bypass_found

    def test_no_auth_checks_returns_clean(self):
        from core.audit.condition_smt import check_auth_bypass
        source = (
            "int func(int x) {\n"
            "    if (x > 0)\n"
            "        return 0;\n"
            "    return -1;\n"
            "}\n"
        )
        result = check_auth_bypass(source)
        assert not result.bypass_found
        assert "no auth checks" in result.reasoning

    def test_guard_is_auth_check_not_flagged(self):
        from core.audit.condition_smt import check_auth_bypass
        source = (
            "int func(void) {\n"
            "    if (capable(CAP_SYS_ADMIN))\n"
            "        return 0;\n"
            "    if (!ns_capable(ns, CAP_NET_RAW))\n"
            "        return -EPERM;\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_auth_bypass(source)
        assert not result.bypass_found

    def test_hypothesis_maps_to_auth_bypass_verb(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("permission bypass via early return") == "check-auth-bypass"
        assert hypothesis_to_smt_verb("capability bypass in ptrace") == "check-auth-bypass"
        assert hypothesis_to_smt_verb("privilege escalation via uid check") == "check-auth-bypass"

    def test_result_to_dict(self):
        from core.audit.condition_smt import AuthBypassResult
        r = AuthBypassResult(
            bypass_found=True,
            early_return_line=3,
            guard_text="(same_thread_group(task, current))",
            bypassed_checks=["capability:ptrace_has_cap"],
            reasoning="early return bypasses auth",
        )
        d = r.to_dict()
        assert d["bypass_found"] is True
        assert d["early_return_line"] == 3
        assert "ptrace_has_cap" in d["bypassed_checks"][0]

    def test_cascading_permission_not_flagged(self):
        from core.audit.condition_smt import check_auth_bypass
        source = (
            "static bool has_pid_permissions(struct proc_fs_info *fs_info,\n"
            "    struct task_struct *task, enum proc_hidepid hide_pid_min)\n"
            "{\n"
            "    if (fs_info->hide_pid == HIDEPID_NOT_PTRACEABLE)\n"
            "        return ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS);\n"
            "    if (fs_info->hide_pid < hide_pid_min)\n"
            "        return true;\n"
            "    if (in_group_p(fs_info->pid_gid))\n"
            "        return true;\n"
            "    return ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS);\n"
            "}\n"
        )
        result = check_auth_bypass(source)
        assert not result.bypass_found


class TestLockDiscipline:
    """Tests for the lock discipline SMT check."""

    def test_return_between_lock_unlock(self):
        from core.audit.condition_smt import check_lock_discipline
        source = (
            "int foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    if (b->err)\n"
            "        return -EINVAL;\n"
            "    b->count++;\n"
            "    spin_unlock(&b->lock);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_lock_discipline(source)
        assert result.violation_found
        assert "spin_lock" in result.lock_type
        assert result.return_line > 0

    def test_balanced_lock_unlock(self):
        from core.audit.condition_smt import check_lock_discipline
        source = (
            "int foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    b->count++;\n"
            "    spin_unlock(&b->lock);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_lock_discipline(source)
        assert not result.violation_found

    def test_no_lock_acquires(self):
        from core.audit.condition_smt import check_lock_discipline
        source = "int foo(void) { return 0; }\n"
        result = check_lock_discipline(source)
        assert not result.violation_found
        assert "no lock acquires" in result.reasoning

    def test_missing_unlock_entirely(self):
        from core.audit.condition_smt import check_lock_discipline
        source = (
            "void foo(struct bar *b) {\n"
            "    mutex_lock(&b->mtx);\n"
            "    b->val = 42;\n"
            "}\n"
        )
        result = check_lock_discipline(source)
        assert result.violation_found
        assert "no matching" in result.reasoning

    def test_goto_error_path_with_unlock(self):
        from core.audit.condition_smt import check_lock_discipline
        source = (
            "int foo(struct bar *b) {\n"
            "    spin_lock(&b->lock);\n"
            "    if (b->err)\n"
            "        goto out;\n"
            "    b->count++;\n"
            "out:\n"
            "    spin_unlock(&b->lock);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_lock_discipline(source)
        assert not result.violation_found

    def test_mutex_lock_interruptible(self):
        from core.audit.condition_smt import check_lock_discipline
        source = (
            "int foo(struct bar *b) {\n"
            "    mutex_lock_interruptible(&b->mtx);\n"
            "    if (b->err)\n"
            "        return -EINTR;\n"
            "    mutex_unlock(&b->mtx);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_lock_discipline(source)
        assert result.violation_found

    def test_result_to_dict(self):
        from core.audit.condition_smt import LockDisciplineResult
        r = LockDisciplineResult(
            violation_found=True,
            lock_type="spin_lock",
            acquire_line=5,
            return_line=8,
            reasoning="lock held on return",
        )
        d = r.to_dict()
        assert d["violation_found"] is True
        assert d["lock_type"] == "spin_lock"
        assert d["acquire_line"] == 5
        assert d["return_line"] == 8

    def test_hypothesis_maps_to_lock_discipline_verb(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("lock imbalance in error path") == "check-lock-discipline"
        assert hypothesis_to_smt_verb("missing unlock before return") == "check-lock-discipline"
        assert hypothesis_to_smt_verb("spinlock held on error return") == "check-lock-discipline"
        assert hypothesis_to_smt_verb("deadlock from recursive locking") == "check-lock-discipline"


class TestResourceLeak:
    """Tests for the error-path resource leak SMT check."""

    def test_leak_on_error_return(self):
        from core.audit.condition_smt import check_resource_leak
        source = (
            "int foo(struct device *dev) {\n"
            "    char *buf = kmalloc(256, GFP_KERNEL);\n"
            "    int ret = do_thing(buf);\n"
            "    if (ret < 0)\n"
            "        return ret;\n"
            "    kfree(buf);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_resource_leak(source)
        assert result.leak_found
        assert result.alloc_var == "buf"
        assert result.alloc_func == "kmalloc"

    def test_no_leak_when_freed(self):
        from core.audit.condition_smt import check_resource_leak
        source = (
            "int foo(struct device *dev) {\n"
            "    char *buf = kmalloc(256, GFP_KERNEL);\n"
            "    int ret = do_thing(buf);\n"
            "    if (ret < 0) {\n"
            "        kfree(buf);\n"
            "        return ret;\n"
            "    }\n"
            "    kfree(buf);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_resource_leak(source)
        assert not result.leak_found

    def test_no_allocs(self):
        from core.audit.condition_smt import check_resource_leak
        source = "int foo(void) { return 0; }\n"
        result = check_resource_leak(source)
        assert not result.leak_found
        assert "no allocations" in result.reasoning

    def test_null_check_not_a_leak(self):
        from core.audit.condition_smt import check_resource_leak
        source = (
            "int foo(void) {\n"
            "    char *p = kzalloc(64, GFP_KERNEL);\n"
            "    if (!p)\n"
            "        return -ENOMEM;\n"
            "    kfree(p);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_resource_leak(source)
        assert not result.leak_found

    def test_goto_cleanup_not_a_leak(self):
        from core.audit.condition_smt import check_resource_leak
        source = (
            "int foo(void) {\n"
            "    char *buf = kmalloc(128, GFP_KERNEL);\n"
            "    if (do_thing())\n"
            "        goto err;\n"
            "    kfree(buf);\n"
            "    return 0;\n"
            "err:\n"
            "    kfree(buf);\n"
            "    return -EIO;\n"
            "}\n"
        )
        result = check_resource_leak(source)
        assert not result.leak_found

    def test_result_to_dict(self):
        from core.audit.condition_smt import ResourceLeakResult
        r = ResourceLeakResult(
            leak_found=True,
            alloc_var="buf",
            alloc_func="kmalloc",
            alloc_line=3,
            return_line=7,
            reasoning="leak on error path",
        )
        d = r.to_dict()
        assert d["leak_found"] is True
        assert d["alloc_var"] == "buf"
        assert d["alloc_func"] == "kmalloc"

    def test_hypothesis_maps_to_resource_leak_verb(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("resource leak in error path") == "check-resource-leak"
        assert hypothesis_to_smt_verb("memory leak when init fails") == "check-resource-leak"
        assert hypothesis_to_smt_verb("allocated but not freed on error") == "check-resource-leak"


class TestNullPropagation:
    """Tests for the null propagation detection check."""

    def test_deref_without_null_check(self):
        from core.audit.condition_smt import check_null_propagation
        source = (
            "int foo(struct device *dev) {\n"
            "    char *buf = kmalloc(256, GFP_KERNEL);\n"
            "    buf->field = 42;\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_null_propagation(source)
        assert result.null_deref_found
        assert result.var_name == "buf"
        assert result.source_func == "kmalloc"

    def test_null_check_before_deref(self):
        from core.audit.condition_smt import check_null_propagation
        source = (
            "int foo(struct device *dev) {\n"
            "    char *buf = kmalloc(256, GFP_KERNEL);\n"
            "    if (!buf)\n"
            "        return -ENOMEM;\n"
            "    buf->field = 42;\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_null_propagation(source)
        assert not result.null_deref_found

    def test_is_err_check(self):
        from core.audit.condition_smt import check_null_propagation
        source = (
            "int foo(void) {\n"
            "    struct clk *clk = devm_kzalloc(dev, sizeof(*clk), GFP_KERNEL);\n"
            "    if (IS_ERR(clk))\n"
            "        return PTR_ERR(clk);\n"
            "    clk->rate = 1000;\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_null_propagation(source)
        assert not result.null_deref_found

    def test_no_nullable_assigns(self):
        from core.audit.condition_smt import check_null_propagation
        source = "int foo(void) { return 0; }\n"
        result = check_null_propagation(source)
        assert not result.null_deref_found
        assert "no nullable" in result.reasoning

    def test_no_deref(self):
        from core.audit.condition_smt import check_null_propagation
        source = (
            "int foo(void) {\n"
            "    char *buf = kzalloc(64, GFP_KERNEL);\n"
            "    kfree(buf);\n"
            "    return 0;\n"
            "}\n"
        )
        result = check_null_propagation(source)
        assert not result.null_deref_found

    def test_result_to_dict(self):
        from core.audit.condition_smt import NullPropagationResult
        r = NullPropagationResult(
            null_deref_found=True,
            var_name="ptr",
            source_func="kmalloc",
            assign_line=3,
            deref_line=5,
            reasoning="deref without check",
        )
        d = r.to_dict()
        assert d["null_deref_found"] is True
        assert d["var_name"] == "ptr"
        assert d["deref_line"] == 5

    def test_hypothesis_maps_to_null_propagation_verb(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("null pointer dereference") == "check-null-propagation"
        assert hypothesis_to_smt_verb("missing null check after alloc") == "check-null-propagation"
        assert hypothesis_to_smt_verb("unchecked null from kmalloc") == "check-null-propagation"


class TestIntegerNarrowing:
    """Tests for the integer narrowing detection check."""

    def test_size_t_to_int_narrowing(self):
        from core.audit.condition_smt import check_integer_narrowing
        source = (
            "void foo(size_t len) {\n"
            "    int local_len = len;\n"
            "    do_thing(local_len);\n"
            "}\n"
        )
        result = check_integer_narrowing(source)
        assert result.narrowing_found
        assert result.source_type == "size_t"
        assert result.dest_type == "int"
        assert result.source_width == 64
        assert result.dest_width == 32

    def test_same_width_no_narrowing(self):
        from core.audit.condition_smt import check_integer_narrowing
        source = (
            "void foo(unsigned int len) {\n"
            "    int local_len = len;\n"
            "    do_thing(local_len);\n"
            "}\n"
        )
        result = check_integer_narrowing(source)
        assert not result.narrowing_found

    def test_bounds_check_prevents_flag(self):
        from core.audit.condition_smt import check_integer_narrowing
        source = (
            "void foo(size_t len) {\n"
            "    if (len > INT_MAX)\n"
            "        return;\n"
            "    int local_len = len;\n"
            "    do_thing(local_len);\n"
            "}\n"
        )
        result = check_integer_narrowing(source)
        assert not result.narrowing_found

    def test_no_narrowing_assignments(self):
        from core.audit.condition_smt import check_integer_narrowing
        source = "int foo(void) { return 0; }\n"
        result = check_integer_narrowing(source)
        assert not result.narrowing_found

    def test_result_to_dict(self):
        from core.audit.condition_smt import IntegerNarrowingResult
        r = IntegerNarrowingResult(
            narrowing_found=True,
            source_type="size_t",
            dest_type="u16",
            source_width=64,
            dest_width=16,
            assign_line=5,
            reasoning="narrowing without check",
        )
        d = r.to_dict()
        assert d["narrowing_found"] is True
        assert d["source_type"] == "size_t"
        assert d["dest_width"] == 16

    def test_hypothesis_maps_to_integer_narrowing_verb(self):
        from core.audit.hypothesis_mapping import hypothesis_to_smt_verb
        assert hypothesis_to_smt_verb("integer narrowing in copy path") == "check-integer-narrowing"
        assert hypothesis_to_smt_verb("truncation of user-supplied length") == "check-integer-narrowing"
        assert hypothesis_to_smt_verb("size_t to int conversion") == "check-integer-narrowing"


# ── Deepen parallelisation ──────────────────────────────────────────

class TestDeepenParallel:

    @staticmethod
    def _make_outcome(file, func, status, body="body", hypothesis="hyp"):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file=file,
            function=func,
            status=status,
            body=body,
            hypothesis=hypothesis,
            review_result={"body": body},
        )

    @staticmethod
    def _make_checklist(*entries):
        from collections import defaultdict
        by_file = defaultdict(list)
        for file, func in entries:
            by_file[file].append({
                "name": func,
                "line_start": 1,
                "line_end": 100,
            })
        files = [
            {"path": f, "functions": funcs}
            for f, funcs in by_file.items()
        ]
        return {"files": files}

    def test_serial_and_parallel_produce_same_results(self, monkeypatch, tmp_path):
        import copy
        import time

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _deepen_suspicious,
        )

        outcomes = [
            self._make_outcome("a.c", "foo", "suspicious"),
            self._make_outcome("b.c", "bar", "suspicious"),
            self._make_outcome("c.c", "baz", "suspicious"),
        ]
        checklist = self._make_checklist(
            ("a.c", "foo"), ("b.c", "bar"), ("c.c", "baz"),
        )
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
            deepen_suspicious=True,
            enable_session_context=False,
            blind_first_pass=False,
        )

        def _fake_build_context(cfg, gap, *a, **kw):
            return {"file": gap["file"], "function": gap["name"]}

        monkeypatch.setattr(_orch, "_build_context", _fake_build_context)

        call_count = 0
        def mock_review(ctx, cfg):
            nonlocal call_count
            call_count += 1
            return self._make_outcome(
                ctx["file"], ctx["function"], "finding", body="found it",
            )

        result_serial = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes),
            suspicious=3,
        )
        _deepen_suspicious(
            result_serial, config, mock_review, checklist,
            None, None, [], None, set(), time.time(), None,
            max_workers=1,
        )

        serial_count = call_count
        call_count = 0

        result_parallel = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes),
            suspicious=3,
        )
        _deepen_suspicious(
            result_parallel, config, mock_review, checklist,
            None, None, [], None, set(), time.time(), None,
            max_workers=4,
        )

        assert serial_count == call_count == 3
        assert result_serial.findings == result_parallel.findings

    def test_parallel_deepen_no_targets(self, tmp_path):
        import time

        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _deepen_suspicious,
        )

        result = OrchestratorResult(
            outcomes=[self._make_outcome("a.c", "foo", "clean")],
            clean=1,
        )
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            deepen_suspicious=True,
        )
        out = _deepen_suspicious(
            result, config, lambda c, cfg: None,
            {"files": []}, None, None, [], None, set(),
            time.time(), None, max_workers=4,
        )
        assert out.clean == 1

    def test_parallel_deepen_handles_review_failure(self, monkeypatch, tmp_path):
        import time

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _deepen_suspicious,
        )

        outcomes = [
            self._make_outcome("a.c", "foo", "suspicious"),
            self._make_outcome("b.c", "bar", "suspicious"),
        ]
        checklist = self._make_checklist(("a.c", "foo"), ("b.c", "bar"))
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
            deepen_suspicious=True,
            enable_session_context=False,
            blind_first_pass=False,
        )

        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]},
        )

        def mock_review(ctx, cfg):
            if ctx["function"] == "foo":
                raise RuntimeError("LLM failed")
            from core.audit.orchestrator import ReviewOutcome
            return ReviewOutcome(
                file="b.c", function="bar", status="finding",
                body="ok", hypothesis="null pointer dereference in bar",
                evidence_tool="semgrep:cwe-476",
                review_result={"body": "ok"},
            )

        result = OrchestratorResult(outcomes=list(outcomes), suspicious=2)
        out = _deepen_suspicious(
            result, config, mock_review, checklist,
            None, None, [], None, set(), time.time(), None,
            max_workers=4,
        )
        assert out.findings == 1


class TestDisagreementParallel:

    @staticmethod
    def _make_outcome(file, func, status, body="body"):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file=file, function=func, status=status, body=body,
            review_result={"body": body},
        )

    def test_serial_and_parallel_same_results(self, monkeypatch, tmp_path):
        import copy
        import time
        from types import SimpleNamespace

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _re_review_disagreements,
        )

        outcomes = [
            self._make_outcome("a.c", "foo", "clean"),
            self._make_outcome("b.c", "bar", "clean"),
        ]
        checklist = {
            "files": [
                {"file": "a.c", "items": [{"name": "foo", "line_start": 1, "line_end": 50}]},
                {"file": "b.c", "items": [{"name": "bar", "line_start": 1, "line_end": 50}]},
            ],
        }
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
        )
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]},
        )

        disagreements = [
            SimpleNamespace(
                file="a.c", function="foo",
                resolution="mechanical wins",
                mechanical_claim=SimpleNamespace(reachable=True, has_flow=True),
            ),
            SimpleNamespace(
                file="b.c", function="bar",
                resolution="mechanical wins",
                mechanical_claim=SimpleNamespace(reachable=True, has_flow=False),
            ),
        ]

        call_count = 0
        def mock_review(ctx, cfg):
            nonlocal call_count
            call_count += 1
            return self._make_outcome(ctx["file"], ctx["function"], "suspicious")

        result_serial = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2,
        )
        _re_review_disagreements(
            disagreements, result_serial, config, mock_review,
            checklist, None, None, time.time(), None,
            max_workers=1,
        )
        serial_count = call_count

        call_count = 0
        result_parallel = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2,
        )
        _re_review_disagreements(
            disagreements, result_parallel, config, mock_review,
            checklist, None, None, time.time(), None,
            max_workers=4,
        )

        assert serial_count == call_count == 2
        assert result_serial.suspicious == result_parallel.suspicious == 2

    def test_handles_review_failure(self, monkeypatch, tmp_path):
        import time
        from types import SimpleNamespace

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _re_review_disagreements,
        )

        outcomes = [
            self._make_outcome("a.c", "foo", "clean"),
            self._make_outcome("b.c", "bar", "clean"),
        ]
        checklist = {
            "files": [
                {"file": "a.c", "items": [{"name": "foo"}]},
                {"file": "b.c", "items": [{"name": "bar"}]},
            ],
        }
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
        )
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]},
        )
        disagreements = [
            SimpleNamespace(
                file="a.c", function="foo",
                resolution="wins",
                mechanical_claim=SimpleNamespace(reachable=True, has_flow=True),
            ),
            SimpleNamespace(
                file="b.c", function="bar",
                resolution="wins",
                mechanical_claim=SimpleNamespace(reachable=True, has_flow=True),
            ),
        ]

        def mock_review(ctx, cfg):
            if ctx["function"] == "foo":
                raise RuntimeError("boom")
            return self._make_outcome("b.c", "bar", "suspicious")

        result = OrchestratorResult(outcomes=list(outcomes), clean=2)
        out = _re_review_disagreements(
            disagreements, result, config, mock_review,
            checklist, None, None, time.time(), None,
            max_workers=4,
        )
        assert out.suspicious == 1
        assert out.clean == 1


class TestIterativeReReviewParallel:

    @staticmethod
    def _make_outcome(file, func, status, body="body"):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file=file, function=func, status=status, body=body,
            review_result={"body": body},
        )

    def test_parallel_iteration_same_results(self, monkeypatch, tmp_path):
        import copy
        import time

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _iterative_re_review,
        )

        outcomes = [
            self._make_outcome("a.c", "caller1", "clean"),
            self._make_outcome("a.c", "caller2", "clean"),
            self._make_outcome("b.c", "callee", "finding"),
        ]

        checklist = {
            "items": [
                {"file": "a.c", "functions": [
                    {"name": "caller1", "line_start": 1, "line_end": 50},
                    {"name": "caller2", "line_start": 51, "line_end": 100},
                ]},
                {"file": "b.c", "functions": [
                    {"name": "callee", "line_start": 1, "line_end": 50},
                ]},
            ],
        }
        context_map = {
            "call_graph": {
                "a.c:caller1": ["b.c:callee"],
                "a.c:caller2": ["b.c:callee"],
            },
        }
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
            propagate_constraints=True,
            enable_session_context=False,
        )
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]},
        )
        monkeypatch.setattr(
            _orch, "_commit_outcome", lambda *a, **kw: None,
        )
        monkeypatch.setattr(
            _orch, "save_constraints", lambda *a, **kw: None,
        )

        call_count = 0
        def mock_review(ctx, cfg):
            nonlocal call_count
            call_count += 1
            return self._make_outcome(ctx["file"], ctx["function"], "clean")

        result_serial = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2, findings=1,
        )
        _iterative_re_review(
            result_serial, config, mock_review, checklist,
            context_map, None, set(), [], None, None,
            time.time(), None, max_workers=1,
        )
        serial_count = call_count

        call_count = 0
        result_parallel = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2, findings=1,
        )
        _iterative_re_review(
            result_parallel, config, mock_review, checklist,
            context_map, None, set(), [], None, None,
            time.time(), None, max_workers=4,
        )

        assert serial_count == call_count
        assert result_serial.clean == result_parallel.clean


class TestStudyReReviewParallel:

    @staticmethod
    def _make_outcome(file, func, status, body="body"):
        from core.audit.orchestrator import ReviewOutcome
        return ReviewOutcome(
            file=file, function=func, status=status, body=body,
            review_result={"body": body},
        )

    def test_serial_and_parallel_same_results(self, monkeypatch, tmp_path):
        import copy
        import time

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _re_review_study_enriched,
        )

        outcomes = [
            self._make_outcome("a.c", "foo", "clean"),
            self._make_outcome("b.c", "bar", "clean"),
        ]
        checklist = {
            "files": [
                {"path": "a.c", "functions": [{"name": "foo", "line_start": 1, "line_end": 50}]},
                {"path": "b.c", "functions": [{"name": "bar", "line_start": 1, "line_end": 50}]},
            ],
        }
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
            enable_session_context=False,
        )
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]},
        )
        monkeypatch.setattr(
            _orch, "_commit_outcome", lambda *a, **kw: None,
        )

        reading_list = {"a.c:foo", "b.c:bar"}

        call_count = 0
        def mock_review(ctx, cfg):
            nonlocal call_count
            call_count += 1
            return self._make_outcome(ctx["file"], ctx["function"], "suspicious")

        result_serial = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2,
        )
        _re_review_study_enriched(
            result_serial, config, mock_review, checklist, None, {},
            None, set(), reading_list, time.time(), None,
            max_workers=1,
        )
        serial_count = call_count

        call_count = 0
        result_parallel = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2,
        )
        _re_review_study_enriched(
            result_parallel, config, mock_review, checklist, None, {},
            None, set(), reading_list, time.time(), None,
            max_workers=4,
        )

        assert serial_count == call_count == 2
        assert result_serial.suspicious == result_parallel.suspicious

    def test_duplicate_gap_entries_do_not_crash(self, monkeypatch, tmp_path):
        """Duplicate reading-list entries resolve to the same prior
        outcome; the second replace used to raise ValueError from
        outcomes.index() once the first iteration had swapped the prior
        out of the list. Candidates are now deduped and the replace is
        guarded (same shape as _re_review_joern_enriched)."""
        import copy
        import time

        import core.audit.orchestrator as _orch
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            _re_review_study_enriched,
        )

        outcomes = [
            self._make_outcome("a.c", "foo", "clean"),
            self._make_outcome("b.c", "bar", "clean"),
        ]
        checklist = {
            "files": [
                {"path": "a.c", "functions": [{"name": "foo", "line_start": 1, "line_end": 50}]},
                {"path": "b.c", "functions": [{"name": "bar", "line_start": 1, "line_end": 50}]},
            ],
        }
        config = OrchestratorConfig(
            target_path=tmp_path,
            out_dir=tmp_path,
            sweep_validate_findings=False,
            enable_session_context=False,
        )
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {"file": gap["file"], "function": gap["name"]},
        )
        monkeypatch.setattr(
            _orch, "_commit_outcome", lambda *a, **kw: None,
        )

        call_count = 0
        def mock_review(ctx, cfg):
            nonlocal call_count
            call_count += 1
            return self._make_outcome(ctx["file"], ctx["function"], "suspicious")

        # A list (not a set) so the duplicate entries actually reach
        # the candidate loop — the signature says set, but nothing
        # enforces it and the dedupe must hold either way.
        reading_list = ["a.c:foo", "a.c:foo", "b.c:bar"]

        result = OrchestratorResult(
            outcomes=copy.deepcopy(outcomes), clean=2,
        )
        _re_review_study_enriched(
            result, config, mock_review, checklist, None, {},
            None, set(), reading_list, time.time(), None,
            max_workers=1,
        )

        # Each function reviewed exactly once; no duplicate outcomes.
        assert call_count == 2
        assert len(result.outcomes) == 2
        statuses = {(o.file, o.function): o.status for o in result.outcomes}
        assert statuses[("a.c", "foo")] == "suspicious"
        assert statuses[("b.c", "bar")] == "suspicious"


# ── Pre-loop SMT screen ──────────────────────────────────────────────


class TestPreLoopSmtScreen:

    def _make_config(self, tmp_path):
        @dataclass
        class _Cfg:
            target_path: Path = tmp_path
            sweep_validate_findings: bool = True
        return _Cfg()

    def test_auth_bypass_injects_evidence_and_keeps_in_workqueue(self, tmp_path):
        from core.audit.orchestrator import OrchestratorResult, _pre_loop_smt_screen

        src = tmp_path / "auth.c"
        src.write_text("""\
int check_access(struct task *t) {
    if (same_thread_group(t, current))
        return 0;
    if (!ptrace_has_cap(cred, tcred, mode))
        return -EPERM;
    return 0;
}
""")
        # ptrace_has_cap comes from the linux_kernel vocab pack; mark
        # the target as a kernel tree so the screen's vocab loads it.
        (tmp_path / "Kconfig").write_text("config FOO\n")
        workqueue = [
            {"file": "auth.c", "name": "check_access", "line_start": 1, "line_end": 7},
        ]
        result = OrchestratorResult()
        config = self._make_config(tmp_path)

        kept = _pre_loop_smt_screen(workqueue, config, result)
        assert len(kept) == 1
        assert result.findings == 0
        assert "_smt_pre_evidence" in kept[0]

    def test_clean_function_stays_in_workqueue(self, tmp_path):
        from core.audit.orchestrator import OrchestratorResult, _pre_loop_smt_screen

        src = tmp_path / "clean.c"
        src.write_text("""\
int add(int a, int b) {
    return a + b;
}
""")
        workqueue = [
            {"file": "clean.c", "name": "add", "line_start": 1, "line_end": 3},
        ]
        result = OrchestratorResult()
        config = self._make_config(tmp_path)

        kept = _pre_loop_smt_screen(workqueue, config, result)
        assert len(kept) == 1
        assert result.findings == 0
        assert len(result.outcomes) == 0

    def test_non_c_file_skips_c_only_checks(self, tmp_path):
        from core.audit.orchestrator import OrchestratorResult, _pre_loop_smt_screen

        src = tmp_path / "app.py"
        src.write_text("""\
def greet(name):
    return f"hello {name}"
""")
        workqueue = [
            {"file": "app.py", "name": "greet", "line_start": 1, "line_end": 2},
        ]
        result = OrchestratorResult()
        config = self._make_config(tmp_path)

        kept = _pre_loop_smt_screen(workqueue, config, result)
        assert len(kept) == 1
        assert result.findings == 0

    def test_mixed_workqueue_partial_screen(self, tmp_path):
        from core.audit.orchestrator import OrchestratorResult, _pre_loop_smt_screen

        buggy = tmp_path / "leak.c"
        buggy.write_text("""\
int process(int fd) {
    void *buf = malloc(1024);
    if (fd < 0)
        return -1;
    free(buf);
    return 0;
}
""")
        clean = tmp_path / "ok.c"
        clean.write_text("""\
int add(int a, int b) {
    return a + b;
}
""")
        workqueue = [
            {"file": "leak.c", "name": "process", "line_start": 1, "line_end": 7},
            {"file": "ok.c", "name": "add", "line_start": 1, "line_end": 3},
        ]
        result = OrchestratorResult()
        config = self._make_config(tmp_path)

        kept = _pre_loop_smt_screen(workqueue, config, result)
        assert len(kept) == 2
        assert kept[0]["name"] == "process"
        assert "_smt_pre_evidence" in kept[0]
        assert kept[1]["name"] == "add"
        assert result.findings == 0
