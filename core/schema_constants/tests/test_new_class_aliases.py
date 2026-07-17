"""New exploitation-class labels must route into memory-corruption feasibility.

A scanner or LLM that emits a modern bug-class label (a JIT missing-write-barrier
type confusion, an inline-cache confusion, a kernel stack/cross-cache UAF) must
have it normalise to a canonical memory-corruption vuln_type so it enters Stage E
feasibility analysis instead of falling through to "other" and being silently
skipped.
"""

from core.schema_constants import normalise_vuln_type, needs_feasibility_analysis


class TestNewClassAliases:
    def test_jit_write_barrier_routes_to_type_confusion(self):
        assert normalise_vuln_type("jit_write_barrier") == "type_confusion"
        assert needs_feasibility_analysis("jit_write_barrier")

    def test_missing_write_barrier_routes(self):
        assert normalise_vuln_type("missing_write_barrier") == "type_confusion"

    def test_inline_cache_confusion_routes(self):
        assert normalise_vuln_type("ic_type_confusion") == "type_confusion"
        assert normalise_vuln_type("inline_cache_type_confusion") == "type_confusion"

    def test_kernel_stack_uaf_routes_to_use_after_free(self):
        assert normalise_vuln_type("kernel_stack_uaf") == "use_after_free"
        assert needs_feasibility_analysis("kernel_stack_uaf")

    def test_cross_cache_uaf_routes(self):
        assert normalise_vuln_type("cross_cache_uaf") == "use_after_free"
        assert needs_feasibility_analysis("cross_cache_uaf")
