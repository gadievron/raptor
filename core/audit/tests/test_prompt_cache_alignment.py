"""Cache-aligned prompt composition (pattern library in system prompt).

When the provider supports prompt caching, the run-stable pattern
material moves from every per-function user prompt into the (cached)
system prompt. These tests pin the three load-bearing properties:
the library is deterministic (byte-identical → cache hits), the user
prompt actually drops the static material (the saving), and dynamic
mid-run primers never migrate into the cached prefix (correctness).
"""

from __future__ import annotations

from core.audit.context import (
    format_context_for_prompt,
    render_pattern_library,
)


def _ctx(**over):
    base = {
        "file": "src/aes_util.c",
        "function": "f",
        "source": "int f(void) { return 1; }",
        "language": "c",
        "line_start": 1,
        "line_end": 1,
        "strategy_primers": ["STATIC PRIMER SENTINEL"],
        "strategy_exemplars": [{
            "cve": "CVE-SENTINEL", "strategy": "memory",
            "title": "t", "reasoning": "r",
        }],
    }
    base.update(over)
    return base


def test_library_is_deterministic_and_substantial():
    lib1 = render_pattern_library()
    lib2 = render_pattern_library()
    assert lib1 == lib2, "cache prefix must be byte-identical across calls"
    assert len(lib1) > 2000
    # One source of truth: the fixed pattern blocks render in the library
    assert "Kernel-internal patterns" in lib1
    assert "Go patterns" in lib1
    assert "Crypto helper patterns" in lib1
    assert "Strategy exemplars" in lib1


def test_default_composition_unchanged():
    p = format_context_for_prompt(_ctx())
    assert "STATIC PRIMER SENTINEL" in p
    assert "CVE-SENTINEL" in p
    assert "Crypto helper patterns" in p


def test_patterns_in_system_drops_static_material():
    p = format_context_for_prompt(_ctx(), patterns_in_system=True)
    assert "STATIC PRIMER SENTINEL" not in p
    assert "CVE-SENTINEL" not in p
    assert "Crypto helper patterns" not in p
    # the function's own content is untouched
    assert "src/aes_util.c:f" in p
    assert "int f(void)" in p


def test_dynamic_primers_stay_in_user_prompt():
    ctx = _ctx(dynamic_primers=["DYNAMIC PRIMER SENTINEL"])
    ctx["strategy_primers"] = [
        "STATIC PRIMER SENTINEL", "DYNAMIC PRIMER SENTINEL",
    ]
    p = format_context_for_prompt(ctx, patterns_in_system=True)
    assert "DYNAMIC PRIMER SENTINEL" in p
    assert "STATIC PRIMER SENTINEL" not in p


def test_dynamic_primers_never_in_library():
    # The library is built from static registries only — nothing
    # run-discovered may enter the cached prefix.
    lib = render_pattern_library()
    assert "DYNAMIC" not in lib


def test_kernel_blocks_gated():
    ctx = _ctx(file="drivers/net/foo.c",
               source="static int f(void) { spin_lock(&l); return 0; }",
               kernel_style=True)
    p_default = format_context_for_prompt(dict(ctx))
    p_system = format_context_for_prompt(dict(ctx), patterns_in_system=True)
    if "Kernel-internal patterns" in p_default:
        assert "Kernel-internal patterns" not in p_system


class TestCacheAlignedReviewComposition:
    """make_review_fn on a caching-composition transport: the pattern
    library lands in the system prompt, byte-stable across calls and
    across factory invocations (the cache prefix must not drift), and
    leaves the per-function user prompt."""

    class _Client:
        def __init__(self):
            self.calls = []

        def supports_prompt_caching_for(self):
            return True

        def generate_structured(self, prompt, schema,
                                system_prompt=None, **kwargs):
            self.calls.append((prompt, system_prompt))

            class _Resp:
                result = {"status": "clean", "body": "ok"}  # noqa: RUF012
                cost = 0.0
                model = "fake"

            return _Resp()

    def _run(self, client):
        from core.audit.llm_review import make_review_fn
        review_fn = make_review_fn(client)
        review_fn(
            {"file": "a.c", "function": "f", "source": "int f(){}",
             "line_start": 1, "line_end": 2},
            None,
        )

    def test_pattern_library_moves_to_system_prompt(self):
        client = self._Client()
        self._run(client)
        prompt, system_prompt = client.calls[0]
        assert "Crypto helper patterns" in system_prompt
        assert "Crypto helper patterns" not in prompt

    def test_system_prompt_byte_stable_across_calls_and_factories(self):
        c1 = self._Client()
        self._run(c1)
        self._run(c1)
        c2 = self._Client()
        self._run(c2)
        prompts = [sp for _, sp in c1.calls] + [sp for _, sp in c2.calls]
        assert len(set(prompts)) == 1, (
            "system prompt must be byte-identical across calls - it is "
            "the server-side cache prefix on the claudecode transport"
        )


class TestKernelHeuristicCorroboration:
    """Path hints alone must not classify userland trees as kernel C
    (openssl has crypto/ lib/ — the whole codebase got kernel
    exemplars). A kernel verdict now needs file-content markers."""

    def test_userland_crypto_dir_not_kernel(self, tmp_path):
        from core.audit.context import _is_kernel_c, _kernel_file_cache
        _kernel_file_cache.clear()
        src = tmp_path / "crypto" / "aes"
        src.mkdir(parents=True)
        f = src / "aes_core.c"
        f.write_text('#include <openssl/aes.h>\nint f(void){return 1;}\n')
        ctx = {"file": "crypto/aes/aes_core.c",
               "target_path": str(tmp_path)}
        assert _is_kernel_c(ctx) is False

    def test_kernel_file_with_markers_is_kernel(self, tmp_path):
        from core.audit.context import _is_kernel_c, _kernel_file_cache
        _kernel_file_cache.clear()
        src = tmp_path / "drivers" / "net"
        src.mkdir(parents=True)
        f = src / "foo.c"
        f.write_text('#include <linux/module.h>\nMODULE_LICENSE("GPL");\n')
        ctx = {"file": "drivers/net/foo.c", "target_path": str(tmp_path)}
        assert _is_kernel_c(ctx) is True

    def test_unreadable_file_falls_back_to_path_hint(self):
        from core.audit.context import _is_kernel_c, _kernel_file_cache
        _kernel_file_cache.clear()
        ctx = {"file": "drivers/net/gone.c", "target_path": "/nonexistent"}
        assert _is_kernel_c(ctx) is True

    def test_non_hinted_path_never_kernel(self):
        from core.audit.context import _is_kernel_c
        assert _is_kernel_c({"file": "src/app.c"}) is False
