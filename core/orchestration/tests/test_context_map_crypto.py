"""Crypto-inventory bootstrap for bare /audit runs (A9).

The final comparison audit ran /audit directly on an openssl target —
no /understand map — and ``crypto_inventory`` stayed empty (0 refs in
checklist/gaps): the crypto API packs only fed the source-intel phase
of ``/understand --map``. These tests prove an openssl-shaped fixture
yields nonzero crypto_inventory refs through the audit path: the
pack-driven prep bootstrap, per-function context extraction, and gap
strategy routing.
"""

from __future__ import annotations

import os

from core.orchestration.context_map_crypto import (
    enrich_with_crypto_inventory,
)

_OPENSSL_C = """\
#include <openssl/evp.h>

static int encrypt_buf(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl,
                       const unsigned char *in, int inl)
{
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        return 0;
    return EVP_EncryptUpdate(ctx, out, outl, in, inl);
}

static void fill_nonce(unsigned char *buf, int n)
{
    RAND_bytes(buf, n);
}

static int weak_token(void)
{
    return rand();
}
"""


def _fixture(tmp_path):
    src = tmp_path / "crypto_util.c"
    src.write_text(_OPENSSL_C)
    checklist = {
        "target_path": str(tmp_path),
        "files": [{
            "path": "crypto_util.c",
            "items": [
                {"name": "encrypt_buf", "kind": "function",
                 "line_start": 3, "line_end": 9, "metadata": {}},
                {"name": "fill_nonce", "kind": "function",
                 "line_start": 11, "line_end": 14, "metadata": {}},
                {"name": "weak_token", "kind": "function",
                 "line_start": 16, "line_end": 19, "metadata": {}},
            ],
        }],
    }
    return checklist


class TestBootstrap:
    def test_openssl_fixture_yields_nonzero_refs(self, tmp_path):
        checklist = _fixture(tmp_path)
        context_map: dict = {}
        n = enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        )
        assert n > 0
        sites = context_map["crypto_inventory"]
        fns = {s["fn"] for s in sites}
        assert "EVP_EncryptInit_ex" in fns   # openssl prefix family
        assert "RAND_bytes" in fns           # openssl rng prefix family
        assert "rand" in fns                 # hardcoded libc seed

    def test_site_shape_matches_source_intel_contract(self, tmp_path):
        checklist = _fixture(tmp_path)
        context_map: dict = {}
        enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        )
        by_fn = {s["fn"]: s for s in context_map["crypto_inventory"]}
        evp = by_fn["EVP_EncryptInit_ex"]
        assert evp["kind"] == "primitive_call"
        assert evp["api"] == "openssl"
        assert evp["file"] == "crypto_util.c"
        assert evp["function"] == "encrypt_buf"  # enclosing resolution
        rng = by_fn["RAND_bytes"]
        assert rng["kind"] == "rng_source"
        assert rng["function"] == "fill_nonce"
        libc = by_fn["rand"]
        assert libc["api"] == "libc"
        assert libc["kind"] == "rng_source"
        assert libc["function"] == "weak_token"

    def test_cwd_independent_pack_resolution(self, tmp_path, monkeypatch):
        """Packs resolve relative to the tree, never the invocation
        cwd (one of the A9 failure hypotheses)."""
        checklist = _fixture(tmp_path)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.setattr(os, "getcwd", lambda: str(elsewhere))
        monkeypatch.chdir(elsewhere)
        context_map: dict = {}
        assert enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        ) > 0

    def test_existing_map_section_never_overwritten(self, tmp_path):
        checklist = _fixture(tmp_path)
        prior = [{"kind": "primitive_call", "file": "x.c", "line": 1,
                  "function": "f", "api": "openssl", "fn": "HMAC"}]
        context_map = {"crypto_inventory": list(prior)}
        assert enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        ) == 0
        assert context_map["crypto_inventory"] == prior

    def test_no_checklist_no_sites(self, tmp_path):
        context_map: dict = {}
        assert enrich_with_crypto_inventory(
            context_map, checklist=None, target_path=tmp_path,
        ) == 0
        assert "crypto_inventory" not in context_map

    def test_non_crypto_target_stays_empty(self, tmp_path):
        (tmp_path / "plain.c").write_text(
            "int add(int a, int b) { return a + b; }\n",
        )
        checklist = {
            "target_path": str(tmp_path),
            "files": [{"path": "plain.c", "items": [
                {"name": "add", "kind": "function",
                 "line_start": 1, "line_end": 1, "metadata": {}},
            ]}],
        }
        context_map: dict = {}
        assert enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        ) == 0
        assert "crypto_inventory" not in context_map


class TestAuditPathConsumption:
    def test_per_function_context_extraction(self, tmp_path):
        """The audit's per-function context extractor sees the
        bootstrapped sites."""
        from core.audit.context import _extract_crypto_inventory

        checklist = _fixture(tmp_path)
        context_map: dict = {}
        enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        )
        entries = _extract_crypto_inventory(
            context_map, "crypto_util.c", "encrypt_buf",
        )
        assert entries
        assert all(e["function"] == "encrypt_buf" for e in entries)

    def test_gap_strategy_routing_sees_crypto_sites(self, tmp_path):
        """compute_gaps tags the function with the crypto strategy from
        the inventory — the file/function names carry no crypto
        vocabulary, so pre-fix only 'general' fired."""
        from core.audit.gaps import compute_gaps

        src = tmp_path / "util.c"
        src.write_text(
            "static void mix(unsigned char *b, int n)\n"
            "{\n"
            "    EVP_DigestUpdate(g_ctx, b, n);\n"
            "}\n",
        )
        checklist = {
            "target_path": str(tmp_path),
            "files": [{"path": "util.c", "items": [
                {"name": "mix", "kind": "function",
                 "line_start": 1, "line_end": 4, "metadata": {}},
            ]}],
        }
        context_map: dict = {}
        enrich_with_crypto_inventory(
            context_map, checklist=checklist, target_path=tmp_path,
        )
        gaps = compute_gaps(checklist, [], context_map=context_map)
        gap = next(g for g in gaps if g["name"] == "mix")
        assert "crypto" in gap["strategies"]

        # Fails-before shape: without the inventory the same gap
        # carries no crypto strategy (nothing in the path/source
        # keyword maps matches).
        bare = compute_gaps(checklist, [], context_map=None)
        bare_gap = next(g for g in bare if g["name"] == "mix")
        assert "crypto" not in bare_gap["strategies"]
