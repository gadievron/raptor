// crypto_calls.cocci — enumerate cryptographic primitive call sites + RNG
// sources for the Phase B `crypto_inventory` /understand --map section.
//
// NOT a "is this crypto broken" detector — pure enumeration. One
// COCCIRESULT per call:
//
//   crypto:<kind>:<api>:<fn>
//
// kind ∈ primitive_call | rng_source (per pack)
// api  = the pack's tag (openssl | kernel | libsodium | ...) or libc
// fn   = the concrete function name matched
//
// PER-LIBRARY COVERAGE IS DATA, NOT CODE. The `@api-packs:` slot below
// is rendered at analyze time by engine/coccinelle/api_pack_renderer.py
// from packs/*.json — one generated rule pair per (api, kind). Family
// membership is prefix-based where the library reserves the namespace
// (EVP_Digest*, crypto_skcipher_*, crypto_secretbox*, ...), with exact
// names only where prefixes would collide across libraries (see
// packs/README.md). Adding MbedTLS / BCrypt / Botan coverage = adding a
// pack file; this rule never grows another identifier list.
//
// Only the libc RNG rule is hardcoded here — universal C vocabulary
// per the operator policy, not library-specific API surface.
//
// Known limitations (documented for downstream consumers):
//   * Name-only matching. A non-crypto project that defines
//     `int SHA256_Update(state *, void *, size_t)` (rare but possible
//     for educational code or replacements) will fire. Short names
//     like `rand` have HIGH collision risk in pure-userspace code;
//     consumers should disambiguate using surrounding context.
//   * Prefix families intentionally cover future members (e.g. a new
//     EVP_Digest* verb) and adjacent same-namespace calls; the section
//     is enumeration, so over-capture within a library's namespace is
//     acceptable where under-capture is not.
//   * `rand()` and `random()` are categorised as `rng_source` here
//     because that is their advertised purpose, even though they are
//     cryptographically broken. The Phase B section is enumeration;
//     "broken RNG used in crypto context" reasoning belongs to a
//     separate finding-style rule.
//
// Consumed by packages/source_intel/analyze.py:_parse_match_to_crypto_call
// → CryptoCallEvidence tuples → SourceIntelResult.crypto_calls →
// context_map_sites.build_crypto_inventory → cmap["crypto_inventory"].


// =====================================================================
// Per-library packs — rendered rule pairs land below this marker
// =====================================================================

// @api-packs: packs crypto


// =====================================================================
// libc RNG — universal vocabulary, stays hardcoded
// =====================================================================

@libc_rng@
position p;
identifier fn = { rand, random, srand, srandom, drand48, lrand48, mrand48 };
@@
fn@p(...)

@script:python depends on libc_rng@
p << libc_rng.p;
fn << libc_rng.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:rng_source:libc:" + str(fn),
    }) + "\n")
