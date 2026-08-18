# Crypto API packs

Per-library crypto API surface, consumed by `crypto_calls.cocci` via the
`// @api-packs:` render slot (`engine/coccinelle/api_pack_renderer.py`).
At analyze time one Coccinelle rule pair (match + report) is generated
per `(api, kind)` from every `*.json` in this directory, so the cocci
file carries **no per-library identifier catalog**.

## Growth path

**A new crypto library is a new pack file — no cocci edit.**
Drop e.g. `mbedtls.json` here and `/understand --map` starts inventorying
`mbedtls_*` call sites: the renderer picks the file up automatically and
`packages/source_intel/analyze.py` accepts the new `api` tag from the
pack (the tag set is derived from this directory, not hardcoded).
The out-of-scope list from the old monolith (MbedTLS, Windows BCrypt,
Botan, Crypto++...) lands as pack files when target corpus shows demand.

## Schema

```json
{
  "api": "openssl",              // message tag: crypto:<kind>:<api>:<fn>
  "description": "...",          // free-form; document prefix decisions
  "kinds": {
    "primitive_call": {          // kind ∈ primitive_call | rng_source
      "prefixes": ["EVP_Digest"],// family match: fn starts with this
      "names": ["HMAC"]          // exact match: fn == this
    }
  }
}
```

* `api` must match `[a-z][a-z0-9_]*` (it is spliced into the COCCIRESULT
  message and into generated rule names).
* `prefixes` / `names` entries must be C identifiers (or identifier
  prefixes): `[A-Za-z_][A-Za-z0-9_]*`. Invalid entries are dropped with
  a warning; a structurally broken pack is skipped, never fatal.

## Prefix vs name

Prefer a **prefix** whenever the library reserves the namespace — that is
what kills the enumerated-list growth pressure (every future
`EVP_DigestSqueeze`-style addition is covered for free). Use exact
**names** only where a prefix would collide with another library's
namespace: the canonical case is the kernel's `crypto_aead_<verb>` verbs
vs libsodium's `crypto_aead_<alg>_<verb>` names (see kernel-crypto.json).

Keep prefixes as tight as the API design allows. `EVP_Digest` (verb
surface) is right; `EVP_` (everything, including context management)
is not — the inventory enumerates primitive *use*, not object lifecycle.

## What does NOT belong here

* libc RNG (`rand`, `random`, `*rand48`...) — universal vocabulary,
  stays hardcoded in `crypto_calls.cocci` per the operator policy.
* Project-specific wrappers — those are learned by the study loop
  (DomainVocabulary), not shipped as data.

## Equivalence pin

`packages/source_intel/tests/test_crypto_calls.py` pins byte-identical
`crypto_inventory` output on a fixture corpus containing the full
pre-migration 174-name catalog
(`tests/fixtures/crypto_equivalence/`). Editing a pack such that a
legacy name is lost will fail that pin; pure additions will not.
