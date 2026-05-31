// crypto_calls.cocci — enumerate cryptographic primitive call sites + RNG
// sources for the Phase B `crypto_inventory` /understand --map section.
//
// NOT a "is this crypto broken" detector — pure enumeration. One
// COCCIRESULT per call:
//
//   crypto:<kind>:<api>:<fn>
//
// kind ∈ primitive_call | rng_source
// api  ∈ openssl | kernel | libsodium | libc
// fn   = the concrete function name matched
//
// Coverage (v1):
//   * OpenSSL — modern EVP_* (Init/Update/Final + key/cipher mgmt),
//     legacy AES_/SHA*_/HMAC_/DES_/RC4_/MD5_/BF_ primitives.
//   * Linux kernel crypto API — crypto_alloc_*, crypto_skcipher_*,
//     crypto_shash_*, crypto_ahash_*, crypto_aead_*.
//   * libsodium — crypto_secretbox_*, crypto_box_*, crypto_sign_*,
//     crypto_aead_*, crypto_auth_*, crypto_pwhash_*.
//   * RNG sources — OpenSSL RAND_bytes/RAND_priv_bytes, libsodium
//     randombytes_buf, Linux getrandom, libc rand/random.
//
// Out of scope (deferred): MbedTLS, Windows BCrypt, Bouncy
// Castle/Java crypto, C++ wrappers (Botan, Crypto++). Add as separate
// rules / axes when target corpus shows demand.
//
// Known limitations (documented for downstream consumers):
//   * Name-only matching. A non-crypto project that defines
//     `int SHA256_Update(state *, void *, size_t)` (rare but possible
//     for educational code or replacements) will fire. Short names
//     like `rand` have HIGH collision risk in pure-userspace code;
//     consumers should disambiguate using surrounding context.
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
// OpenSSL — modern EVP_* surface
// =====================================================================

@evp_calls@
position p;
identifier fn = {
    EVP_EncryptInit, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal,
    EVP_EncryptFinal_ex,
    EVP_DecryptInit, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_DecryptFinal,
    EVP_DecryptFinal_ex,
    EVP_CipherInit, EVP_CipherInit_ex, EVP_CipherUpdate, EVP_CipherFinal,
    EVP_CipherFinal_ex,
    EVP_DigestInit, EVP_DigestInit_ex, EVP_DigestUpdate, EVP_DigestFinal,
    EVP_DigestFinal_ex, EVP_Digest,
    EVP_DigestSignInit, EVP_DigestSignUpdate, EVP_DigestSignFinal,
    EVP_DigestVerifyInit, EVP_DigestVerifyUpdate, EVP_DigestVerifyFinal,
    EVP_PKEY_encrypt, EVP_PKEY_decrypt,
    EVP_PKEY_sign, EVP_PKEY_verify,
    EVP_PKEY_derive,
    HMAC_Init, HMAC_Init_ex, HMAC_Update, HMAC_Final, HMAC
};
@@
fn@p(...)

@script:python depends on evp_calls@
p << evp_calls.p;
fn << evp_calls.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:primitive_call:openssl:" + str(fn),
    }) + "\n")


// =====================================================================
// OpenSSL — legacy / per-algorithm primitives
// =====================================================================

@openssl_legacy@
position p;
identifier fn = {
    AES_encrypt, AES_decrypt, AES_set_encrypt_key, AES_set_decrypt_key,
    AES_cbc_encrypt, AES_ctr128_encrypt, AES_ecb_encrypt, AES_ofb128_encrypt,
    DES_encrypt1, DES_encrypt2, DES_encrypt3, DES_ecb_encrypt,
    DES_ncbc_encrypt, DES_cbc_encrypt, DES_set_key, DES_set_odd_parity,
    RC4, RC4_set_key,
    MD5_Init, MD5_Update, MD5_Final, MD5,
    SHA1_Init, SHA1_Update, SHA1_Final, SHA1,
    SHA224_Init, SHA224_Update, SHA224_Final, SHA224,
    SHA256_Init, SHA256_Update, SHA256_Final, SHA256,
    SHA384_Init, SHA384_Update, SHA384_Final, SHA384,
    SHA512_Init, SHA512_Update, SHA512_Final, SHA512,
    BF_set_key, BF_encrypt, BF_decrypt, BF_cbc_encrypt, BF_ecb_encrypt
};
@@
fn@p(...)

@script:python depends on openssl_legacy@
p << openssl_legacy.p;
fn << openssl_legacy.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:primitive_call:openssl:" + str(fn),
    }) + "\n")


// =====================================================================
// Linux kernel crypto API
// =====================================================================

@kernel_crypto@
position p;
identifier fn = {
    crypto_alloc_skcipher, crypto_alloc_cipher, crypto_alloc_shash,
    crypto_alloc_ahash, crypto_alloc_aead, crypto_alloc_akcipher,
    crypto_alloc_kpp, crypto_alloc_rng,
    crypto_skcipher_encrypt, crypto_skcipher_decrypt,
    crypto_skcipher_setkey,
    crypto_aead_encrypt, crypto_aead_decrypt, crypto_aead_setkey,
    crypto_aead_setauthsize,
    crypto_shash_init, crypto_shash_update, crypto_shash_final,
    crypto_shash_digest, crypto_shash_setkey,
    crypto_ahash_init, crypto_ahash_update, crypto_ahash_final,
    crypto_ahash_digest, crypto_ahash_setkey,
    crypto_akcipher_encrypt, crypto_akcipher_decrypt,
    crypto_akcipher_sign, crypto_akcipher_verify
};
@@
fn@p(...)

@script:python depends on kernel_crypto@
p << kernel_crypto.p;
fn << kernel_crypto.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:primitive_call:kernel:" + str(fn),
    }) + "\n")


// =====================================================================
// libsodium
// =====================================================================

@libsodium_crypto@
position p;
identifier fn = {
    crypto_secretbox, crypto_secretbox_open,
    crypto_secretbox_easy, crypto_secretbox_open_easy,
    crypto_secretbox_detached, crypto_secretbox_open_detached,
    crypto_box, crypto_box_open, crypto_box_easy, crypto_box_open_easy,
    crypto_box_detached, crypto_box_open_detached,
    crypto_box_keypair, crypto_box_seed_keypair,
    crypto_sign, crypto_sign_open, crypto_sign_detached,
    crypto_sign_verify_detached, crypto_sign_keypair,
    crypto_sign_seed_keypair,
    crypto_aead_chacha20poly1305_encrypt,
    crypto_aead_chacha20poly1305_decrypt,
    crypto_aead_chacha20poly1305_ietf_encrypt,
    crypto_aead_chacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_auth, crypto_auth_verify,
    crypto_pwhash, crypto_pwhash_str, crypto_pwhash_str_verify,
    crypto_generichash, crypto_generichash_init, crypto_generichash_update,
    crypto_generichash_final,
    crypto_hash_sha256, crypto_hash_sha512
};
@@
fn@p(...)

@script:python depends on libsodium_crypto@
p << libsodium_crypto.p;
fn << libsodium_crypto.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:primitive_call:libsodium:" + str(fn),
    }) + "\n")


// =====================================================================
// RNG sources — every API consumed for entropy/randomness
// =====================================================================

@openssl_rng@
position p;
identifier fn = {
    RAND_bytes, RAND_priv_bytes, RAND_pseudo_bytes, RAND_seed, RAND_add
};
@@
fn@p(...)

@script:python depends on openssl_rng@
p << openssl_rng.p;
fn << openssl_rng.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:rng_source:openssl:" + str(fn),
    }) + "\n")


@libsodium_rng@
position p;
identifier fn = {
    randombytes_buf, randombytes_buf_deterministic,
    randombytes_random, randombytes_uniform, randombytes
};
@@
fn@p(...)

@script:python depends on libsodium_rng@
p << libsodium_rng.p;
fn << libsodium_rng.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:rng_source:libsodium:" + str(fn),
    }) + "\n")


@kernel_rng@
position p;
identifier fn = {
    get_random_bytes, get_random_u32, get_random_u64,
    get_random_long, prandom_u32, prandom_bytes,
    getrandom
};
@@
fn@p(...)

@script:python depends on kernel_rng@
p << kernel_rng.p;
fn << kernel_rng.fn;
@@
import json, sys
for _p in p:
    sys.stderr.write("COCCIRESULT:" + json.dumps({
        "file": _p.file, "line": int(_p.line),
        "rule": "crypto_calls",
        "message": "crypto:rng_source:kernel:" + str(fn),
    }) + "\n")


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
