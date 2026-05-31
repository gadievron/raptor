"""Tests for the crypto axis — crypto_calls.cocci + CryptoCallEvidence.

Two layers:
  * Unit: the message parser (`_parse_match_to_crypto_call`) — deterministic,
    no spatch. Pins the COCCIRESULT shape, the kind/api enums, the structural
    4-segment split, and rejection of malformed payloads.
  * Real-spatch E2E: gated on spatch availability. Smoke fixture with every
    covered API + kind family fires; out-of-axis APIs (memcpy / strcmp /
    open) do NOT fire.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from packages.source_intel.analyze import (
    CryptoCallEvidence,
    SourceIntelResult,
    _parse_match_to_crypto_call,
    analyze,
)


class _Match:
    """Shape-compatible stand-in for coccinelle.runner.SpatchMatch."""

    def __init__(self, message: str, file: str = "x.c", line: int = 1) -> None:
        self.message = message
        self.file = file
        self.line = line


# --- parser unit tests ----------------------------------------------------


def test_parser_accepts_canonical_message():
    out = _parse_match_to_crypto_call(_Match(
        "crypto:primitive_call:openssl:EVP_EncryptInit_ex",
        file="c.c", line=42,
    ))
    assert out == [CryptoCallEvidence(
        kind="primitive_call", api="openssl", fn="EVP_EncryptInit_ex",
        location=("c.c", 42), enclosing_function=None,
    )]


def test_parser_recognises_every_api():
    apis = ("openssl", "kernel", "libsodium", "libc")
    for api in apis:
        out = _parse_match_to_crypto_call(_Match(
            f"crypto:primitive_call:{api}:some_fn",
        ))
        assert out and out[0].api == api, f"api={api} rejected"


def test_parser_recognises_both_kinds():
    for kind in ("primitive_call", "rng_source"):
        out = _parse_match_to_crypto_call(_Match(
            f"crypto:{kind}:openssl:some_fn",
        ))
        assert out and out[0].kind == kind, f"kind={kind} rejected"


def test_parser_rejects_unknown_kind():
    assert _parse_match_to_crypto_call(_Match(
        "crypto:key_decl:openssl:some_var",
    )) == []


def test_parser_rejects_unknown_api():
    # MbedTLS is deferred — until/unless the cocci adds a `mbedtls` rule,
    # the parser must reject it so a typo doesn't silently leak through.
    assert _parse_match_to_crypto_call(_Match(
        "crypto:primitive_call:mbedtls:mbedtls_aes_setkey_enc",
    )) == []


def test_parser_rejects_truncated_message():
    assert _parse_match_to_crypto_call(_Match(
        "crypto:primitive_call:openssl",
    )) == []


def test_parser_rejects_empty_fn():
    assert _parse_match_to_crypto_call(_Match(
        "crypto:primitive_call:openssl:",
    )) == []


def test_parser_ignores_other_rules():
    # Other rules' COCCIRESULTs must not leak through the dispatch.
    assert _parse_match_to_crypto_call(_Match("lock_site:acquire:spin:spin_lock:&sl")) == []
    assert _parse_match_to_crypto_call(_Match("lsm:security_inode_permission")) == []
    assert _parse_match_to_crypto_call(_Match("alloc_paired:kmalloc:kfree")) == []


def test_crypto_calls_default_empty_on_bare_result():
    r = SourceIntelResult()
    assert r.crypto_calls == ()


# --- real-spatch E2E (skipped in CI; runs locally) ------------------------


_CRYPTO_FIXTURE = """\
#include <stddef.h>
#include <stdint.h>

/* OpenSSL */
int EVP_EncryptInit_ex(void *, void *, void *, const unsigned char *, const unsigned char *);
int EVP_DigestUpdate(void *, const void *, size_t);
void AES_encrypt(const unsigned char *, unsigned char *, const void *);
int  SHA256_Update(void *, const void *, size_t);
int  RAND_bytes(unsigned char *, int);

/* Linux kernel crypto */
void *crypto_alloc_skcipher(const char *, unsigned int, unsigned int);
int   crypto_skcipher_encrypt(void *);
void  get_random_bytes(void *, int);

/* libsodium */
int crypto_secretbox_easy(unsigned char *, const unsigned char *,
                          unsigned long long, const unsigned char *,
                          const unsigned char *);
void randombytes_buf(void *, size_t);

/* libc */
int rand(void);

/* OUT OF AXIS — must NOT fire */
void *memcpy(void *, const void *, size_t);
int   strcmp(const char *, const char *);

int driver(void) {
    unsigned char k[32], iv[16], buf[64];

    EVP_EncryptInit_ex(0, 0, 0, k, iv);
    EVP_DigestUpdate(0, buf, sizeof buf);
    AES_encrypt(buf, buf, k);
    SHA256_Update(0, buf, sizeof buf);
    RAND_bytes(buf, sizeof buf);

    crypto_alloc_skcipher("aes", 0, 0);
    crypto_skcipher_encrypt(0);
    get_random_bytes(buf, sizeof buf);

    crypto_secretbox_easy(buf, buf, sizeof buf, iv, k);
    randombytes_buf(buf, sizeof buf);

    int r = rand();

    memcpy(buf, k, sizeof buf);
    strcmp("a", "b");

    return r;
}
"""


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_crypto_calls_covers_every_api_kind_combination(tmp_path: Path) -> None:
    (tmp_path / "c.c").write_text(_CRYPTO_FIXTURE)
    r = analyze(tmp_path)

    triples = {(c.kind, c.api, c.fn) for c in r.crypto_calls}
    expected = {
        # OpenSSL primitive_call surface
        ("primitive_call", "openssl", "EVP_EncryptInit_ex"),
        ("primitive_call", "openssl", "EVP_DigestUpdate"),
        ("primitive_call", "openssl", "AES_encrypt"),
        ("primitive_call", "openssl", "SHA256_Update"),
        # OpenSSL RNG
        ("rng_source", "openssl", "RAND_bytes"),
        # Kernel primitive_call + RNG
        ("primitive_call", "kernel", "crypto_alloc_skcipher"),
        ("primitive_call", "kernel", "crypto_skcipher_encrypt"),
        ("rng_source", "kernel", "get_random_bytes"),
        # libsodium primitive_call + RNG
        ("primitive_call", "libsodium", "crypto_secretbox_easy"),
        ("rng_source", "libsodium", "randombytes_buf"),
        # libc RNG
        ("rng_source", "libc", "rand"),
    }
    missing = expected - triples
    assert not missing, f"families not captured: {sorted(missing)}"


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_crypto_calls_skips_out_of_axis_apis(tmp_path: Path) -> None:
    # memcpy / strcmp aren't crypto; they belong to other rules (or none).
    # If they appear in crypto_calls, the cocci is too broad.
    (tmp_path / "c.c").write_text(_CRYPTO_FIXTURE)
    r = analyze(tmp_path)

    fns = {c.fn for c in r.crypto_calls}
    assert "memcpy" not in fns
    assert "strcmp" not in fns


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_crypto_calls_carry_enclosing_function(tmp_path: Path) -> None:
    (tmp_path / "c.c").write_text(_CRYPTO_FIXTURE)
    r = analyze(tmp_path)

    # Every site comes from `driver` — no stray attributions.
    fns = {c.enclosing_function for c in r.crypto_calls}
    assert fns == {"driver"}, f"unexpected enclosing functions: {fns}"
