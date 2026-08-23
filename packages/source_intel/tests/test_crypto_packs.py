"""Tests for the crypto API-pack machinery (WP5 vocab migration).

Three layers:
  * Hermetic pack/renderer unit tests — schema validation, regex
    construction, marker handling. No spatch.
  * Hermetic coverage pin — the shipped packs' compiled matchers must
    cover the full pre-migration 174-name catalog
    (``fixtures/crypto_equivalence/legacy_catalog.json``) with correct
    (api, kind) attribution and no cross-library capture. This is what
    lets the spatch-gated pin below stay meaningful in CI images
    without spatch.
  * Real-spatch equivalence pin — ``crypto_inventory`` byte-identical
    on the fixture corpus that exercises every legacy name plus
    negatives.
"""

from __future__ import annotations

import importlib
import json
import shutil
from pathlib import Path

import pytest

from engine.coccinelle.api_pack_renderer import (
    KindSpec,
    load_packs,
    pack_apis,
    render_text,
)

_CRYPTO_DIR = (
    Path(__file__).resolve().parents[3]
    / "engine" / "coccinelle" / "source_intel" / "crypto"
)
_PACKS_DIR = _CRYPTO_DIR / "packs"
_RULE = _CRYPTO_DIR / "crypto_calls.cocci"
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "crypto_equivalence"


def _load_catalog() -> list[dict]:
    return json.loads(
        (_FIXTURES / "legacy_catalog.json").read_text()
    )["entries"]


# --- pack loading ----------------------------------------------------------


def test_shipped_packs_load():
    packs = load_packs(_PACKS_DIR)
    assert {p.api for p in packs} == {"openssl", "kernel", "libsodium"}


def test_pack_apis_from_shipped_dir():
    assert pack_apis(_PACKS_DIR) == frozenset(
        {"openssl", "kernel", "libsodium"}
    )


def test_missing_pack_dir_yields_no_packs(tmp_path: Path):
    assert load_packs(tmp_path / "nope") == []


def test_malformed_pack_skipped(tmp_path: Path):
    (tmp_path / "bad.json").write_text("{not json")
    (tmp_path / "notdict.json").write_text('["list"]')
    (tmp_path / "ok.json").write_text(json.dumps({
        "api": "mbedtls",
        "kinds": {"primitive_call": {"prefixes": ["mbedtls_aes_"]}},
    }))
    packs = load_packs(tmp_path)
    assert [p.api for p in packs] == ["mbedtls"]


def test_invalid_api_tag_rejected(tmp_path: Path):
    for bad in ("MbedTLS", "mbed tls", "mbed:tls", "", 7):
        (tmp_path / "p.json").write_text(json.dumps({
            "api": bad,
            "kinds": {"k": {"names": ["f"]}},
        }))
        assert load_packs(tmp_path) == [], f"api={bad!r} accepted"


def test_invalid_entries_dropped_valid_kept(tmp_path: Path):
    (tmp_path / "p.json").write_text(json.dumps({
        "api": "x",
        "kinds": {
            "primitive_call": {
                "prefixes": ["good_", "bad prefix", "1leading", ""],
                "names": ["fine", "no|pe"],
            },
            "BAD KIND": {"names": ["f"]},
        },
    }))
    packs = load_packs(tmp_path)
    assert len(packs) == 1
    spec = packs[0].kinds["primitive_call"]
    assert spec.prefixes == ("good_",)
    assert spec.names == ("fine",)
    assert set(packs[0].kinds) == {"primitive_call"}


# --- regex construction ----------------------------------------------------


def test_str_regex_shape():
    spec = KindSpec(prefixes=("AES_",), names=("HMAC",))
    assert spec.str_regex() == "^\\(AES_\\|HMAC$\\)"


def test_python_regex_prefix_and_exact_semantics():
    spec = KindSpec(prefixes=("AES_",), names=("getrandom",))
    rx = spec.python_regex()
    assert rx.match("AES_encrypt")
    assert rx.match("AES_wrap_key")          # future family member
    assert rx.match("getrandom")
    assert not rx.match("getrandom_extra")   # exact names stay exact
    assert not rx.match("XAES_encrypt")      # anchored
    assert not rx.match("aes_encrypt")       # case-sensitive


# --- hermetic coverage pin (full legacy catalog, no spatch) -----------------


def _compiled_shipped():
    return {
        (p.api, kind): spec.python_regex()
        for p in load_packs(_PACKS_DIR)
        for kind, spec in p.kinds.items()
    }


def test_packs_cover_entire_legacy_catalog():
    """Every pre-migration name matches its own (api, kind) matcher."""
    matchers = _compiled_shipped()
    missing = []
    for entry in _load_catalog():
        if entry["api"] == "libc":
            continue  # stays hardcoded in the cocci (universal vocab)
        rx = matchers.get((entry["api"], entry["kind"]))
        if rx is None or not rx.match(entry["fn"]):
            missing.append(entry)
    assert not missing, f"legacy names lost by packs: {missing}"


def test_packs_never_cross_capture():
    """No legacy name matches another library's matcher — the kernel
    crypto_aead_<verb> vs libsodium crypto_aead_<alg>_* split is the
    load-bearing case."""
    matchers = _compiled_shipped()
    wrong = []
    for entry in _load_catalog():
        if entry["api"] == "libc":
            continue
        for (api, kind), rx in matchers.items():
            if api != entry["api"] and rx.match(entry["fn"]):
                wrong.append((entry["fn"], entry["api"], api, kind))
    assert not wrong, f"cross-library capture: {wrong}"


def test_packs_reject_negatives():
    """Out-of-axis names never match any pack matcher."""
    negatives = [
        "memcpy", "strcmp", "sodium_init", "my_rand", "xEVP_Digest",
        # Context management is deliberately out of scope:
        "EVP_CIPHER_CTX_new", "EVP_MD_CTX_free",
    ]
    matchers = _compiled_shipped()
    hits = [
        (n, api, kind)
        for n in negatives
        for (api, kind), rx in matchers.items()
        if rx.match(n)
    ]
    assert not hits, f"negatives captured: {hits}"


def test_libc_names_stay_in_the_cocci():
    """The universal libc RNG list is code, not pack data."""
    text = _RULE.read_text()
    for fn in ("rand", "random", "srand", "srandom",
               "drand48", "lrand48", "mrand48"):
        assert fn in text, fn
    libc_entries = [e for e in _load_catalog() if e["api"] == "libc"]
    assert len(libc_entries) == 7


# --- rendering -------------------------------------------------------------


def test_render_generates_one_block_per_api_kind():
    text = render_text(_RULE)
    assert text is not None
    # 3 packs x 2 kinds = 6 generated script blocks + 1 static libc.
    assert text.count("@script:python") == 7
    for api in ("openssl", "kernel", "libsodium"):
        assert f':{api}:" + str(fn)' in text


def test_unrendered_rule_is_still_valid_input():
    """The marker is a comment; the shipped file must keep parsing (and
    the static libc rule keeps emitting) when rendering is unavailable."""
    text = _RULE.read_text()
    assert "// @api-packs: packs crypto" in text
    assert "COCCIRESULT" in text  # libc block emits without rendering


def test_render_returns_none_without_marker(tmp_path: Path):
    rule = tmp_path / "r.cocci"
    rule.write_text("@r@\nidentifier f;\n@@\nf(...)\n")
    assert render_text(rule) is None


def test_render_leaves_marker_when_packs_missing(tmp_path: Path):
    rule = tmp_path / "r.cocci"
    rule.write_text("// @api-packs: packs crypto\n")
    assert render_text(rule) is None


def test_render_refuses_escaping_pack_dir(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "evil.json").write_text(json.dumps({
        "api": "evil", "kinds": {"k": {"names": ["f"]}},
    }))
    ruledir = tmp_path / "rules"
    ruledir.mkdir()
    rule = ruledir / "r.cocci"
    rule.write_text("// @api-packs: ../outside crypto\n")
    assert render_text(rule) is None


def test_new_library_needs_no_cocci_edit(tmp_path: Path):
    """The WP5 growth path: drop a pack file, get coverage."""
    ruledir = tmp_path / "crypto"
    packdir = ruledir / "packs"
    packdir.mkdir(parents=True)
    (ruledir / "crypto_calls.cocci").write_text(
        _RULE.read_text()  # verbatim shipped rule, no edit
    )
    for src in _PACKS_DIR.glob("*.json"):
        shutil.copyfile(src, packdir / src.name)
    (packdir / "mbedtls.json").write_text(json.dumps({
        "api": "mbedtls",
        "kinds": {"primitive_call": {"prefixes": ["mbedtls_aes_"]}},
    }))
    text = render_text(ruledir / "crypto_calls.cocci")
    assert text is not None
    assert ':mbedtls:" + str(fn)' in text
    assert '"^\\(mbedtls_aes_\\)"' in text


def test_generated_blocks_deterministic():
    assert render_text(_RULE) == render_text(_RULE)


# --- analyze-side integration (hermetic) ------------------------------------

analyze_mod = importlib.import_module("packages.source_intel.analyze")


def test_materialize_skips_axes_without_slots(tmp_path: Path):
    axis = tmp_path / "attrs"
    axis.mkdir()
    (axis / "plain.cocci").write_text("@r@\nidentifier f;\n@@\nf(...)\n")
    eff, handle = analyze_mod._materialize_rules_dir(axis)
    assert eff == axis and handle is None


def test_materialize_renders_slotted_axis():
    eff, handle = analyze_mod._materialize_rules_dir(_CRYPTO_DIR)
    try:
        assert handle is not None
        rendered = (eff / "crypto_calls.cocci").read_text()
        assert rendered.count("@script:python") == 7
    finally:
        if handle is not None:
            handle.cleanup()


def test_axis_dirs_ignore_data_subdirs():
    axes = analyze_mod._axis_dirs(_CRYPTO_DIR.parent)
    names = {a.name for a in axes}
    assert "crypto" in names
    # A flat rules_dir pointed at the crypto axis itself must fall back
    # to flat mode (packs/ has no .cocci and is not an axis).
    assert analyze_mod._axis_dirs(_CRYPTO_DIR) == []


def test_parser_accepts_pack_declared_api_tags():
    apis = analyze_mod._crypto_call_apis()
    assert {"libc", "openssl", "kernel", "libsodium"} <= apis


# --- real-spatch equivalence pin --------------------------------------------


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_crypto_inventory_byte_identical_to_legacy(tmp_path: Path):
    """The WP5 exit criterion: on a corpus exercising every one of the
    174 pre-migration names (plus negatives), the packs+prefix pipeline
    produces byte-identical ``crypto_inventory`` output to the recorded
    enumerated-list rule output."""
    from packages.code_understanding.context_map_sites import (
        build_crypto_inventory,
    )
    from packages.source_intel.analyze import analyze

    shutil.copyfile(_FIXTURES / "corpus.c", tmp_path / "corpus.c")
    result = analyze(tmp_path, rules_dir=_CRYPTO_DIR)
    assert result.skipped_reason is None
    assert result.rules_failed == ()

    sites = []
    for site in build_crypto_inventory(result):
        site = dict(site)
        site["file"] = Path(site["file"]).name
        sites.append(site)
    sites.sort(key=lambda d: json.dumps(d, sort_keys=True))
    got = json.dumps(sites, indent=1, sort_keys=True) + "\n"

    expected = (_FIXTURES / "expected_inventory.json").read_text()
    assert got == expected


@pytest.mark.integration
@pytest.mark.skipif(
    not shutil.which("spatch"), reason="spatch not installed",
)
def test_e2e_rendered_rule_parses(tmp_path: Path):
    """spatch must parse the RENDERED rule (integrity test only sees the
    unrendered file)."""
    import subprocess

    rendered = tmp_path / "rendered.cocci"
    rendered.write_text(render_text(_RULE))
    empty = tmp_path / "empty.c"
    empty.write_text("int main(void) { return 0; }\n")
    proc = subprocess.run(
        ["spatch", "--sp-file", str(rendered), "--very-quiet",
         "--no-includes", str(empty)],
        capture_output=True, text=True, timeout=60, check=False,
    )
    err = (proc.stderr or "") + (proc.stdout or "")
    assert proc.returncode == 0, err[:500]
    assert "parse error" not in err.lower()
