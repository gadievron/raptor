"""Equivalence differential: front-door consumers vs the retired
build-id-or-hash chain.

THE make-or-break pin for the identity reroute: existing fid stores,
RE-database keys, and both binary caches are keyed on the OLD
implementation's outputs, so for ELF binaries and for the sha256
fallback the rerouted consumers must produce byte-identical anchors
and cache keys. Each ``_old_*`` reference below is a faithful inline
copy of the retired call chain; the differential drives both over
the same inputs and refuses any divergence.

Documented deltas (intended upgrades, asserted explicitly — never
silent): PE/Mach-O identities exist now where the old chain always
hashed, and an ELF with a sub-8-hex build-id note (expressible via
``ld --build-id=0xNN``) previously anchored NOTHING and now
identifies by content hash — no store ever held a key for either
case, so nothing can misjoin.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from core.binary.addrmap import content_anchor, module_anchor
from core.binary.identity import KIND_SHA256, content_identity

BUILD_ID_40 = "fa1544052f2d4bfa87d3d3bfb1b7b9f4aa11c0de"
BUILD_ID_32 = "0123456789abcdef0123456789abcdef"


def _patch_build_id(monkeypatch, value):
    import core.analysis.binary_oracle as oracle
    if isinstance(value, BaseException):
        def probe(_p):
            raise value
        monkeypatch.setattr(oracle, "read_build_id", probe)
    else:
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: value)


# ---------------------------------------------------------------------------
# Faithful copies of the retired implementations
# ---------------------------------------------------------------------------


def _old_content_anchor(binary_path, *, binary_sha256=None):
    """Pre-reroute ``core.binary.addrmap.content_anchor``."""
    build_id = None
    sha = None
    if binary_path is not None:
        path = Path(binary_path)
        if path.is_file():
            from core.sandbox.errors import SandboxSetupError
            try:
                from core.analysis.binary_oracle import read_build_id
                build_id = read_build_id(path)
            except SandboxSetupError:
                build_id = None
            except Exception:  # noqa: BLE001 - reference copy
                build_id = None
            if build_id is None:
                try:
                    from core.hash import sha256_file
                    sha = sha256_file(path)
                except OSError:
                    sha = None
    return module_anchor(
        build_id=build_id,
        binary_sha256=sha or binary_sha256,
    )


def _old_cfg_cache_key(binary_path):
    """Pre-reroute ``packages.binary_analysis.function_cfg._cache_key``."""
    try:
        from core.analysis.binary_oracle import read_build_id
        bid = read_build_id(binary_path)
    except Exception:  # noqa: BLE001 - reference copy
        bid = None
    if isinstance(bid, str) and re.fullmatch(r"[0-9a-fA-F]{8,128}", bid):
        return bid.lower()
    try:
        from core.hash import sha256_file
        sha = sha256_file(binary_path)
    except OSError:
        sha = None
    return f"sha256:{sha}" if sha else None


def _old_edges_cache_key(binary_path):
    """Pre-reroute cache-key derivation of
    ``core.analysis.binary_oracle_edges`` (both call sites:
    ``read_build_id(...) or _content_hash(...)``)."""
    from core.analysis.binary_oracle import read_build_id
    key = read_build_id(binary_path)
    if key:
        return key
    try:
        from core.hash import sha256_file
        return sha256_file(binary_path)
    except OSError:
        return None


def _new_cfg_cache_key(binary_path):
    from packages.binary_analysis.function_cfg import _cache_key
    return _cache_key(binary_path)


def _new_edges_cache_key(binary_path):
    from core.analysis.binary_oracle_edges import _identity_cache_key
    return _identity_cache_key(binary_path)


def _assert_all_equal(path):
    """Old chain and front-door chain agree on every consumer key."""
    assert _old_content_anchor(path) == content_anchor(path)
    assert _old_cfg_cache_key(path) == _new_cfg_cache_key(path)
    assert _old_edges_cache_key(path) == _new_edges_cache_key(path)


# ---------------------------------------------------------------------------
# The differential
# ---------------------------------------------------------------------------


class TestElfEquivalence:
    @pytest.mark.parametrize("bid", [
        BUILD_ID_40,
        BUILD_ID_32,
        "deadbeef",           # 8 hex — the shortest plausible id
        None,                 # ELF without a build-id note
    ])
    def test_elf_outcomes_are_byte_identical(
        self, monkeypatch, tmp_path, bid,
    ):
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF" + b"\x00" * 48)
        _patch_build_id(monkeypatch, bid)
        _assert_all_equal(p)
        if bid:
            assert content_anchor(p) == bid[:16]
            assert _new_cfg_cache_key(p) == bid

    def test_case_normalisation_matches_the_extractor_contract(
        self, monkeypatch, tmp_path,
    ):
        # read_build_id lowercases by contract (its regex match is
        # .lower()ed), so the old chain never saw uppercase at any
        # key surface. The front door pins the same normalisation;
        # the old EDGES reference is exempt from this comparison
        # because a raw uppercase return is unreachable through the
        # real extractor.
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF" + b"\x00" * 48)
        _patch_build_id(monkeypatch, BUILD_ID_40.upper())
        assert _old_content_anchor(p) == content_anchor(p) \
            == BUILD_ID_40[:16]
        assert _old_cfg_cache_key(p) == _new_cfg_cache_key(p) \
            == BUILD_ID_40
        assert _new_edges_cache_key(p) == BUILD_ID_40

    def test_sandbox_refusal_strictly_improves(
        self, monkeypatch, tmp_path,
    ):
        # Old world: only content_anchor NAMED SandboxSetupError
        # (BaseException by design); the cfg and edges key paths
        # crashed straight through their `except Exception` nets.
        # New world: the refusal is absorbed inside the front door's
        # ELF arm and every consumer degrades to the content hash.
        # Pinned as a strict improvement — the anchor leg must stay
        # byte-identical, the crash legs must stay degraded.
        from core.sandbox.errors import SandboxSetupError
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF payload bytes")
        _patch_build_id(
            monkeypatch, SandboxSetupError("refused", "hint"))
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        assert _old_content_anchor(p) == content_anchor(p) == sha[:16]
        with pytest.raises(SandboxSetupError):
            _old_cfg_cache_key(p)
        with pytest.raises(SandboxSetupError):
            _old_edges_cache_key(p)
        assert _new_cfg_cache_key(p) == f"sha256:{sha}"
        assert _new_edges_cache_key(p) == sha

    def test_probe_crash_strictly_improves(self, monkeypatch, tmp_path):
        # Old world: content_anchor and the cfg key netted generic
        # exceptions; the edges key path was a bare call and crashed.
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF payload bytes")
        _patch_build_id(monkeypatch, RuntimeError("boom"))
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        assert _old_content_anchor(p) == content_anchor(p) == sha[:16]
        assert _old_cfg_cache_key(p) == _new_cfg_cache_key(p) \
            == f"sha256:{sha}"
        with pytest.raises(RuntimeError):
            _old_edges_cache_key(p)
        assert _new_edges_cache_key(p) == sha

    @pytest.mark.parametrize("bad_bid", [
        "1234",          # sub-8 hex (ld --build-id=0x1234)
        "12",            # single-byte id
        "a" * 129,       # oversize: past the 128-hex plausibility cap
    ])
    def test_documented_delta_implausible_length_build_id(
        self, monkeypatch, tmp_path, bad_bid,
    ):
        # The ONE anchor divergence, pinned so it can never widen
        # silently — and pinned for BOTH implausible directions
        # (too short AND too long): the old chain anchored NOTHING
        # (module_anchor rejects outside 8-128 hex and the sha
        # fallback never ran because a build-id WAS returned); the
        # front door identifies by content hash. No store held a key
        # for such a module, so nothing can misjoin. The old EDGES
        # key was the raw implausible id, which the downstream
        # 8-128-hex path validator rejected — no cache entry ever
        # existed under it either.
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF odd id")
        _patch_build_id(monkeypatch, bad_bid)
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        assert _old_content_anchor(p) is None
        assert content_anchor(p) == sha[:16]
        assert _old_cfg_cache_key(p) == _new_cfg_cache_key(p) \
            == f"sha256:{sha}"
        assert _old_edges_cache_key(p) == bad_bid
        from core.analysis.binary_oracle_edges import _cache_path_for
        assert _cache_path_for(bad_bid) is None
        assert _new_edges_cache_key(p) == sha

    def test_documented_delta_caller_digest_with_implausible_bid(
        self, monkeypatch, tmp_path,
    ):
        # Corollary of the same divergence through the binary_sha256
        # kwarg: the old chain fell PAST the file to the
        # caller-supplied digest (the sha fallback never ran, so the
        # kwarg was next in line); the front door identifies the
        # readable file by its own hash and the kwarg never applies.
        # No live call site passes the kwarg together with a
        # readable implausible-build-id ELF — pinned so the
        # divergence stays documented, not accidental.
        p = tmp_path / "t"
        p.write_bytes(b"\x7fELF odd id")
        _patch_build_id(monkeypatch, "1234")
        sha = hashlib.sha256(p.read_bytes()).hexdigest()
        assert _old_content_anchor(p, binary_sha256="cd" * 32) \
            == "cd" * 8
        assert content_anchor(p, binary_sha256="cd" * 32) == sha[:16]


class TestSha256FallbackEquivalence:
    @pytest.mark.parametrize("data", [
        b"#!/bin/sh\necho hi\n",         # script
        b"",                              # empty file
        b"\x00" * 128,                    # zero blob
        bytes(range(256)),                # binary junk
        b"MZ" + b"\xff" * 64,            # MZ stub, no PE signature
        b"\xca\xfe\xba\xbe\x00\x00\x00\x00",  # fat header, no slices
    ])
    def test_non_identifiable_files_are_byte_identical(
        self, monkeypatch, tmp_path, data,
    ):
        # Faithful old-world behaviour: readelf over non-ELF bytes
        # found no Build ID line.
        _patch_build_id(monkeypatch, None)
        p = tmp_path / "t"
        p.write_bytes(data)
        _assert_all_equal(p)
        sha = hashlib.sha256(data).hexdigest()
        assert content_anchor(p) == sha[:16]
        assert _new_cfg_cache_key(p) == f"sha256:{sha}"
        assert _new_edges_cache_key(p) == sha

    def test_absent_path_is_byte_identical(self, tmp_path):
        missing = tmp_path / "missing"
        assert _old_content_anchor(missing) == content_anchor(missing) \
            is None
        assert _old_content_anchor(missing, binary_sha256="cd" * 32) \
            == content_anchor(missing, binary_sha256="cd" * 32) \
            == "cd" * 8


# ---------------------------------------------------------------------------
# The readelf spawn dies on non-ELF inputs at all four consumers
# ---------------------------------------------------------------------------


class TestNoReadelfSpawnOnNonElf:
    """The old chain paid one (always-failing) sandboxed readelf
    spawn per non-ELF file at each consumer; the front door's format
    sniff kills it. The exploding probe proves no consumer can reach
    read_build_id for non-ELF bytes."""

    @pytest.fixture()
    def exploding_probe(self, monkeypatch):
        _patch_build_id(monkeypatch, AssertionError(
            "readelf probe spawned on a non-ELF target"))

    def _non_elf(self, tmp_path):
        p = tmp_path / "t.exe"
        p.write_bytes(b"MZ" + b"\x00" * 64)
        return p

    def test_content_anchor(self, exploding_probe, tmp_path):
        p = self._non_elf(tmp_path)
        assert content_anchor(p) == hashlib.sha256(
            p.read_bytes()).hexdigest()[:16]

    def test_function_cfg_cache_key(self, exploding_probe, tmp_path):
        p = self._non_elf(tmp_path)
        assert _new_cfg_cache_key(p).startswith("sha256:")

    def test_edges_cache_key(self, exploding_probe, tmp_path):
        p = self._non_elf(tmp_path)
        assert _new_edges_cache_key(p) == hashlib.sha256(
            p.read_bytes()).hexdigest()

    def test_build_manifest(self, exploding_probe, tmp_path):
        from packages.binary_analysis.manifest import build_manifest
        p = self._non_elf(tmp_path)
        manifest = build_manifest(p)
        assert manifest.identity_kind == KIND_SHA256
        assert manifest.build_id == hashlib.sha256(
            p.read_bytes()).hexdigest()

    def test_provenance_probe(self, exploding_probe, tmp_path):
        # Was already ELF-gated pre-reroute; the pin keeps it so now
        # that the block carries identity values for every format.
        from core.analysis.binary_provenance import probe_binary
        p = self._non_elf(tmp_path)
        block = probe_binary(p)
        assert block["probe"] == "not_elf"
        assert block["identity_kind"] == KIND_SHA256


# ---------------------------------------------------------------------------
# Live toolchain differential (skipped where cc is unavailable)
# ---------------------------------------------------------------------------


class TestLiveToolchainDifferential:
    def test_real_elf_agrees_end_to_end(self, tmp_path):
        cc = shutil.which("cc") or shutil.which("gcc")
        if cc is None:
            pytest.skip("no C compiler on this runner")
        src = tmp_path / "t.c"
        src.write_text("int main(void) { return 0; }\n")
        out = tmp_path / "t"
        proc = subprocess.run(
            [cc, "-g", "-Wl,--build-id=sha1", "-o", str(out), str(src)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            pytest.skip(f"cc failed: {proc.stderr[:200]!r}")
        # No monkeypatching: both chains drive the REAL sandboxed
        # read_build_id. Whatever it yields (a build-id, None on a
        # missing readelf) the outputs must agree byte-for-byte.
        try:
            _assert_all_equal(out)
            ident = content_identity(out)
        except BaseException as exc:  # SandboxSetupError is BaseException
            if type(exc).__name__ == "SandboxSetupError":
                pytest.skip("sandbox refused on this runner")
            raise
        assert ident is not None
        if ident.kind != KIND_SHA256:
            assert ident.kind == "elf_build_id"
            assert re.fullmatch(r"[0-9a-f]{40}", ident.value)
            assert content_anchor(out) == ident.value[:16]
