"""Normalized function identity (fid) across the blackbox pipeline.

The manifest carries the module-identity legs (build_id, recorded
image_base); the context map, investigation view, and graph nodes
carry per-record fids. Everything is strictly additive: artifacts
from before these fields load unchanged, and a run whose base was
never recorded mints nothing (fail-closed).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

from packages.binary_analysis.investigation import build_investigation
from packages.binary_analysis.manifest import BinaryManifest, build_manifest
from packages.binary_analysis.pipeline import (
    _saved_context_for_runtime,
    analyse_blackbox_binary,
)
from packages.binary_analysis.radare2_understand import (
    BinaryContextMap,
    FunctionInfo,
)

BUILD_ID = "fa1544052f2d4bfa87d3d3bfb1b7b9f4aa11c0de"
ANCHOR16 = BUILD_ID[:16]


def _write_binary(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    path.chmod(0o755)
    return path


def _elf_ctx(binary: Path) -> BinaryContextMap:
    ctx = BinaryContextMap(
        binary_path=binary,
        arch="x86",
        bits=64,
        binary_format="elf",
        image_base=0x400000,
        image_base_recorded=True,
    )
    main = FunctionInfo(name="main", address=0x401000, size=64,
                        is_entry=True)
    parser = FunctionInfo(name="parse_request", address=0x401100,
                          size=128, calls_dangerous=["strcpy"])
    sink = FunctionInfo(name="sym.imp.strcpy", address=0x402000,
                        size=16, is_imported=True)
    ctx.entry_points = [main]
    ctx.interesting_functions = [main, parser]
    ctx.dangerous_sinks = [sink]
    ctx.imports = ["sym.imp.recv", "sym.imp.strcpy"]
    return ctx


class TestManifestIdentityLegs:
    def test_build_manifest_records_build_id_and_recorded_base(
        self, tmp_path, monkeypatch,
    ):
        import core.analysis.binary_oracle as oracle
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: BUILD_ID)
        binary = _write_binary(tmp_path / "t", b"\x7fELF" + b"\x00" * 64)
        manifest = build_manifest(binary, _elf_ctx(binary))
        assert manifest.build_id == BUILD_ID
        assert manifest.image_base == 0x400000

    def test_unrecorded_base_stays_none(self, tmp_path, monkeypatch):
        import hashlib

        import core.analysis.binary_oracle as oracle
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: None)
        data = b"\x7fELF" + b"\x00" * 64
        binary = _write_binary(tmp_path / "t", data)
        ctx = BinaryContextMap(binary_path=binary, binary_format="elf")
        manifest = build_manifest(binary, ctx)
        # No build-id note: the identity falls to the content hash
        # (build_id populated for every format via the front door).
        assert manifest.build_id == hashlib.sha256(data).hexdigest()
        assert manifest.identity_kind == "sha256"
        # image_base defaults to 0 on the context but was never
        # RECORDED — the manifest must not launder the default.
        assert manifest.image_base is None

    def test_non_elf_never_probes_build_id(self, tmp_path, monkeypatch):
        import hashlib

        import core.analysis.binary_oracle as oracle

        def explode(_p):
            raise AssertionError("readelf probe on a non-ELF target")

        monkeypatch.setattr(oracle, "read_build_id", explode)
        data = b"MZ" + b"\x00" * 64
        binary = _write_binary(tmp_path / "t.exe", data)
        ctx = BinaryContextMap(binary_path=binary, binary_format="pe")
        manifest = build_manifest(binary, ctx)
        # No readelf spawn — but the manifest still identifies the
        # module (an MZ stub with no RSDS record hashes).
        assert manifest.build_id == hashlib.sha256(data).hexdigest()
        assert manifest.identity_kind == "sha256"

    def test_roundtrip(self):
        manifest = BinaryManifest(
            schema_version=1, binary_path="/bin/t",
            binary_sha256="ab" * 32, size_bytes=1, executable=True,
            target_kind="elf-linux", arch="x86", bits=64,
            binary_format="elf", build_id=BUILD_ID,
            image_base=0x400000,
        )
        loaded = BinaryManifest.from_dict(manifest.to_dict())
        assert loaded.build_id == BUILD_ID
        assert loaded.image_base == 0x400000

    def test_old_artifact_loads_with_defaults(self):
        # Pre-field manifests carry neither key.
        old = {
            "schema_version": 1, "binary_path": "/bin/t",
            "binary_sha256": "ab" * 32, "size_bytes": 1,
            "executable": True, "target_kind": "elf-linux",
            "arch": "x86", "bits": 64, "binary_format": "elf",
        }
        loaded = BinaryManifest.from_dict(old)
        assert loaded.build_id == ""
        assert loaded.image_base is None

    def test_serialised_none_base_stays_none(self):
        loaded = BinaryManifest.from_dict({
            "schema_version": 1, "binary_path": "/bin/t",
            "binary_sha256": "ab" * 32, "size_bytes": 1,
            "executable": True, "target_kind": "elf-linux",
            "arch": "x86", "bits": 64, "binary_format": "elf",
            "build_id": "", "image_base": None,
        })
        assert loaded.image_base is None


class TestPipelineFids:
    def _run(self, tmp_path, monkeypatch, *, recorded=True):
        import core.analysis.binary_oracle as oracle
        monkeypatch.setattr(oracle, "read_build_id", lambda _p: BUILD_ID)
        binary = _write_binary(tmp_path / "sample",
                               b"\x7fELF" + b"\x00" * 128)
        out = tmp_path / "out"
        ctx = _elf_ctx(binary)
        if not recorded:
            ctx.image_base_recorded = False
        with patch(
            "packages.binary_analysis.pipeline.analyse_binary_context",
            return_value=ctx,
        ):
            result = analyse_blackbox_binary(binary, out_dir=out)
        return result, out

    def test_context_map_records_carry_fid(self, tmp_path, monkeypatch):
        result, out = self._run(tmp_path, monkeypatch)
        cm = result.context_map
        # Aligned with the manifest identity even when the r2 probe
        # layer never set it — one module, one anchor.
        assert cm["content_anchor"] == ANCHOR16
        assert cm["image_base_recorded"] is True
        fns = {f["name"]: f for f in cm["interesting_functions"]}
        assert fns["main"]["fid"] == f"{ANCHOR16}:0x1000"
        assert fns["parse_request"]["fid"] == f"{ANCHOR16}:0x1100"
        eps = {f["name"]: f for f in cm["entry_points"]}
        assert eps["main"]["fid"] == f"{ANCHOR16}:0x1000"
        sinks = {f["name"]: f for f in cm["sink_details"]}
        assert sinks["sym.imp.strcpy"]["fid"] == f"{ANCHOR16}:0x2000"
        saved = json.loads((out / "binary-context-map.json").read_text())
        assert (
            {f["name"]: f for f in saved["interesting_functions"]}
            ["main"]["fid"] == f"{ANCHOR16}:0x1000"
        )

    def test_unrecorded_base_mints_nothing(self, tmp_path, monkeypatch):
        result, _out = self._run(tmp_path, monkeypatch, recorded=False)
        cm = result.context_map
        for family in ("interesting_functions", "entry_points",
                       "sink_details"):
            for fn in cm[family]:
                assert "fid" not in fn, (family, fn.get("name"))

    def test_graph_function_nodes_carry_fid(self, tmp_path, monkeypatch):
        result, _out = self._run(tmp_path, monkeypatch)
        with sqlite3.connect(result.graph_path) as conn:
            rows = conn.execute(
                "SELECT name, props_json FROM nodes WHERE kind='function'",
            ).fetchall()
        props = {name: json.loads(blob) for name, blob in rows}
        assert props["main"]["fid"] == f"{ANCHOR16}:0x1000"
        # ...and the binary node carries the identity legs.
        with sqlite3.connect(result.graph_path) as conn:
            blob = conn.execute(
                "SELECT props_json FROM nodes WHERE kind='binary'",
            ).fetchone()[0]
        binary_props = json.loads(blob)
        assert binary_props["build_id"] == BUILD_ID
        assert binary_props["image_base"] == 0x400000

    def test_investigation_passthrough(self, tmp_path, monkeypatch):
        result, out = self._run(tmp_path, monkeypatch)
        investigation = build_investigation(result, out)
        surfaces = {
            item["name"]: item
            for item in investigation["ranked_surfaces"]
        }
        assert (
            surfaces["sym.imp.strcpy"]["fid"] == f"{ANCHOR16}:0x2000"
        )


class TestContextMapObjectFids:
    def test_fn_dict_emits_fid_when_anchored(self, tmp_path):
        ctx = _elf_ctx(tmp_path / "t.bin")
        ctx.content_anchor = ANCHOR16
        data = ctx.to_dict()
        fns = {f["name"]: f for f in data["interesting_functions"]}
        assert fns["main"]["fid"] == f"{ANCHOR16}:0x1000"
        assert data["content_anchor"] == ANCHOR16
        assert data["image_base_recorded"] is True

    def test_fn_dict_stays_fid_free_without_anchor(self, tmp_path):
        ctx = _elf_ctx(tmp_path / "t.bin")
        data = ctx.to_dict()
        for fn in data["interesting_functions"]:
            assert "fid" not in fn

    def test_fn_dict_stays_fid_free_when_unrecorded(self, tmp_path):
        ctx = _elf_ctx(tmp_path / "t.bin")
        ctx.content_anchor = ANCHOR16
        ctx.image_base_recorded = False
        data = ctx.to_dict()
        for fn in data["interesting_functions"]:
            assert "fid" not in fn


class TestExtractMetadataRecordedGuard:
    """The live r2 seam records a base ONLY when the ij reply's bin
    block actually carries baddr — a degraded/empty reply recording
    base 0 as a fact minted stable WRONG identities."""

    def _extract(self, tmp_path, payload: str) -> BinaryContextMap:
        from packages.binary_analysis.radare2_understand import (
            BinaryUnderstand,
        )
        bu = BinaryUnderstand.__new__(BinaryUnderstand)
        bu._cmd_deg = lambda *_a, **_k: payload  # type: ignore[method-assign]
        ctx = BinaryContextMap(binary_path=tmp_path / "missing.bin")
        bu._extract_metadata(None, ctx)
        return ctx

    def test_baddr_present_records(self, tmp_path):
        ctx = self._extract(
            tmp_path,
            '{"bin": {"arch": "x86", "bits": 64, "bintype": "elf",'
            ' "baddr": 4194304}}',
        )
        assert ctx.image_base == 0x400000
        assert ctx.image_base_recorded is True

    def test_baddr_zero_still_records(self, tmp_path):
        ctx = self._extract(
            tmp_path,
            '{"bin": {"arch": "x86", "bits": 64, "bintype": "elf",'
            ' "baddr": 0}}',
        )
        assert ctx.image_base == 0
        assert ctx.image_base_recorded is True

    def test_bin_block_without_baddr_records_nothing(self, tmp_path):
        ctx = self._extract(
            tmp_path,
            '{"bin": {"arch": "x86", "bits": 64, "bintype": "elf"}}',
        )
        assert ctx.image_base_recorded is False

    def test_empty_reply_records_nothing(self, tmp_path):
        ctx = self._extract(tmp_path, "{}")
        assert ctx.image_base_recorded is False

    def test_non_dict_bin_records_nothing(self, tmp_path):
        ctx = self._extract(tmp_path, '{"bin": "degraded"}')
        assert ctx.image_base_recorded is False


class TestSavedContextRestore:
    def _manifest(self) -> BinaryManifest:
        return BinaryManifest(
            schema_version=1, binary_path="/bin/t",
            binary_sha256="ab" * 32, size_bytes=1, executable=True,
            target_kind="elf-linux", arch="x86", bits=64,
            binary_format="elf",
        )

    def test_flags_restored(self):
        ctx = _saved_context_for_runtime(self._manifest(), {
            "image_base": "0x400000",
            "image_base_recorded": True,
            "content_anchor": ANCHOR16,
            "interesting_functions": [],
        })
        assert ctx.image_base == 0x400000
        assert ctx.image_base_recorded is True
        assert ctx.content_anchor == ANCHOR16

    def test_legacy_map_stays_unrecorded(self):
        ctx = _saved_context_for_runtime(self._manifest(), {
            "image_base": "0x400000",
            "interesting_functions": [],
        })
        assert ctx.image_base_recorded is False
        assert ctx.content_anchor == ""


class TestContextAnchorAlignment:
    """The context's path-probed anchor must agree with the
    manifest's kind-aware identity anchor — one module, one anchor."""

    def _manifest(self, *, build_id, identity_kind):
        return BinaryManifest(
            schema_version=1, binary_path="/bin/t",
            binary_sha256="ab" * 32, size_bytes=1, executable=True,
            target_kind="macho", arch="arm64", bits=64,
            binary_format="macho", build_id=build_id,
            identity_kind=identity_kind, image_base=0x100000,
        )

    def test_slice_identity_overrides_path_probe(self):
        # Fat Mach-O shape: the path probe saw the whole-file hash;
        # the manifest carries the analysed slice's LC_UUID. Records
        # and manifest-minted fids must share the slice anchor.
        from packages.binary_analysis.pipeline import (
            _align_context_anchor,
            _fid_fragment,
        )
        uuid_hex = bytes(range(16)).hex()
        manifest = self._manifest(
            build_id=uuid_hex, identity_kind="macho_uuid")
        ctx = BinaryContextMap(
            binary_path=Path("/bin/t"),
            image_base=0x100000, image_base_recorded=True,
        )
        ctx.content_anchor = "cd" * 8            # whole-file probe
        _align_context_anchor(ctx, manifest)
        assert ctx.content_anchor == uuid_hex[:16]
        assert _fid_fragment(manifest, 0x100010) == {
            "fid": f"{uuid_hex[:16]}:0x10"}

    def test_no_identity_leaves_probe_alone(self):
        from packages.binary_analysis.pipeline import (
            _align_context_anchor,
        )
        manifest = self._manifest(build_id="", identity_kind="")
        ctx = BinaryContextMap(binary_path=Path("/bin/t"))
        ctx.content_anchor = "cd" * 8
        _align_context_anchor(ctx, manifest)
        assert ctx.content_anchor == "cd" * 8

    def test_elf_alignment_is_a_no_op(self):
        from packages.binary_analysis.pipeline import (
            _align_context_anchor,
        )
        manifest = self._manifest(
            build_id=BUILD_ID, identity_kind="elf_build_id")
        ctx = BinaryContextMap(binary_path=Path("/bin/t"))
        ctx.content_anchor = ANCHOR16       # the same probe result
        _align_context_anchor(ctx, manifest)
        assert ctx.content_anchor == ANCHOR16


class TestIdentityKindCompat:
    """Schema-compat pins for the additive identity_kind field."""

    def test_roundtrip_preserves_identity_kind(self):
        manifest = BinaryManifest(
            schema_version=1, binary_path="/bin/t",
            binary_sha256="ab" * 32, size_bytes=1, executable=True,
            target_kind="pe-exe", arch="x86", bits=64,
            binary_format="pe", build_id="c" * 33,
            identity_kind="pe_guid_age", image_base=0x400000,
        )
        loaded = BinaryManifest.from_dict(manifest.to_dict())
        assert loaded.identity_kind == "pe_guid_age"
        assert loaded.build_id == "c" * 33

    def test_old_reader_shape_tolerates_new_field(self):
        # A record written by THIS schema (identity_kind present,
        # plus a future unknown key) loads through the .get-tolerant
        # from_dict without error — additive fields stay additive.
        record = {
            "schema_version": 1, "binary_path": "/bin/t",
            "binary_sha256": "ab" * 32, "size_bytes": 1,
            "executable": True, "target_kind": "elf-linux",
            "arch": "x86", "bits": 64, "binary_format": "elf",
            "build_id": BUILD_ID, "identity_kind": "elf_build_id",
            "some_future_field": {"nested": True},
        }
        loaded = BinaryManifest.from_dict(record)
        assert loaded.build_id == BUILD_ID
        assert loaded.identity_kind == "elf_build_id"

    def test_new_reader_treats_kind_absent_as_elf_or_unknown(self):
        # Old records (build_id set, kind absent) anchor by the
        # historical prefix rule — never an error, never a refusal.
        from core.binary.addrmap import to_fid
        old = BinaryManifest.from_dict({
            "schema_version": 1, "binary_path": "/bin/t",
            "binary_sha256": "ab" * 32, "size_bytes": 1,
            "executable": True, "target_kind": "elf-linux",
            "arch": "x86", "bits": 64, "binary_format": "elf",
            "build_id": BUILD_ID, "image_base": 0x400000,
        })
        assert old.identity_kind == ""
        assert to_fid(0x401000, old) == f"{ANCHOR16}:0x1000"

    def test_no_reader_assumes_build_id_is_gnu(self):
        # Pin: a non-ELF identity value in build_id (kind sha256)
        # anchors exactly as the legacy empty-build_id + sha256 leg
        # did — byte-identical fids, no GNU/readelf assumption.
        from core.binary.addrmap import to_fid
        sha = "ab" * 32
        legacy = BinaryManifest.from_dict({
            "schema_version": 1, "binary_path": "/bin/t",
            "binary_sha256": sha, "size_bytes": 1,
            "executable": True, "target_kind": "pe-exe",
            "arch": "x86", "bits": 64, "binary_format": "pe",
            "build_id": "", "image_base": 0x400000,
        })
        current = BinaryManifest.from_dict({
            **legacy.to_dict(), "build_id": sha,
            "identity_kind": "sha256",
        })
        assert to_fid(0x401000, legacy) == to_fid(0x401000, current) \
            == f"{sha[:16]}:0x1000"

    def test_pe_kind_manifest_mints_hashed_anchor(self):
        # The keystone hazard: a PE manifest's build_id (canonical
        # GUID+age) must anchor HASHED through every fid chokepoint,
        # never as a value prefix.
        import hashlib

        from core.binary.addrmap import to_fid
        canonical = "a1b2c3d4e5f6071890abcdef012345672a"
        hashed = hashlib.sha256(canonical.encode()).hexdigest()[:16]
        manifest = BinaryManifest.from_dict({
            "schema_version": 1, "binary_path": "/bin/t.exe",
            "binary_sha256": "cd" * 32, "size_bytes": 1,
            "executable": True, "target_kind": "pe-exe",
            "arch": "x86", "bits": 64, "binary_format": "pe",
            "build_id": canonical, "identity_kind": "pe_guid_age",
            "image_base": 0x400000,
        })
        fid = to_fid(0x401000, manifest)
        assert fid == f"{hashed}:0x1000"
        assert fid is not None and not fid.startswith(canonical[:16])
