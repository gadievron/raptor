"""Tests for packages.ghidra.ebpf_capability — the eBPF lifter gate.

Everything here is hermetic: a fake Ghidra install tree under
``tmp_path`` (discovered via ``GHIDRA_INSTALL_DIR`` with PATH lookup
stubbed out) and a monkeypatched record directory. The consult API's
contract under test: ``trusted`` ONLY on a fully passing probe record
for the current install fingerprint; everything else — absent
install, absent module, no record, stale record, corrupt record,
failed features — degrades with a reason and never raises.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from packages.ghidra import ebpf_capability as cap
from packages.ghidra.ebpf_capability import (
    CAPABILITY_KIND,
    CAPABILITY_SCHEMA,
    EbpfLifterCapability,
    TIER_DOWNGRADED,
    TIER_TRUSTED,
    ebpf_lifter_capability,
    ebpf_module_dir,
    evaluate_record,
    ghidra_install_root,
    install_fingerprint,
    load_capability_record,
    record_path,
    save_capability_record,
)


def _make_install(root: Path, *, version: str = "12.1.2",
                  with_module: bool = True) -> Path:
    (root / "support").mkdir(parents=True)
    (root / "support" / "analyzeHeadless").write_text(
        "#!/bin/sh\n", encoding="utf-8")
    ghidra = root / "Ghidra"
    ghidra.mkdir()
    (ghidra / "application.properties").write_text(
        f"application.version={version}\n", encoding="utf-8")
    if with_module:
        lang = ghidra / "Processors" / "eBPF" / "data" / "languages"
        lang.mkdir(parents=True)
        (lang / "eBPF.slaspec").write_text("spec-v1", encoding="utf-8")
        (lang / "eBPF.ldefs").write_text("ldefs", encoding="utf-8")
    return root


@pytest.fixture()
def install(tmp_path, monkeypatch):
    """Fake install discovered via GHIDRA_INSTALL_DIR; records under
    a test-local dir; the host's real analyzeHeadless never leaks in."""
    root = _make_install(tmp_path / "ghidra")
    monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
    monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(root))
    from core.config import RaptorConfig
    monkeypatch.setattr(RaptorConfig, "BASE_OUT_DIR", tmp_path / "out")
    return root


def _record(fingerprint: str, *, feature_pass: bool = True,
            aggregate: bool = True) -> dict:
    return {
        "schema": CAPABILITY_SCHEMA,
        "kind": CAPABILITY_KIND,
        "install_fingerprint": fingerprint,
        "features": {
            "v4_sdiv": {"pass": feature_pass, "object": "sdiv_v4"},
            "v3_jmp32_jeq": {"pass": True, "object": "jmp32_v3"},
        },
        "failed_features": [] if feature_pass else ["v4_sdiv"],
        "pass": aggregate and feature_pass,
    }


class TestDiscovery:
    def test_install_root_via_env(self, install):
        assert ghidra_install_root() == install.resolve()

    def test_install_root_absent(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        assert ghidra_install_root() is None

    def test_env_dir_without_headless_rejected(self, tmp_path,
                                               monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        monkeypatch.setenv("GHIDRA_INSTALL_DIR", str(tmp_path))
        assert ghidra_install_root() is None

    def test_which_resolves_support_parent(self, tmp_path, monkeypatch):
        root = _make_install(tmp_path / "g2")
        headless = root / "support" / "analyzeHeadless"
        monkeypatch.setattr(
            shutil, "which",
            lambda name: str(headless) if name == "analyzeHeadless"
            else None,
        )
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        assert ghidra_install_root() == root.resolve()

    def test_module_dir(self, install):
        module = ebpf_module_dir(install)
        assert module is not None and module.name == "eBPF"

    def test_module_dir_absent(self, tmp_path, monkeypatch):
        root = _make_install(tmp_path / "g3", with_module=False)
        assert ebpf_module_dir(root) is None


class TestFingerprint:
    def test_stable(self, install):
        first = install_fingerprint(install)
        second = install_fingerprint(install)
        assert first is not None and first == second

    def test_module_edit_invalidates(self, install):
        before = install_fingerprint(install)
        spec = (install / "Ghidra" / "Processors" / "eBPF" / "data"
                / "languages" / "eBPF.slaspec")
        spec.write_text("spec-v2", encoding="utf-8")
        after = install_fingerprint(install)
        assert after is not None and after != before

    def test_version_bump_invalidates(self, install):
        before = install_fingerprint(install)
        (install / "Ghidra" / "application.properties").write_text(
            "application.version=12.2\n", encoding="utf-8")
        after = install_fingerprint(install)
        assert after is not None and after != before

    def test_module_absent_unfingerprintable(self, tmp_path,
                                             monkeypatch):
        root = _make_install(tmp_path / "g4", with_module=False)
        assert install_fingerprint(root) is None

    def test_file_count_cap_two_directions(self, install, monkeypatch):
        module = ebpf_module_dir(install)
        existing = sum(1 for p in module.rglob("*") if p.is_file())
        monkeypatch.setattr(cap, "MAX_MODULE_FILES", existing)
        # At the cap: still fingerprintable.
        assert install_fingerprint(install) is not None
        # One past the cap: refused (unfingerprintable, not partial).
        (module / "extra.sinc").write_text("x", encoding="utf-8")
        assert install_fingerprint(install) is None

    def test_file_size_cap_two_directions(self, install, monkeypatch):
        monkeypatch.setattr(cap, "MAX_MODULE_FILE_BYTES", 16)
        module = ebpf_module_dir(install)
        big = module / "data" / "languages" / "big.sinc"
        big.write_bytes(b"a" * 16)  # at the cap: fine
        assert install_fingerprint(install) is not None
        big.write_bytes(b"a" * 17)  # past the cap: refused
        assert install_fingerprint(install) is None


class TestRecordPath:
    def test_valid_fingerprint(self, install):
        fp = install_fingerprint(install)
        path = record_path(fp)
        assert path is not None
        assert path.name == f"ebpf-lifter-{fp[:16]}.json"

    @pytest.mark.parametrize("bad", [
        "", "short", "UPPERCASEHEX00001111", "../../../etc/passwd",
        "a" * 15, "a" * 129, "g" * 64, None, 42,
    ])
    def test_malformed_fingerprint_refused(self, install, bad):
        assert record_path(bad) is None

    def test_save_refuses_missing_fingerprint(self, install):
        with pytest.raises(ValueError):
            save_capability_record({"schema": CAPABILITY_SCHEMA})

    def test_trailing_newline_refused_two_directions(self, install):
        # fullmatch, not match: `$` tolerates one trailing newline,
        # which would let a not-quite-hex value steer path
        # composition. The clean form must still compose.
        clean = "b" * 64
        assert record_path(clean) is not None
        assert record_path(clean + "\n") is None


class TestConsult:
    def test_no_ghidra_downgraded(self, tmp_path, monkeypatch):
        monkeypatch.setattr(shutil, "which", lambda *a, **k: None)
        monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
        result = ebpf_lifter_capability()
        assert result.tier == TIER_DOWNGRADED
        assert not result.trusted
        assert "not found" in result.reason

    def test_no_record_downgraded_names_probe_script(self, install):
        result = ebpf_lifter_capability()
        assert result.tier == TIER_DOWNGRADED
        assert "ebpf-lifter-probe" in result.reason
        assert result.fingerprint == install_fingerprint(install)

    def test_passing_record_trusted(self, install):
        fp = install_fingerprint(install)
        path = save_capability_record(_record(fp))
        assert path.is_file()
        result = ebpf_lifter_capability()
        assert result.tier == TIER_TRUSTED
        assert result.trusted
        assert result.failed_features == ()
        assert result.record_path == str(path)

    def test_failed_feature_downgrades_and_names_it(self, install):
        fp = install_fingerprint(install)
        save_capability_record(_record(fp, feature_pass=False))
        result = ebpf_lifter_capability()
        assert result.tier == TIER_DOWNGRADED
        assert "v4_sdiv" in result.reason
        assert result.failed_features == ("v4_sdiv",)

    def test_upgrade_orphans_record(self, install):
        fp = install_fingerprint(install)
        save_capability_record(_record(fp))
        assert ebpf_lifter_capability().trusted
        spec = (install / "Ghidra" / "Processors" / "eBPF" / "data"
                / "languages" / "eBPF.slaspec")
        spec.write_text("upgraded", encoding="utf-8")
        result = ebpf_lifter_capability()
        assert result.tier == TIER_DOWNGRADED
        assert "ebpf-lifter-probe" in result.reason

    def test_corrupt_record_downgrades_never_raises(self, install):
        fp = install_fingerprint(install)
        path = record_path(fp)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        result = ebpf_lifter_capability()
        assert result.tier == TIER_DOWNGRADED

    def test_record_size_cap_two_directions(self, install, monkeypatch):
        fp = install_fingerprint(install)
        save_capability_record(_record(fp))
        size = record_path(fp).stat().st_size
        # At/above the record's size: loads and grants trust.
        monkeypatch.setattr(cap, "RECORD_MAX_BYTES", size)
        assert ebpf_lifter_capability().tier == TIER_TRUSTED
        # Below it: refused wholesale (downgrade), not partially read.
        monkeypatch.setattr(cap, "RECORD_MAX_BYTES", size - 1)
        assert ebpf_lifter_capability().tier == TIER_DOWNGRADED

    @pytest.mark.parametrize("mutate", [
        lambda r: r.update(schema=CAPABILITY_SCHEMA + 1),
        lambda r: r.update(kind="something-else"),
        lambda r: r.update(install_fingerprint="c" * 64),
    ])
    def test_schema_kind_fingerprint_mismatch(self, install, mutate):
        fp = install_fingerprint(install)
        record = _record(fp)
        mutate(record)
        path = record_path(fp)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record), encoding="utf-8")
        loaded, _ = load_capability_record(fp)
        assert loaded is None
        assert ebpf_lifter_capability().tier == TIER_DOWNGRADED


class TestEvaluateRecord:
    FP = "d" * 64

    def test_empty_feature_matrix_downgrades(self):
        record = _record(self.FP)
        record["features"] = {}
        result = evaluate_record(record, self.FP, None)
        assert result.tier == TIER_DOWNGRADED

    def test_aggregate_true_but_feature_failed_downgrades(self):
        # A stale aggregate must not outvote the per-feature scan.
        record = _record(self.FP, feature_pass=False)
        record["pass"] = True
        result = evaluate_record(record, self.FP, None)
        assert result.tier == TIER_DOWNGRADED
        assert result.failed_features == ("v4_sdiv",)

    def test_features_pass_but_aggregate_false_downgrades(self):
        # The aggregate is the probe's completeness attestation — a
        # truncated matrix with every surviving entry passing must
        # not grant trust.
        record = _record(self.FP)
        record["pass"] = False
        result = evaluate_record(record, self.FP, None)
        assert result.tier == TIER_DOWNGRADED
        assert "aggregate" in result.reason

    def test_non_dict_feature_entry_counts_as_failed(self):
        record = _record(self.FP)
        record["features"]["v4_smod"] = "yes"
        result = evaluate_record(record, self.FP, None)
        assert result.tier == TIER_DOWNGRADED
        assert "v4_smod" in result.failed_features

    def test_full_pass_trusted_with_metadata(self):
        result = evaluate_record(_record(self.FP), self.FP, None)
        assert result.trusted
        meta = result.as_metadata()
        assert meta["tier"] == TIER_TRUSTED
        assert meta["install_fingerprint"] == self.FP
        assert "failed_features" not in meta

    def test_hostile_feature_name_escaped(self):
        # Feature names come from the on-disk record: a name carrying
        # ESC/OSC/bidi bytes must reach the reason, failed_features,
        # and stamp metadata only in escaped form.
        record = _record(self.FP)
        hostile = "v9_\x1b]0;evil\x07_\u202espoof"
        record["features"][hostile] = {"pass": False}
        result = evaluate_record(record, self.FP, None)
        assert result.tier == TIER_DOWNGRADED
        meta = result.as_metadata()
        for text in (result.reason, *result.failed_features,
                     meta["reason"], *meta["failed_features"]):
            assert "\x1b" not in text
            assert "\x07" not in text
            assert "\u202e" not in text
        assert "\\x1b" in result.reason
        assert "\\u202e" in result.reason
        assert any("\\x07" in name for name in meta["failed_features"])

    def test_as_metadata_escapes_raw_fields(self):
        # Belt-and-braces seam: even a capability built with raw text
        # (a future producer that forgot intake escaping) must stamp
        # only escaped metadata.
        raw = EbpfLifterCapability(
            tier=TIER_DOWNGRADED,
            reason="failed: v9_\x1b[31mred",
            failed_features=("v9_\x07bell",),
        )
        meta = raw.as_metadata()
        assert "\x1b" not in meta["reason"]
        assert "\\x1b" in meta["reason"]
        assert meta["failed_features"] == ["v9_\\x07bell"]
