"""/fuzz env build-on-demand (S5.5).

Ratified rules: fires only for source-tree targets whose build the
operator authorised (project ``build`` marker or explicit flag);
builds AFL-instrumented in the pinned AFL++ image; the campaign runs
from the exported rootfs under sandbox image-rootfs mode — never a
docker fuzz runner, never an unsandboxed fallback. The live path is
covered by the S5.5 smoke (real image build + rootfs afl-fuzz run).
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from packages.fuzzing.env_build import (
    PROVENANCE_FILENAME,
    ROOTFS_DIRNAME,
    env_build_candidate,
    env_build_for_fuzzing,
)


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "main.c").write_text("int main(void){return 0;}\n")
    return repo


def _product(ok=True, rels=("app",), rootfs=None, reason="build_failed"):
    if ok and rootfs is not None:
        for cand in ("usr/local/bin",):
            (rootfs / cand).mkdir(parents=True, exist_ok=True)
        (rootfs / "usr/local/bin/afl-fuzz").write_bytes(b"\x7fELF")
        for rel in rels:
            dest = rootfs / "src" / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(b"\x7fELF")
    return SimpleNamespace(
        ok=ok,
        reason="" if ok else reason,
        detail="" if ok else "boom",
        artifacts={rel: Path(f"/x/{rel}") for rel in rels} if ok else {},
        checksums={rel: "0" * 64 for rel in rels} if ok else {},
        rootfs=rootfs if ok else None,
    )


class TestCandidacy:
    def test_not_a_dir_declines_silently(self, tmp_path):
        f = tmp_path / "file.c"
        f.write_text("int main;")
        ok, why = env_build_candidate(f)
        assert (ok, why) == (False, "")

    def test_no_docker_declines_with_hint(self, tmp_path):
        with patch("shutil.which", return_value=None):
            ok, why = env_build_candidate(_repo(tmp_path))
        assert not ok
        assert "docker" in why

    def test_gate_denied_names_the_marker(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("core.project.trust.resolve_build_execution",
                   return_value=False):
            ok, why = env_build_candidate(_repo(tmp_path))
        assert not ok
        assert "'build' trust marker" in why
        assert "--env-build" in why

    def test_no_command_declines_with_hint(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=None):
            ok, why = env_build_candidate(_repo(tmp_path))
        assert not ok
        assert "build-command" in why

    def test_authorised_with_command_is_candidate(self, tmp_path):
        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")):
            ok, why = env_build_candidate(_repo(tmp_path))
        assert ok and why == ""

    def test_explicit_flag_reaches_the_gate(self, tmp_path):
        seen = {}

        def gate(explicit, **kw):
            seen["explicit"] = explicit
            return bool(explicit)

        with patch("shutil.which", return_value="/usr/bin/docker"), \
             patch("core.project.trust.resolve_build_execution", gate), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")):
            ok, _ = env_build_candidate(_repo(tmp_path), build=True)
        assert ok
        assert seen["explicit"] is True


class TestEnvBuildForFuzzing:
    def test_gate_denied_is_structured(self, tmp_path):
        with patch("core.project.trust.resolve_build_execution",
                   return_value=False):
            res = env_build_for_fuzzing(_repo(tmp_path), tmp_path / "out")
        assert not res.ok
        assert res.reason == "not_authorized"

    def test_success_reports_rootfs_and_in_rootfs_paths(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME

        def fake_build(repo, cmd, **kw):
            assert kw["keep_rootfs"] == rootfs
            assert "aflplusplus" in kw["base_image"]
            assert kw["toolchain"].cc == "afl-clang-fast"
            return _product(rootfs=rootfs, rels=("app", "tools/gen"))

        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "project-setting:default")), \
             patch("core.env.build.containerized_build", fake_build):
            res = env_build_for_fuzzing(_repo(tmp_path), out)
        assert res.ok
        assert res.guessed is False
        assert res.rootfs == rootfs
        assert res.binaries == {"app": "/src/app",
                                "tools/gen": "/src/tools/gen"}
        assert res.afl_fuzz == "/usr/local/bin/afl-fuzz"
        prov = out / PROVENANCE_FILENAME
        assert prov.is_file()
        prov_text = prov.read_text()
        assert '"guessed_build_command": false' in prov_text
        # the extracted host copies outlive the rootfs cleanup — the
        # provenance record is how operators find them
        assert '"host_artifacts"' in prov_text
        assert "/x/app" in prov_text

    def test_detected_command_is_guessed(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build",
                   lambda *a, **kw: _product(rootfs=rootfs)):
            res = env_build_for_fuzzing(_repo(tmp_path), out)
        assert res.ok
        assert res.guessed is True

    def test_build_failure_is_structured(self, tmp_path):
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build",
                   lambda *a, **kw: _product(ok=False)):
            res = env_build_for_fuzzing(_repo(tmp_path), tmp_path / "out")
        assert not res.ok
        assert res.reason == "build_failed"

    def test_missing_afl_fuzz_in_image_declines_and_cleans(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME

        def fake_build(repo, cmd, **kw):
            product = _product(rootfs=rootfs)
            (rootfs / "usr/local/bin/afl-fuzz").unlink()
            return product

        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build", fake_build):
            res = env_build_for_fuzzing(_repo(tmp_path), out)
        assert not res.ok
        assert res.reason == "no_afl_fuzz_in_image"
        assert not rootfs.exists()


class TestRemediations:
    def test_explicit_opt_out_declines_silently(self, tmp_path):
        ok, why = env_build_candidate(_repo(tmp_path), build=False)
        assert (ok, why) == (False, "")

    def test_stale_rootfs_refused(self, tmp_path):
        out = tmp_path / "out"
        (out / ROOTFS_DIRNAME / "src").mkdir(parents=True)
        (out / ROOTFS_DIRNAME / "src" / "old-binary").write_bytes(b"\x7fELF")
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build") as build:
            res = env_build_for_fuzzing(_repo(tmp_path), out)
        build.assert_not_called()
        assert not res.ok
        assert res.reason == "stale_rootfs"
        # the operator's kept tree is untouched
        assert (out / ROOTFS_DIRNAME / "src" / "old-binary").exists()


class TestSanitizerAndCmplog:
    def test_asan_and_cmplog_reach_the_build(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME
        seen = {}

        def fake_build(repo, cmd, **kw):
            seen.update(kw)
            product = _product(rootfs=rootfs)
            twin = rootfs / "src-cmplog" / "app"
            twin.parent.mkdir(parents=True, exist_ok=True)
            twin.write_bytes(b"\x7fELF")
            return product

        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "project-setting:default")), \
             patch("core.env.build.containerized_build", fake_build):
            res = env_build_for_fuzzing(_repo(tmp_path), out,
                                        sanitizer="asan", cmplog=True)
        assert res.ok
        assert seen["run_env"] == {"AFL_USE_ASAN": "1"}
        assert seen["aux_builds"] == {"src-cmplog": {"AFL_LLVM_CMPLOG": "1"}}
        assert res.sanitizer == "asan"
        assert res.cmplog_binaries == {"app": "/src-cmplog/app"}
        prov = (out / PROVENANCE_FILENAME).read_text()
        assert '"sanitizer": "asan"' in prov
        assert "/src-cmplog/app" in prov

    def test_cmplog_twin_missing_degrades(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME
        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build",
                   lambda *a, **kw: _product(rootfs=rootfs)):
            res = env_build_for_fuzzing(_repo(tmp_path), out, cmplog=True)
        assert res.ok
        assert res.cmplog_binaries == {}

    def test_unknown_sanitizer_refused(self, tmp_path):
        res = env_build_for_fuzzing(_repo(tmp_path), tmp_path / "out",
                                    sanitizer="msan")
        assert not res.ok
        assert res.reason == "unsupported_sanitizer"


class TestBrokenAflBlocklist:
    """Known-broken AFL++ builds are refused at the artifact level —
    v5.02c's cmplog+sanitizer silent-false-negative class must never
    run a campaign, regardless of where the image came from."""

    def test_blocklisted_version_refused_and_cleaned(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME

        def fake_build(repo, cmd, **kw):
            product = _product(rootfs=rootfs)
            (rootfs / "usr/local/bin/afl-fuzz").write_bytes(
                b"\x7fELF" + b"afl-fuzz++5.02c\x00")
            return product

        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build", fake_build):
            res = env_build_for_fuzzing(_repo(tmp_path), out)
        assert not res.ok
        assert res.reason == "broken_afl_version"
        assert "++5.02c" in res.detail
        assert "FALSE NEGATIVES" in res.detail.upper() or \
            "false negatives" in res.detail
        assert not rootfs.exists()

    def test_healthy_version_passes(self, tmp_path):
        out = tmp_path / "out"
        out.mkdir()
        rootfs = out / ROOTFS_DIRNAME

        def fake_build(repo, cmd, **kw):
            product = _product(rootfs=rootfs)
            (rootfs / "usr/local/bin/afl-fuzz").write_bytes(
                b"\x7fELF" + b"afl-fuzz++5.03a\x00")
            return product

        with patch("core.project.trust.resolve_build_execution",
                   return_value=True), \
             patch("core.build.resolve.resolve_build_command",
                   return_value=("make", "detected:make")), \
             patch("core.env.build.containerized_build", fake_build):
            res = env_build_for_fuzzing(_repo(tmp_path), out)
        assert res.ok
