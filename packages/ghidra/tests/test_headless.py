"""Tests for the analyzeHeadless wrapper contracts."""


class TestCopyPreparedContract:
    def test_standalone_refuses_existing_destination(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out" / "p.gpr"
        dst.parent.mkdir()
        dst.write_text("pre-placed")
        with pytest.raises(GhidraError, match="already exists"):
            import_enrichments(gpr, tmp_path / "e.json", dst)

    def test_copy_prepared_requires_copy(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out" / "p.gpr"
        dst.parent.mkdir()
        with pytest.raises(GhidraError, match="no working copy"):
            import_enrichments(
                gpr, tmp_path / "e.json", dst, copy_prepared=True,
            )

    def test_name_mismatch_refused(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        with pytest.raises(GhidraError, match="project name"):
            import_enrichments(
                gpr, tmp_path / "e.json", tmp_path / "renamed.gpr",
            )

    def test_preplaced_rep_only_refused(self, tmp_path):
        import pytest
        from packages.ghidra.headless import GhidraError, import_enrichments
        gpr = tmp_path / "p.gpr"
        gpr.write_text("x")
        dst = tmp_path / "out"
        dst.mkdir()
        (dst / "p.rep").mkdir()
        with pytest.raises(GhidraError, match="already exists"):
            import_enrichments(gpr, tmp_path / "e.json", dst / "p.gpr")


class TestCmdLogScrubbing:
    def test_both_running_log_sites_scrub_the_argv(self):
        # The argv embeds project/program names from the hostile
        # project database; both "running:" log sites must route
        # through the terminal sanitiser (drift guard).
        import inspect

        from packages.ghidra import headless
        src = inspect.getsource(headless)
        assert 'logger.info("running: %s", " ".join(cmd))' not in src
        assert src.count('sanitise_for_terminal(" ".join(cmd)') == 2
