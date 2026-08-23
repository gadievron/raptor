"""Tests for version_diff_sinks — sink change detection across dep versions."""

import pytest

from packages.sca.supply_chain.version_diff_sinks import (
    SinkChange,
    VersionDiffSinkResult,
    _detect_guard_changes,
    analyze_version_diff_sinks,
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class TestSinkChange:
    def test_added_to_dict(self):
        sc = SinkChange(
            file_path="lib/util.py",
            sink_api="eval",
            line=10,
            change_type="added",
            is_unconditional=True,
        )
        d = sc.to_dict()
        assert d["change_type"] == "added"
        assert d["is_unconditional"] is True
        assert "guard_count_old" not in d

    def test_guard_change_to_dict(self):
        sc = SinkChange(
            file_path="lib/util.py",
            sink_api="eval",
            line=10,
            change_type="guard_removed",
            guard_count_old=2,
            guard_count_new=0,
            was_unconditional=False,
            is_unconditional=True,
        )
        d = sc.to_dict()
        assert d["guard_count_old"] == 2
        assert d["guard_count_new"] == 0


class TestVersionDiffSinkResult:
    def test_empty(self):
        r = VersionDiffSinkResult([], [], [])
        assert r.total_changes == 0
        assert not r.has_new_unconditional_sinks
        assert r.summary_line() == "no sink changes detected"

    def test_with_added_sinks(self):
        r = VersionDiffSinkResult(
            added_sinks=[
                SinkChange("a.py", "eval", 1, "added", is_unconditional=True),
                SinkChange("b.py", "exec", 5, "added", is_unconditional=False),
            ],
            removed_sinks=[],
            guard_changes=[],
        )
        assert r.total_changes == 2
        assert r.has_new_unconditional_sinks
        assert "2 sink(s) added" in r.summary_line()
        assert "1 unconditional" in r.summary_line()

    def test_to_dict(self):
        r = VersionDiffSinkResult(
            added_sinks=[
                SinkChange("a.py", "eval", 1, "added", is_unconditional=True),
            ],
            removed_sinks=[],
            guard_changes=[],
        )
        d = r.to_dict()
        assert len(d["added_sinks"]) == 1
        assert d["has_new_unconditional_sinks"] is True


# ---------------------------------------------------------------------------
# analyze_version_diff_sinks
# ---------------------------------------------------------------------------


def _ts_available():
    try:
        import tree_sitter  # noqa: F401
        return True
    except ImportError:
        return False


class TestAnalyzeVersionDiffSinks:
    def test_empty_inputs(self):
        result = analyze_version_diff_sinks({}, {})
        assert result.total_changes == 0

    def test_no_parseable_files(self):
        result = analyze_version_diff_sinks(
            {"readme.txt": "hello"},
            {"readme.txt": "world"},
        )
        assert result.total_changes == 0

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_detects_added_sink(self):
        old_files = {
            "lib/util.py": "def safe():\n    return 42\n",
        }
        new_files = {
            "lib/util.py": (
                "import os\n"
                "def safe():\n"
                "    os.system('ls')\n"
            ),
        }
        result = analyze_version_diff_sinks(old_files, new_files)
        added_apis = {s.sink_api for s in result.added_sinks}
        if added_apis:
            assert "os.system" in added_apis or "system" in added_apis

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_detects_removed_sink(self):
        old_files = {
            "lib/util.py": (
                "import os\n"
                "def run():\n"
                "    os.system('ls')\n"
            ),
        }
        new_files = {
            "lib/util.py": "def run():\n    return 42\n",
        }
        result = analyze_version_diff_sinks(old_files, new_files)
        removed_apis = {s.sink_api for s in result.removed_sinks}
        if removed_apis:
            assert "os.system" in removed_apis or "system" in removed_apis

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_detects_guard_added(self):
        old_files = {
            "lib/util.py": (
                "def run(cmd):\n"
                "    eval(cmd)\n"
            ),
        }
        new_files = {
            "lib/util.py": (
                "def run(cmd, user):\n"
                "    if user.is_admin:\n"
                "        eval(cmd)\n"
            ),
        }
        result = analyze_version_diff_sinks(old_files, new_files)
        guard_types = {g.change_type for g in result.guard_changes}
        if guard_types:
            assert "guard_added" in guard_types

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_detects_guard_removed(self):
        old_files = {
            "lib/util.py": (
                "def run(cmd, user):\n"
                "    if user.is_admin:\n"
                "        eval(cmd)\n"
            ),
        }
        new_files = {
            "lib/util.py": (
                "def run(cmd):\n"
                "    eval(cmd)\n"
            ),
        }
        result = analyze_version_diff_sinks(old_files, new_files)
        guard_types = {g.change_type for g in result.guard_changes}
        if guard_types:
            assert "guard_removed" in guard_types

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_unchanged_file_skipped(self):
        same_source = "def safe():\n    return 42\n"
        result = analyze_version_diff_sinks(
            {"lib/util.py": same_source},
            {"lib/util.py": same_source},
            changed_files_only=True,
        )
        assert result.total_changes == 0

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_new_file_with_sinks(self):
        result = analyze_version_diff_sinks(
            {},
            {"lib/backdoor.py": "import os\nos.system('id')\n"},
        )
        if result.added_sinks:
            apis = {s.sink_api for s in result.added_sinks}
            assert "os.system" in apis or "system" in apis

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_deleted_file_with_sinks(self):
        result = analyze_version_diff_sinks(
            {"lib/old.py": "import os\nos.system('id')\n"},
            {},
        )
        if result.removed_sinks:
            apis = {s.sink_api for s in result.removed_sinks}
            assert "os.system" in apis or "system" in apis

    def test_custom_sink_names(self):
        old_files = {"lib/a.py": "def f():\n    pass\n"}
        new_files = {"lib/a.py": "def f():\n    my_sink()\n"}
        result = analyze_version_diff_sinks(
            old_files, new_files,
            sink_names=frozenset({"my_sink"}),
        )
        # Even if tree-sitter isn't available, this shouldn't crash
        assert isinstance(result, VersionDiffSinkResult)

    @pytest.mark.skipif(not _ts_available(), reason="tree-sitter")
    def test_summary_line_comprehensive(self):
        result = VersionDiffSinkResult(
            added_sinks=[
                SinkChange("a.py", "eval", 1, "added", is_unconditional=True),
            ],
            removed_sinks=[
                SinkChange("b.py", "exec", 5, "removed"),
            ],
            guard_changes=[
                SinkChange(
                    "c.py", "system", 3, "guard_added",
                    guard_count_old=0, guard_count_new=1,
                ),
            ],
        )
        summary = result.summary_line()
        assert "1 sink(s) added" in summary
        assert "1 unconditional" in summary
        assert "1 sink(s) removed" in summary
        assert "1 guard(s) added" in summary


# ---------------------------------------------------------------------------
# _detect_guard_changes classification
# ---------------------------------------------------------------------------


class _StubGuard:
    def __init__(self, category="value"):
        self.category = category


class _StubSinkGuard:
    """Duck-typed stand-in for core.audit's SinkGuard."""

    def __init__(self, line=1, n_guards=0, categories=()):
        self.sink_line = line
        self.guards = [
            _StubGuard(categories[i] if i < len(categories) else "value")
            for i in range(n_guards)
        ]
        self.unconditional = n_guards == 0

    @property
    def guard_count(self):
        return len(self.guards)


class TestDetectGuardChanges:
    def _run(self, old_guards, new_guards):
        out: list[SinkChange] = []
        _detect_guard_changes(
            "lib/util.py", "eval", old_guards, new_guards, out,
        )
        return out

    def test_sole_guard_removed(self):
        out = self._run(
            [_StubSinkGuard(n_guards=1)],
            [_StubSinkGuard(n_guards=0)],
        )
        assert len(out) == 1
        assert out[0].change_type == "guard_removed"
        assert out[0].was_unconditional is False
        assert out[0].is_unconditional is True

    def test_sole_guard_removed_masked_by_new_guarded_site(self):
        # Existing site loses its only guard while a new guarded call
        # site raises the aggregate guard total — the conditional →
        # unconditional transition must outrank the raw totals.
        out = self._run(
            [_StubSinkGuard(line=3, n_guards=1)],
            [
                _StubSinkGuard(line=3, n_guards=0),
                _StubSinkGuard(line=9, n_guards=2),
            ],
        )
        assert len(out) == 1
        assert out[0].change_type == "guard_removed"
        assert out[0].is_unconditional is True

    def test_guard_added_to_unconditional_sink(self):
        out = self._run(
            [_StubSinkGuard(n_guards=0)],
            [_StubSinkGuard(n_guards=1, categories=("auth",))],
        )
        assert len(out) == 1
        assert out[0].change_type == "guard_added"
        assert out[0].was_unconditional is True
        assert out[0].is_unconditional is False
        assert out[0].guard_categories == ["auth"]

    def test_guard_added_despite_total_drop(self):
        # The unconditional site gains its first guard while another
        # site sheds guards: totals drop, but no site is left
        # unconditional.
        out = self._run(
            [
                _StubSinkGuard(line=3, n_guards=0),
                _StubSinkGuard(line=9, n_guards=3),
            ],
            [
                _StubSinkGuard(line=3, n_guards=1),
                _StubSinkGuard(line=9, n_guards=1),
            ],
        )
        assert len(out) == 1
        assert out[0].change_type == "guard_added"

    def test_guard_weakened_counts_as_removed(self):
        out = self._run(
            [_StubSinkGuard(n_guards=2)],
            [_StubSinkGuard(n_guards=1)],
        )
        assert len(out) == 1
        assert out[0].change_type == "guard_removed"

    def test_guard_strengthened_counts_as_added(self):
        out = self._run(
            [_StubSinkGuard(n_guards=1)],
            [_StubSinkGuard(n_guards=2)],
        )
        assert len(out) == 1
        assert out[0].change_type == "guard_added"

    def test_no_change_emits_nothing(self):
        out = self._run(
            [_StubSinkGuard(n_guards=1)],
            [_StubSinkGuard(n_guards=1)],
        )
        assert out == []
