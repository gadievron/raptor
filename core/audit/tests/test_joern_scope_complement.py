"""--scope complement → CPG ``scope_exclude_dirs`` derivation.

Fail-safe contract: coverage is always a SUPERSET of the scope; every
normalisation anomaly degrades to () — the full-tree build — never to
an over-exclusion.
"""

from __future__ import annotations

import types
from pathlib import Path

from core.audit.joern_backend import scope_complement_exclude_dirs


def _tree(tmp_path: Path, dirs: list[str]) -> Path:
    target = tmp_path / "repo"
    for d in dirs:
        (target / d).mkdir(parents=True, exist_ok=True)
    return target


class TestComplement:
    def test_root_siblings_excluded(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "mm", "net", "fs"])
        got = scope_complement_exclude_dirs(target, ["ipc", "mm"], target)
        assert got == tuple(sorted(
            [str(target / "net"), str(target / "fs")],
        ))

    def test_string_scope_accepted(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "net"])
        got = scope_complement_exclude_dirs(target, "ipc", target)
        assert got == (str(target / "net"),)

    def test_nested_scope_excludes_per_level(self, tmp_path):
        target = _tree(
            tmp_path, ["drivers/gpu", "drivers/net", "mm"],
        )
        got = scope_complement_exclude_dirs(
            target, ["drivers/gpu"], target,
        )
        assert str(target / "mm") in got
        assert str(target / "drivers" / "net") in got
        assert str(target / "drivers") not in got
        assert str(target / "drivers" / "gpu") not in got

    def test_dot_slash_spelling_normalised(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "net"])
        got = scope_complement_exclude_dirs(target, ["./ipc"], target)
        assert got == (str(target / "net"),)

    def test_file_leaf_scope_keeps_parent_files(self, tmp_path):
        target = _tree(tmp_path, ["engine/sched", "mm"])
        (target / "engine" / "boot.c").write_text("int f;")
        got = scope_complement_exclude_dirs(
            target, ["engine/boot.c"], target,
        )
        # Sibling DIRS of the leaf are excluded; the parent dir (and
        # its files, fork.c included) stays — superset coverage.
        assert str(target / "mm") in got
        assert str(target / "engine" / "sched") in got
        assert str(target / "engine") not in got

    def test_narrowed_root_reanchors_scope(self, tmp_path):
        target = _tree(
            tmp_path, ["common/a", "common/b", "other"],
        )
        narrowed = target / "common"
        got = scope_complement_exclude_dirs(
            narrowed, ["common/a"], target,
        )
        assert got == (str(narrowed / "b"),)

    def test_scope_equal_to_narrowed_root_is_full_subtree(self, tmp_path):
        target = _tree(tmp_path, ["common/a", "common/b"])
        narrowed = target / "common"
        assert scope_complement_exclude_dirs(
            narrowed, ["common"], target,
        ) == ()

    def test_dot_dirs_left_to_shared_rule(self, tmp_path):
        target = _tree(tmp_path, ["ipc", ".git"])
        got = scope_complement_exclude_dirs(target, ["ipc"], target)
        assert got == ()  # .git handled by the shared rule, not here

    def test_symlink_dirs_never_excluded(self, tmp_path):
        target = _tree(tmp_path, ["ipc"])
        outside = tmp_path / "outside"
        outside.mkdir()
        (target / "link").symlink_to(outside)
        got = scope_complement_exclude_dirs(target, ["ipc"], target)
        assert got == ()


class TestComplementFailSafe:
    def test_no_scope_is_empty(self, tmp_path):
        target = _tree(tmp_path, ["ipc"])
        assert scope_complement_exclude_dirs(target, None, target) == ()
        assert scope_complement_exclude_dirs(target, [], target) == ()

    def test_whole_tree_scope_is_empty(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "net"])
        assert scope_complement_exclude_dirs(target, ["."], target) == ()
        assert scope_complement_exclude_dirs(
            target, ["ipc", "."], target) == ()

    def test_absolute_scope_under_target_rebased(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "net"])
        got = scope_complement_exclude_dirs(
            target, [str(target / "ipc")], target,
        )
        assert got == (str(target / "net"),)

    def test_absolute_scope_outside_target_fails_safe(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "net"])
        assert scope_complement_exclude_dirs(
            target, ["/elsewhere/ipc"], target,
        ) == ()

    def test_dotdot_segment_fails_safe(self, tmp_path):
        target = _tree(tmp_path, ["ipc", "net"])
        assert scope_complement_exclude_dirs(
            target, ["ipc/../net"], target,
        ) == ()

    def test_scope_outside_narrowed_root_fails_safe(self, tmp_path):
        target = _tree(tmp_path, ["common/a", "other"])
        narrowed = target / "common"
        assert scope_complement_exclude_dirs(
            narrowed, ["other"], target,
        ) == ()

    def test_missing_root_fails_safe(self, tmp_path):
        target = _tree(tmp_path, ["ipc"])
        assert scope_complement_exclude_dirs(
            target / "gone", ["ipc"], target,
        ) == ()


class TestScopeThreadedToBuild:
    def test_start_joern_server_forwards_scope(self, monkeypatch, tmp_path):
        import core.audit.joern_backend as jb
        import packages.joern.lifecycle as lifecycle

        monkeypatch.setattr(jb, "joern_available",
                            lambda overrides=None: True)
        monkeypatch.setattr(jb, "target_has_c_sources", lambda p: True)
        fake_srv = types.SimpleNamespace(_cpg_loaded=False)
        monkeypatch.setattr(lifecycle, "joern_acquire",
                            lambda tunables: fake_srv)
        monkeypatch.setattr(jb, "install_flow_semantics",
                            lambda *a, **k: 0)
        seen: dict = {}

        def fake_ensure(srv, target_path, tunables=None, exclude_dirs=(),
                        scope_exclude_dirs=(), out_dir=None):
            seen["scope"] = scope_exclude_dirs
            return True

        monkeypatch.setattr(jb, "_ensure_cpg_loaded", fake_ensure)
        scope = (str(tmp_path / "outofscope"),)
        srv = jb.start_joern_server(tmp_path, scope_exclude_dirs=scope)
        assert srv is fake_srv
        assert seen["scope"] == scope

    def test_ensure_cpg_loaded_keys_slot_on_scope(self, monkeypatch, tmp_path):
        import core.audit.joern_backend as jb

        # _ensure_cpg_loaded mkdirs its cache under Path.home() —
        # keep the test's writes inside its own tmp tree.
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

        captured: dict = {}

        def fake_build(target, cache_dir, **kwargs):
            captured.update(kwargs)
            cpg = types.SimpleNamespace(exists=lambda: False)
            return cpg

        import packages.joern.runner as runner
        monkeypatch.setattr(runner, "build_cpg_cached", fake_build)
        srv = types.SimpleNamespace(_cpg_loaded=False)
        scope = (str(tmp_path / "skipme"),)
        ok = jb._ensure_cpg_loaded(
            srv, tmp_path, exclude_dirs=(), scope_exclude_dirs=scope,
        )
        assert ok is False  # fake build "fails"; threading is the point
        assert captured.get("scope_exclude_dirs") == scope

    def test_presweep_identity_changes_with_scope(self, tmp_path):
        import core.audit.joern_backend as jb

        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main() {}")
        skip = target / "skipme"
        skip.mkdir()
        (skip / "b.c").write_text("int f() {}")
        unscoped = jb._presweep_flows_identity(target)
        scoped = jb._presweep_flows_identity(
            target, scope_exclude_dirs=(str(skip),),
        )
        assert unscoped is not None and scoped is not None
        assert unscoped[0] != scoped[0]
        assert unscoped[1] == scoped[1]


class TestRootAliasParity:
    """Parity with the gap selector's root-alias rule: an entry that
    aliases the target root by a path suffix is dropped there (gaps
    then span the whole tree), so the complement must never read it
    as a subdirectory and exclude the reviewed siblings."""

    def test_alias_only_scope_is_whole_tree(self, tmp_path):
        target = tmp_path / "webapp"
        (target / "modules").mkdir(parents=True)
        (target / "server").mkdir()
        assert scope_complement_exclude_dirs(
            target, ["webapp"], target,
        ) == ()

    def test_multi_segment_alias_dropped(self, tmp_path):
        target = tmp_path / "vendor" / "webapp"
        (target / "modules").mkdir(parents=True)
        assert scope_complement_exclude_dirs(
            target, ["vendor/webapp"], target,
        ) == ()

    def test_mixed_list_drops_only_the_alias(self, tmp_path):
        target = tmp_path / "webapp"
        for d in ("modules", "server", "docs"):
            (target / d).mkdir(parents=True)
        got = scope_complement_exclude_dirs(
            target, ["webapp", "modules"], target,
        )
        # The alias drops; the real entry's complement remains.
        assert got == tuple(sorted(
            [str(target / "server"), str(target / "docs")],
        ))

    def test_complement_never_excludes_a_gap_dir(self, tmp_path):
        # The invariant, pinned on the REAL functions: for any scope,
        # every directory compute_gaps selects gaps in stays out of
        # the complement (graph coverage is a superset of the
        # reviewed set).
        from core.audit.gaps import compute_gaps

        target = tmp_path / "webapp"
        for d in ("modules", "server", "docs"):
            (target / d).mkdir(parents=True)
        checklist = {
            "target_path": str(target),
            "files": [
                {
                    "path": f"{d}/{d}.c",
                    "items": [{
                        "name": f"fn_{d}", "kind": "function",
                        "line_start": 1, "line_end": 8,
                    }],
                }
                for d in ("modules", "server", "docs")
            ],
        }
        for scope in (["webapp"], ["modules"], ["webapp", "server"],
                      ["./modules", "docs"], None):
            gaps = compute_gaps(checklist, [], scope=scope)
            excluded = set(scope_complement_exclude_dirs(
                target, scope, target,
            ))
            for gap in gaps:
                gap_dir = str(target / Path(gap["file"]).parts[0])
                assert gap_dir not in excluded, (
                    f"scope={scope}: gap in {gap['file']} but "
                    f"{gap_dir} excluded from the CPG"
                )
            # And the alias-only scope must review ALL three dirs.
            if scope == ["webapp"]:
                assert len(gaps) == 3
                assert excluded == set()
