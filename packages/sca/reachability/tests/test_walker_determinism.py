"""Walk order must be stable across hosts/filesystems.

Raw ``os.walk`` order is readdir-dependent; unsorted walks made the
capped reachability evidence lists differ between runs of the same
tree, churning corpus refresh diffs.
"""

from __future__ import annotations

from pathlib import Path

from packages.sca.reachability._walker import walk_source_files


def test_walk_returns_lexicographic_order(tmp_path: Path) -> None:
    for rel in (
        "zeta/mod.go", "zeta/alpha.go", "alpha/z.go", "alpha/a.go",
        "beta.go", "aardvark.go",
    ):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("package x\n")
    files = [
        str(path.relative_to(tmp_path))
        for path, _suffix in walk_source_files(tmp_path)
    ]
    assert files == [
        "aardvark.go", "beta.go",
        "alpha/a.go", "alpha/z.go",
        "zeta/alpha.go", "zeta/mod.go",
    ]


def test_nonexistent_target_is_not_cached(tmp_path: Path) -> None:
    """``os.walk`` is lazy and swallows scandir errors, so a
    nonexistent target used to yield an empty walk that was then
    CACHED — a target created later in the process stayed pinned
    empty. The miss must not be memoised."""
    from packages.sca.reachability._walker import walk_source_files
    target = tmp_path / "appears-later"
    assert walk_source_files(target) == ()
    target.mkdir()
    (target / "main.go").write_text("package main\n", encoding="utf-8")
    files = [p.name for p, _ in walk_source_files(target)]
    assert files == ["main.go"]


def test_scan_resets_the_walk_memo(tmp_path: Path) -> None:
    """The walk memo is per-scan: a long-lived process re-scanning
    the same target must see files added between scans."""
    from packages.sca.models import Confidence, Dependency, PinStyle
    from packages.sca.reachability import scan

    def _dep(name: str) -> Dependency:
        return Dependency(
            ecosystem="Go", name=name, version="1.0.0",
            declared_in=Path("go.mod"), scope="main",
            is_lockfile=False, pin_style=PinStyle.EXACT, direct=True,
            purl=f"pkg:golang/{name}@1.0.0",
            parser_confidence=Confidence("high", reason="t"),
        )

    target = tmp_path / "proj"
    target.mkdir()
    dep = _dep("example.com/lib")
    first = scan(target, [dep])
    assert first[dep.key()].verdict == "not_reachable"
    (target / "main.go").write_text(
        'package main\n\nimport "example.com/lib"\n', encoding="utf-8",
    )
    second = scan(target, [dep])
    assert second[dep.key()].verdict == "imported"
