"""The partition-closure gate must (a) pass on a clean synthetic partition,
and FAIL loudly on every historical hole shape: (b) a small directory shed by
a compressed unit label (unclaimed files), (c) a changed-since-base file
owned by no unit, (d) a dead map token (blanket carry naming a vanished
directory), plus ownership conflicts. Hermetic: file universes come from
--files-from/--changed-from lists under tmp_path; the git-mode test skips
when git is absent and pins its own identity per command."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / ".github" / "scripts" / "review_partition_closure.py"

FILES = [
    "core/parser/lex.py",
    "core/parser/tests/test_lex.py",
    "core/trajectories/store.py",
    "core/trajectories/types.py",
    "libexec/tool-run",
    "test/data/corpus.txt",
    "vendored/kit/skip.py",
]

CLEAN_MAP = """# unit map
U1: core/parser/ core/trajectories/
U2: libexec/ test/
"""


def _fixture(tmp_path: Path, map_text: str = CLEAN_MAP,
             files: list[str] | None = None,
             changed: list[str] | None = None) -> list[str]:
    (tmp_path / "map.txt").write_text(map_text)
    (tmp_path / "files.txt").write_text("\n".join(files or FILES) + "\n")
    args = [
        sys.executable, str(SCRIPT),
        "--map", str(tmp_path / "map.txt"),
        "--files-from", str(tmp_path / "files.txt"),
        "--exclude", "vendored/*",
    ]
    if changed is not None:
        (tmp_path / "changed.txt").write_text("\n".join(changed) + "\n")
        args += ["--changed-from", str(tmp_path / "changed.txt")]
    return args


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, check=False)


def test_clean_partition_passes(tmp_path):
    res = _run(_fixture(tmp_path))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "PARTITION CLEAN" in res.stdout


def test_shed_directory_fails(tmp_path):
    # Hole shape: the compressed unit label loses a small dir's files.
    shed = CLEAN_MAP.replace(" core/trajectories/", "")
    res = _run(_fixture(tmp_path, map_text=shed))
    assert res.returncode == 1
    assert "UNCLAIMED: core/trajectories/store.py" in res.stdout
    assert "UNCLAIMED: core/trajectories/types.py" in res.stdout
    assert "core/trajectories" in res.stdout.split("UNCLAIMED by top-2 dirs")[1]


def test_changed_unclaimed_file_fails(tmp_path):
    # Hole shape: a file changed since the previous review base has no owner.
    shed = CLEAN_MAP.replace(" core/trajectories/", "")
    res = _run(_fixture(tmp_path, map_text=shed,
                        changed=["core/trajectories/store.py"]))
    assert res.returncode == 1
    assert (
        "CHANGED-UNCLAIMED: core/trajectories/store.py changed since base"
        in res.stdout
    )


def test_changed_claimed_files_are_flagged_for_review(tmp_path):
    res = _run(_fixture(
        tmp_path, changed=["core/parser/lex.py", "libexec/tool-run"],
    ))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "REVIEW U1\tcore/parser/lex.py" in res.stdout
    assert "REVIEW U2\tlibexec/tool-run" in res.stdout


def test_changed_deleted_file_is_informational(tmp_path):
    res = _run(_fixture(tmp_path, changed=["core/parser/removed.py"]))
    assert res.returncode == 0, res.stdout + res.stderr
    assert "not in reviewable set" in res.stdout


def test_dead_map_token_fails(tmp_path):
    # A blanket carry enumerating a vanished dir must not pass silently.
    res = _run(_fixture(tmp_path, map_text=CLEAN_MAP + "U3: core/gone/\n"))
    assert res.returncode == 1
    assert "DEAD TOKEN: unit U3 token 'core/gone/'" in res.stdout


def test_multi_claim_fails(tmp_path):
    res = _run(_fixture(
        tmp_path, map_text=CLEAN_MAP + "U3: core/trajectories/store.py\n",
    ))
    assert res.returncode == 1
    assert "MULTI-CLAIMED: core/trajectories/store.py owned by U1, U3" in res.stdout


def test_same_unit_overlap_is_not_a_conflict(tmp_path):
    doubled = CLEAN_MAP + "U1: core/parser/lex.py\n"
    res = _run(_fixture(tmp_path, map_text=doubled))
    assert res.returncode == 0, res.stdout + res.stderr


def test_exclude_removes_subtree_from_universe(tmp_path):
    # vendored/ is excluded in every case above; without the exclude the
    # unclaimed vendored file must fail the gate.
    _fixture(tmp_path)
    res = _run([
        sys.executable, str(SCRIPT),
        "--map", str(tmp_path / "map.txt"),
        "--files-from", str(tmp_path / "files.txt"),
    ])
    assert res.returncode == 1
    assert "UNCLAIMED: vendored/kit/skip.py" in res.stdout


def test_glob_and_exact_tokens(tmp_path):
    map_text = (
        "U1: core/parser/*.py core/parser/tests/*.py core/trajectories/\n"
        "U2: libexec/tool-run test/data/corpus.txt\n"
    )
    res = _run(_fixture(tmp_path, map_text=map_text))
    assert res.returncode == 0, res.stdout + res.stderr


def test_claims_out_writes_ownership_table(tmp_path):
    args = _fixture(tmp_path) + ["--claims-out", str(tmp_path / "claims.tsv")]
    res = _run(args)
    assert res.returncode == 0
    table = (tmp_path / "claims.tsv").read_text()
    assert "core/trajectories/store.py\tU1" in table
    assert "libexec/tool-run\tU2" in table


def test_malformed_map_is_usage_error(tmp_path):
    res = _run(_fixture(tmp_path, map_text="just some words\n"))
    assert res.returncode != 0
    assert "expected 'UNIT: token ...'" in res.stderr


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_git_mode_ls_files_and_changed_since(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
           "-C", str(repo)]
    subprocess.run([*git, "init", "-q"], check=True)
    (repo / "core").mkdir()
    (repo / "core" / "a.py").write_text("a\n")
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "base"], check=True)
    base = subprocess.run([*git, "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    (repo / "orphan").mkdir()
    (repo / "orphan" / "b.py").write_text("b\n")
    subprocess.run([*git, "add", "-A"], check=True)
    subprocess.run([*git, "commit", "-qm", "change"], check=True)

    (tmp_path / "map.txt").write_text("U1: core/\nU2: orphan/\n")
    res = _run([
        sys.executable, str(SCRIPT), "--map", str(tmp_path / "map.txt"),
        "--tree", str(repo), "--changed-since", base,
    ])
    assert res.returncode == 0, res.stdout + res.stderr
    assert "REVIEW U2\torphan/b.py" in res.stdout

    # The drop shape end-to-end: the changed dir falls out of the map.
    (tmp_path / "map.txt").write_text("U1: core/\n")
    res = _run([
        sys.executable, str(SCRIPT), "--map", str(tmp_path / "map.txt"),
        "--tree", str(repo), "--changed-since", base,
    ])
    assert res.returncode == 1
    assert "CHANGED-UNCLAIMED: orphan/b.py" in res.stdout



def test_git_paths_preserve_names_and_changed_ownership(tmp_path, capsys):
    import importlib.util
    import os
    from unittest.mock import patch

    from core.testing.gitrepo import git_run, init_scratch_repo

    spec = importlib.util.spec_from_file_location("partition_gate_under_test", SCRIPT)
    gate = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(gate)
    repo = init_scratch_repo(tmp_path)
    expected = ["core/café.py", "core/line\nname.py", "core/tab\tname.py",
                'core/quote"name.py', "core/space name.py"]
    if os.name == "posix":
        expected.append("core/" + os.fsdecode(b"raw-\xff.py"))
    for rel in expected + ["vendored/café.py"]:
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("before = 1\n")
    git_run(repo, "add", "-A")
    git_run(repo, "commit", "-qm", "base")
    base = git_run(repo, "rev-parse", "HEAD")
    for rel in expected:
        (repo / rel).write_text("after = 2\n")
    unit_map = tmp_path / "map.txt"
    unit_map.write_text("U1: core/\n")
    claims = tmp_path / "claims.tsv"
    args = ["--map", str(unit_map), "--tree", str(repo),
            "--changed-since", base, "--exclude", "vendored/*",
            "--claims-out", str(claims)]
    for quote_path in ("true", "false"):
        git_run(repo, "config", "core.quotePath", quote_path)
        assert set(gate.git_paths(str(repo), "ls-files")) == set(
            expected + ["vendored/café.py"])
        assert set(gate.git_paths(str(repo), "diff", "--name-only", base)) == set(expected)
        assert gate.main(args) == 0
        output = capsys.readouterr().out
        for rel in expected:
            displayed = rel.encode("utf-8", errors="backslashreplace").decode("utf-8")
            assert f"REVIEW U1\t{displayed}" in output
            assert os.fsencode(rel) + b"\tU1\n" in claims.read_bytes()
        assert f"reviewable {len(expected)} (excluded 1)" in output
        unit_map.write_text("U1: core/\nU2: core/*.py\n")
        assert gate.main(args) == 1
        assert "MULTI-CLAIMED:" in capsys.readouterr().out
        unit_map.write_text("U1: core/\n")
    # Removing the directory claim must still fail for changed unusual paths.
    unit_map.write_text("U1: core/space*\n")
    assert gate.main(args) == 1
    assert "CHANGED-UNCLAIMED: core/café.py" in capsys.readouterr().out
