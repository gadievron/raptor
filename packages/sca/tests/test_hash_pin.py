"""Tests for the hash-pin rewriter (GitHub Actions workflow refs)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from packages.sca.hash_pin import hash_pin_workflows


class _FakeProc(subprocess.CompletedProcess):
    def __init__(self, returncode: int, stdout: str = "",
                 stderr: str = "") -> None:
        super().__init__(args=[], returncode=returncode,
                          stdout=stdout, stderr=stderr)


def _patch_ls_remote(monkeypatch, mapping):
    """``mapping`` is ``{(owner_repo, ref): sha}`` — fake ls-remote output."""
    def fake_run(cmd, **kwargs):
        if cmd[:2] != ["git", "ls-remote"]:
            return _FakeProc(returncode=1)
        # ``git ls-remote https://github.com/owner/repo.git ref refs/tags/ref refs/heads/ref``
        url = cmd[2]
        # Parse owner/repo from URL.
        slug = url.replace("https://github.com/", "").replace(
            ".git", "")
        if "@github.com/" in url:
            slug = url.split("@github.com/", 1)[1].replace(".git", "")
        ref = cmd[3] if len(cmd) >= 4 else ""
        sha = mapping.get((slug, ref))
        if sha is None:
            return _FakeProc(returncode=0, stdout="")
        return _FakeProc(returncode=0,
                          stdout=f"{sha}\trefs/tags/{ref}\n")
    monkeypatch.setattr(subprocess, "run", fake_run)


def test_pins_uses_ref_to_sha(monkeypatch, tmp_path: Path) -> None:
    """``actions/checkout@v4`` resolves to a SHA and gets rewritten."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-node@v3\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/checkout", "v4"): "0" * 40,
        ("actions/setup-node", "v3"): "1" * 40,
    })
    result = hash_pin_workflows(tmp_path, write=True)
    assert len(result.changes) == 2
    assert (workflows / "ci.yml").read_text().count("@" + "0" * 40) == 1
    assert (workflows / "ci.yml").read_text().count("@" + "1" * 40) == 1
    # Original ref preserved as comment.
    assert "# was v4" in (workflows / "ci.yml").read_text()


def test_already_sha_skipped(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    sha = "abcdef" + "0" * 34
    (workflows / "ci.yml").write_text(
        f"jobs:\n  t:\n    steps:\n      - uses: actions/checkout@{sha}\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {})
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []


def test_unresolvable_ref_skipped(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: nonexistent/action@v99\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {})  # no entries → empty stdout
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []
    assert len(result.skipped) == 1


def test_dry_run_does_not_write(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    body = "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n"
    (workflows / "ci.yml").write_text(body, encoding="utf-8")
    _patch_ls_remote(monkeypatch, {("actions/checkout", "v4"): "a" * 40})
    result = hash_pin_workflows(tmp_path, write=False)
    assert len(result.changes) == 1                         # plan computed
    # File untouched.
    assert (workflows / "ci.yml").read_text() == body


def test_local_action_skipped(monkeypatch, tmp_path: Path) -> None:
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - uses: ./.github/actions/local\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {})
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []
    assert result.skipped == []                             # not a candidate


def test_subpath_action(monkeypatch, tmp_path: Path) -> None:
    """``org/action/sub@ref`` — subpath preserved through the rewrite."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/cache/restore@v3\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/cache", "v3"): "c" * 40,
    })
    result = hash_pin_workflows(tmp_path, write=True)
    assert len(result.changes) == 1
    text = (workflows / "ci.yml").read_text()
    assert f"actions/cache/restore@{'c' * 40}" in text


def test_no_workflows_dir(tmp_path: Path) -> None:
    result = hash_pin_workflows(tmp_path)
    assert result.changes == []
    assert result.skipped == []


# ---------------------------------------------------------------------------
# Indentation preservation — pre-fix bug ate everything but one char of
# the leading whitespace, breaking YAML when ``uses:`` was on its own line
# under a multi-line list item (``- name: Checkout`` then
# ``        uses: actions/checkout@v6``).
# ---------------------------------------------------------------------------


def test_preserves_multi_space_indentation(monkeypatch, tmp_path: Path) -> None:
    """``uses:`` on its own line under a list-item header — the
    pre-fix regex captured only 1 char of leading whitespace and
    the rewrite collapsed the indent."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    yml = workflows / "ci.yml"
    yml.write_text(
        "jobs:\n"
        "  t:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v6\n"
        "      - name: Set up Python\n"
        "        uses: actions/setup-python@v6\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/checkout", "v6"): "0" * 40,
        ("actions/setup-python", "v6"): "1" * 40,
    })
    hash_pin_workflows(tmp_path, write=True)
    text = yml.read_text()
    # 8-space indent preserved on every uses: line.
    for line in text.splitlines():
        if "uses:" in line and "actions/" in line:
            assert line.startswith("        uses:"), (
                f"indent collapsed: {line!r}"
            )
    # YAML still parses.
    import yaml
    parsed = yaml.safe_load(text)
    assert parsed["jobs"]["t"]["steps"][0]["uses"].startswith(
        "actions/checkout@"
    )
    assert parsed["jobs"]["t"]["steps"][1]["uses"].startswith(
        "actions/setup-python@"
    )


def test_preserves_indentation_for_dash_uses_form(
    monkeypatch, tmp_path: Path,
) -> None:
    """``- uses: ...`` form (list-item-and-uses-on-same-line) also
    preserves the line's leading indent, however many spaces it
    has."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    yml = workflows / "ci.yml"
    yml.write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@v6\n",     # 6-space indent
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/checkout", "v6"): "a" * 40,
    })
    hash_pin_workflows(tmp_path, write=True)
    text = yml.read_text()
    assert "      - uses:" in text, f"6-space indent + dash lost: {text!r}"
    import yaml
    yaml.safe_load(text)              # must still parse


def test_preserves_indentation_for_tabs(
    monkeypatch, tmp_path: Path,
) -> None:
    """Some YAML files use tabs (technically forbidden by spec but
    GitHub Actions accepts mixed tab+space indent in the wild).
    Defensive: don't break tab-indented files even though we
    don't recommend them."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    yml = workflows / "ci.yml"
    # 2-space + tab indent.
    yml.write_text(
        "jobs:\n  t:\n    steps:\n"
        "  \t- uses: actions/checkout@v6\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/checkout", "v6"): "a" * 40,
    })
    hash_pin_workflows(tmp_path, write=True)
    text = yml.read_text()
    # Indent (2 spaces + tab) preserved.
    assert "  \t- uses:" in text, f"tab indent lost: {text!r}"


def test_pinned_yaml_stays_parseable_round_trip(
    monkeypatch, tmp_path: Path,
) -> None:
    """A workflow that parsed before hash-pinning must still parse
    after. End-to-end gate against the regex bug class — any
    future change to the rewrite logic that breaks YAML structure
    fails this test."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    yml = workflows / "ci.yml"
    yml.write_text(
        "name: Test\n"
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - name: Checkout\n"
        "        uses: actions/checkout@v6\n"
        "      - name: Setup\n"
        "        uses: actions/setup-python@v6\n"
        "        with:\n"
        "          python-version: '3.12'\n"
        "      - name: Run tests\n"
        "        run: pytest\n",
        encoding="utf-8",
    )
    _patch_ls_remote(monkeypatch, {
        ("actions/checkout", "v6"): "0" * 40,
        ("actions/setup-python", "v6"): "1" * 40,
    })
    hash_pin_workflows(tmp_path, write=True)
    import yaml
    parsed = yaml.safe_load(yml.read_text())
    # Structure intact.
    assert parsed["name"] == "Test"
    assert parsed["jobs"]["build"]["runs-on"] == "ubuntu-latest"
    steps = parsed["jobs"]["build"]["steps"]
    assert len(steps) == 3
    assert steps[0]["name"] == "Checkout"
    assert steps[1]["with"]["python-version"] == "3.12"
    assert steps[2]["run"] == "pytest"
