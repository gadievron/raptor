"""Tests for the hash-pin rewriter (GitHub Actions workflow refs).

The resolver routes through :func:`core.git.ls_remote` (sandbox +
egress allowlist); tests stub the sandbox spawn seam
``core.sandbox.run_untrusted_networked`` so the real substrate code
(URL validation, argv construction, token-to-env plumbing) stays
exercised while nothing actually spawns.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import core.sandbox
from packages.sca.hash_pin import hash_pin_workflows


class _FakeProc(subprocess.CompletedProcess):
    def __init__(self, returncode: int, stdout: str = "",
                 stderr: str = "") -> None:
        super().__init__(args=[], returncode=returncode,
                          stdout=stdout, stderr=stderr)


def _positional_tail(cmd) -> list:
    """``[url, *patterns]`` — everything after the ``--`` separator."""
    assert "--" in cmd, f"missing -- separator in argv: {cmd}"
    return list(cmd[cmd.index("--") + 1:])


def _patch_ls_remote(monkeypatch, mapping):
    """``mapping`` is ``{(owner_repo, ref): sha}`` — fake ls-remote output."""
    def fake_run(cmd, **kwargs):
        if "ls-remote" not in cmd:
            return _FakeProc(returncode=1)
        # ``git <pins...> ls-remote --heads --tags --
        #   https://github.com/owner/repo.git ref refs/tags/ref
        #   refs/heads/ref``
        tail = _positional_tail(cmd)
        url = tail[0]
        slug = url.replace("https://github.com/", "").replace(
            ".git", "")
        ref = tail[1] if len(tail) >= 2 else ""
        sha = mapping.get((slug, ref))
        if sha is None:
            return _FakeProc(returncode=0, stdout="")
        return _FakeProc(returncode=0,
                          stdout=f"{sha}\trefs/tags/{ref}\n")
    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)


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


# ---------------------------------------------------------------------------
# Regression: tags preferred over branches when both exist
# ---------------------------------------------------------------------------


def test_tag_preferred_over_branch_with_same_ref_name(
    monkeypatch, tmp_path: Path,
) -> None:
    """When ``git ls-remote`` returns both ``refs/tags/v1.0`` and
    ``refs/heads/v1.0`` pointing to different SHAs, the tag SHA must
    be returned.

    Pre-fix: tags and branches had equal precedence (head_lines could
    win depending on output order). After fix: tag_lines are checked
    before head_lines in ``_pick_sha``."""
    from packages.sca.hash_pin import _pick_sha

    tag_sha = "a" * 40
    branch_sha = "b" * 40
    # Simulate git ls-remote refs with branch listed FIRST
    # (adversarial ordering — if branch wins, the bug is alive).
    refs = [
        (branch_sha, "refs/heads/v1.0"),
        (tag_sha, "refs/tags/v1.0"),
    ]
    assert _pick_sha(refs) == tag_sha


def test_tag_preferred_even_when_branch_listed_first(
    monkeypatch, tmp_path: Path,
) -> None:
    """Same as above but verifies end-to-end through the workflow
    rewriter."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@v1.0\n",
        encoding="utf-8",
    )
    tag_sha = "a" * 40
    branch_sha = "b" * 40

    def fake_run(cmd, **kwargs):
        if "ls-remote" not in cmd:
            return _FakeProc(returncode=1)
        return _FakeProc(
            returncode=0,
            stdout=(
                f"{branch_sha}\trefs/heads/v1.0\n"
                f"{tag_sha}\trefs/tags/v1.0\n"
            ),
        )

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)
    result = hash_pin_workflows(tmp_path, write=True)
    assert len(result.changes) == 1
    text = (workflows / "ci.yml").read_text()
    assert f"@{tag_sha}" in text
    assert f"@{branch_sha}" not in text


# ---------------------------------------------------------------------------
# Argument-injection hardening: ``--`` separator + leading-dash rejection
# ---------------------------------------------------------------------------


def test_ls_remote_argv_uses_end_of_options_separator(
    monkeypatch, tmp_path: Path,
) -> None:
    """The ``--`` separator must precede the URL so no component can
    ever be parsed as a git option."""
    seen_cmds = []

    def fake_run(cmd, **kwargs):
        seen_cmds.append(list(cmd))
        return _FakeProc(
            returncode=0, stdout=f"{'a' * 40}\trefs/tags/v4\n")

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    result = hash_pin_workflows(tmp_path, write=False)
    assert len(result.changes) == 1
    assert len(seen_cmds) == 1
    tail = _positional_tail(seen_cmds[0])
    assert tail[0].startswith("https://github.com/")
    assert tail[1:] == ["v4", "refs/tags/v4", "refs/heads/v4"]


def test_leading_dash_ref_rejected_without_subprocess(
    monkeypatch, tmp_path: Path,
) -> None:
    """A ref with a leading dash could be parsed as a git option;
    the resolver must skip it before any subprocess runs."""
    def fake_run(cmd, **kwargs):
        raise AssertionError(
            f"subprocess must not run for dash-prefixed ref: {cmd}")

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)
    monkeypatch.setattr(subprocess, "run", fake_run)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n"
        "      - uses: actions/checkout@-v4\n",
        encoding="utf-8",
    )
    result = hash_pin_workflows(tmp_path, write=True)
    assert result.changes == []
    assert len(result.skipped) == 1


def test_leading_dash_components_rejected_directly(monkeypatch) -> None:
    """``_resolve_sha`` validates owner / repo / ref itself so it
    stays safe for any future caller."""
    from packages.sca.hash_pin import _resolve_sha

    def fake_run(cmd, **kwargs):
        raise AssertionError("subprocess must not run")

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)
    monkeypatch.setattr(subprocess, "run", fake_run)
    assert _resolve_sha("-owner", "repo", "v1", {}, None) is None
    assert _resolve_sha("owner", "-repo", "v1", {}, None) is None
    assert _resolve_sha("owner", "repo", "--upload-pack=x", {}, None) is None


# ---------------------------------------------------------------------------
# Substrate routing: sandbox + egress allowlist + token-off-argv
# ---------------------------------------------------------------------------


def test_bearer_token_never_on_argv(monkeypatch, tmp_path: Path) -> None:
    """The GITHUB_TOKEN credential must never appear on the spawned
    argv — it rides the GIT_CONFIG_* env mechanism. Captures BOTH the
    sandbox seam and bare subprocess.run so a regression to either
    execution path is caught."""
    token = "ghp_c0ffee0000000000000000000000000000"  # noqa: S105
    seen: list[tuple[list, dict]] = []

    def fake_sandbox_run(cmd, **kwargs):
        seen.append((list(cmd), dict(kwargs)))
        return _FakeProc(returncode=0,
                          stdout=f"{'a' * 40}\trefs/tags/v4\n")

    def fake_subprocess_run(cmd, **kwargs):
        seen.append((list(cmd), dict(kwargs)))
        raise AssertionError(
            f"hash_pin must not spawn a bare subprocess: {cmd}")

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked",
                        fake_sandbox_run)
    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    result = hash_pin_workflows(tmp_path, write=False, github_token=token)
    assert len(result.changes) == 1
    assert seen, "no spawn observed — resolver never ran"
    for cmd, _kwargs in seen:
        assert all(token not in str(arg) for arg in cmd), (
            f"bearer token leaked onto argv: {cmd}"
        )
        assert all("extraheader" not in str(arg) for arg in cmd)
    # Token reached git via env, not argv.
    env = seen[0][1]["env"]
    assert env["GIT_CONFIG_KEY_0"] == "http.extraheader"
    assert token in env["GIT_CONFIG_VALUE_0"]


def test_resolver_pins_egress_allowlist_to_github(
    monkeypatch, tmp_path: Path,
) -> None:
    """Every resolve must go through the sandboxed ls_remote with the
    egress proxy allowlist pinned to github.com — ambient-proxy raw
    subprocess execution bypassed the allowlist entirely."""
    seen_kwargs: list[dict] = []

    def fake_run(cmd, **kwargs):
        seen_kwargs.append(dict(kwargs))
        return _FakeProc(returncode=0,
                          stdout=f"{'a' * 40}\trefs/tags/v4\n")

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text(
        "jobs:\n  t:\n    steps:\n      - uses: actions/checkout@v4\n",
        encoding="utf-8",
    )
    result = hash_pin_workflows(tmp_path, write=False)
    assert len(result.changes) == 1
    assert seen_kwargs[0]["proxy_hosts"] == ["github.com"]


def test_disallowed_host_refused(monkeypatch) -> None:
    """A URL whose host is outside the resolver's allowlist is refused
    before any subprocess fires (defence-in-depth; the egress proxy
    would refuse the CONNECT too), and the resolver degrades to
    skip — never an unsandboxed fallback."""
    import pytest

    import core.git
    from packages.sca.hash_pin import _LS_REMOTE_PROXY_HOSTS, _resolve_sha

    def fake_run(cmd, **kwargs):
        raise AssertionError(
            f"no subprocess may run for a disallowed host: {cmd}")

    monkeypatch.setattr(core.sandbox, "run_untrusted_networked", fake_run)
    monkeypatch.setattr(subprocess, "run", fake_run)

    # The resolver constructs github.com URLs by design; prove the
    # underlying gate holds by driving its substrate with a host
    # outside the pinned allowlist.
    with pytest.raises(ValueError, match="not in proxy_hosts"):
        core.git.ls_remote(
            "https://evil.example.com/owner/repo.git",
            proxy_hosts=_LS_REMOTE_PROXY_HOSTS,
        )
    # And the resolver itself never bypasses the substrate: a normal
    # resolve with the spawn seams poisoned must degrade to None
    # (failure), not fall back to a raw subprocess.
    def fake_ls(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(core.git, "ls_remote", fake_ls)
    assert _resolve_sha("owner", "repo", "v4", {}, None) is None
