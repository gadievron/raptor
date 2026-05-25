"""Regression test: ``--self-test`` git invocations are sandboxed.

A malicious ``.git/config`` in an untrusted target can RCE via
``core.fsmonitor`` / ``core.sshCommand`` / ``core.gitProxy`` at
git startup time. ``_run_self_test`` reads / writes the target's
.git directory, so every git call MUST route through
``core.sandbox.context.run_untrusted`` — that pins network off,
restricts reads (no $HOME), gives git only the target's ``.git/``
+ a sandbox-owned tempdir as writable surfaces. Same containment
posture as the resolver runners that execute ``./mvnw`` /
``./gradlew`` from untrusted trees.

This test asserts the wiring without spinning up an actual git
checkout: we patch ``run_untrusted`` to a stub that records every
invocation, then check each of the four call sites (stash create,
worktree add, git apply, worktree remove) goes through it with
the required sandbox kwargs.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import List

from packages.sca.harden import _run_self_test


class _FakeProc:
    """Stand-in for ``subprocess.CompletedProcess`` — minimal fields
    consumed by the self-test caller (returncode, stdout, stderr)."""

    def __init__(self, returncode: int = 0, stdout: str = "",
                 stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _make_target(tmp_path: Path) -> Path:
    """Materialise the bare minimum of a "git checkout" the
    self-test pre-flight checks for: a ``.git`` directory."""
    target = tmp_path / "target"
    target.mkdir()
    (target / ".git").mkdir()
    (target / ".git" / "config").write_text(
        # Plausible-looking but inert content; the sandbox is what
        # makes a real malicious .git/config safe — this file is
        # never actually parsed because run_untrusted is mocked.
        "[core]\n  bare = false\n",
    )
    return target


def _make_patch(tmp_path: Path) -> Path:
    """Patch file lives OUTSIDE both the target and the sandbox's
    tempdir — the self-test is expected to read it into memory and
    pass via stdin so the sandbox doesn't need read access to
    out_dir."""
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    patch = out_dir / "upgrade.patch"
    patch.write_text(
        "diff --git a/x b/x\nindex 0000000..1111111 100644\n",
    )
    return patch


def test_self_test_routes_git_calls_through_run_untrusted(
    tmp_path: Path, monkeypatch,
):
    target = _make_target(tmp_path)
    patch_path = _make_patch(tmp_path)
    out_dir = tmp_path / "out"

    recorded: List[dict] = []

    def fake_run_untrusted(cmd, **kwargs):
        recorded.append({"cmd": cmd, **kwargs})
        # stash create returns an empty stdout → worktree_ref = HEAD
        if cmd[:3] == ["git", "stash", "create"]:
            return _FakeProc(returncode=0, stdout="", stderr="")
        return _FakeProc(returncode=0)

    # ``plan`` runs after the patch is applied — we don't want it
    # to actually walk a real project. Stub to an empty list.
    def fake_plan(**kwargs):
        return []

    monkeypatch.setattr(
        "core.sandbox.context.run_untrusted", fake_run_untrusted,
    )
    monkeypatch.setattr("packages.sca.harden.plan", fake_plan)

    # ``worktree.exists()`` returns False because we never actually
    # made one — the cleanup path simply skips git worktree remove.
    # Force it to True via a side-channel: create the worktree dir
    # ourselves so the cleanup branch fires.
    real_mkdtemp = __import__("tempfile").mkdtemp

    def mkdtemp_and_seed(*a, **kw):
        path = Path(real_mkdtemp(*a, **kw))
        (path / "wt").mkdir(exist_ok=True)
        return str(path)

    monkeypatch.setattr("tempfile.mkdtemp", mkdtemp_and_seed)

    rc = _run_self_test(
        target=target,
        out_dir=out_dir,
        patch_path=patch_path,
        registries={},
        osv=None, kev=None, epss=None,
        offline=True,
        allow_major=False,
        pin_only=False,
        ecosystem_allowlist=None,
        allow_major_without_review=False,
        allow_degraded=False,
    )

    assert rc == 0, f"self-test should succeed; got rc={rc}"

    # Four git calls expected: stash create, worktree add,
    # git apply, worktree remove.
    cmds = [r["cmd"][:3] for r in recorded]
    assert cmds == [
        ["git", "stash", "create"],
        ["git", "worktree", "add"],
        ["git", "apply", "-"],
        ["git", "worktree", "remove"],
    ], f"expected the four sandboxed git calls; got {cmds}"

    # Every call must hand the sandbox a target, an output tempdir,
    # writable_paths covering only target/.git, and a caller_label
    # for telemetry. ``capture_output`` + ``timeout`` carry through
    # from the original subprocess.run signature.
    target_git = str(target / ".git")
    for r in recorded:
        assert r.get("output"), (
            f"missing output= on {r['cmd']!r}; sandbox needs a "
            f"tempdir to land $HOME / temp files into"
        )
        assert r.get("target"), (
            f"missing target= on {r['cmd']!r}; sandbox engagement "
            f"requires it"
        )
        assert target_git in (r.get("writable_paths") or []), (
            f"writable_paths on {r['cmd']!r} must include "
            f"{target_git!r} so git can update objects / refs"
        )
        assert r.get("caller_label", "").startswith(
            "sca-harden-self-test/"
        ), f"caller_label missing on {r['cmd']!r}"

    # ``git apply -`` should receive the patch via stdin, NOT as a
    # path argument. The sandbox can't read the path (out_dir is
    # outside both target and tmp_root).
    apply_call = [r for r in recorded
                  if r["cmd"][:3] == ["git", "apply", "-"]][0]
    assert apply_call.get("input"), (
        "git apply must receive patch text via input= so the "
        "sandbox doesn't need read access to out_dir"
    )
    assert "diff --git" in apply_call["input"]


def test_self_test_does_not_use_unsandboxed_subprocess_run(
    tmp_path: Path, monkeypatch,
):
    """Defense in depth: monkey-patch ``subprocess.run`` to a
    raising stub. The self-test must NOT touch it — every git
    call routes through ``run_untrusted`` instead. Catches a
    regression where someone reintroduces a plain subprocess.run
    in this function."""
    target = _make_target(tmp_path)
    patch_path = _make_patch(tmp_path)
    out_dir = tmp_path / "out"

    def raising_run(*a, **kw):
        raise AssertionError(
            "subprocess.run() reached from harden self-test path; "
            "must route through core.sandbox.context.run_untrusted"
        )

    def fake_run_untrusted(cmd, **kwargs):
        if cmd[:3] == ["git", "stash", "create"]:
            return _FakeProc(returncode=0, stdout="", stderr="")
        return _FakeProc(returncode=0)

    def fake_plan(**kwargs):
        return []

    real_mkdtemp = __import__("tempfile").mkdtemp

    def mkdtemp_and_seed(*a, **kw):
        path = Path(real_mkdtemp(*a, **kw))
        (path / "wt").mkdir(exist_ok=True)
        return str(path)

    monkeypatch.setattr(
        "core.sandbox.context.run_untrusted", fake_run_untrusted,
    )
    monkeypatch.setattr("packages.sca.harden.plan", fake_plan)
    monkeypatch.setattr("tempfile.mkdtemp", mkdtemp_and_seed)
    monkeypatch.setattr(subprocess, "run", raising_run)

    rc = _run_self_test(
        target=target,
        out_dir=out_dir,
        patch_path=patch_path,
        registries={},
        osv=None, kev=None, epss=None,
        offline=True,
        allow_major=False,
        pin_only=False,
        ecosystem_allowlist=None,
        allow_major_without_review=False,
        allow_degraded=False,
    )
    assert rc == 0


def test_self_test_clean_tree_stash_rc1_is_not_an_error(
    tmp_path: Path, monkeypatch,
):
    """``git stash create`` exits 1 with empty output when the tree is
    clean (nothing to stash) — git's normal signal, and the common case
    on a pristine CI checkout. It must NOT abort the self-test: we fall
    back to HEAD and proceed. Regression for the sca-self-bump CI break
    where ``returncode != 0`` collapsed rc=1 into the failure path."""
    target = _make_target(tmp_path)
    patch_path = _make_patch(tmp_path)
    out_dir = tmp_path / "out"

    recorded: List[dict] = []

    def fake_run_untrusted(cmd, **kwargs):
        recorded.append({"cmd": cmd, **kwargs})
        if cmd[:3] == ["git", "stash", "create"]:
            # Real clean-tree behaviour: rc 1, no stdout, no stderr.
            return _FakeProc(returncode=1, stdout="", stderr="")
        return _FakeProc(returncode=0)

    def fake_plan(**kwargs):
        return []

    real_mkdtemp = __import__("tempfile").mkdtemp

    def mkdtemp_and_seed(*a, **kw):
        path = Path(real_mkdtemp(*a, **kw))
        (path / "wt").mkdir(exist_ok=True)
        return str(path)

    monkeypatch.setattr(
        "core.sandbox.context.run_untrusted", fake_run_untrusted,
    )
    monkeypatch.setattr("packages.sca.harden.plan", fake_plan)
    monkeypatch.setattr("tempfile.mkdtemp", mkdtemp_and_seed)

    rc = _run_self_test(
        target=target,
        out_dir=out_dir,
        patch_path=patch_path,
        registries={},
        osv=None, kev=None, epss=None,
        offline=True,
        allow_major=False,
        pin_only=False,
        ecosystem_allowlist=None,
        allow_major_without_review=False,
        allow_degraded=False,
    )

    assert rc == 0, (
        f"clean-tree `git stash create` rc=1 must be treated as "
        f"'nothing to stash', not a failure; got rc={rc}"
    )
    # No stash ref → the worktree must be created from HEAD.
    wt_add = [r for r in recorded
              if r["cmd"][:3] == ["git", "worktree", "add"]][0]
    assert wt_add["cmd"][-1] == "HEAD", (
        f"clean tree must check out HEAD; got ref {wt_add['cmd'][-1]!r}"
    )


def test_self_test_real_stash_error_still_aborts(
    tmp_path: Path, monkeypatch,
):
    """The rc=1 carve-out is narrow: a genuine ``git stash create``
    failure writes to stderr (and usually exits >1 / by signal), so it
    must STILL abort with rc 6 — real breakage is never swallowed."""
    target = _make_target(tmp_path)
    patch_path = _make_patch(tmp_path)
    out_dir = tmp_path / "out"

    recorded: List[dict] = []

    def fake_run_untrusted(cmd, **kwargs):
        recorded.append({"cmd": cmd, **kwargs})
        if cmd[:3] == ["git", "stash", "create"]:
            return _FakeProc(returncode=128, stdout="",
                             stderr="fatal: not a git repository")
        return _FakeProc(returncode=0)

    def fake_plan(**kwargs):
        return []

    monkeypatch.setattr(
        "core.sandbox.context.run_untrusted", fake_run_untrusted,
    )
    monkeypatch.setattr("packages.sca.harden.plan", fake_plan)

    rc = _run_self_test(
        target=target,
        out_dir=out_dir,
        patch_path=patch_path,
        registries={},
        osv=None, kev=None, epss=None,
        offline=True,
        allow_major=False,
        pin_only=False,
        ecosystem_allowlist=None,
        allow_major_without_review=False,
        allow_degraded=False,
    )

    assert rc == 6, f"real stash error must abort with rc 6; got {rc}"
    # Must stop after the failed stash create — no worktree creation.
    cmds = [r["cmd"][:3] for r in recorded]
    assert cmds == [["git", "stash", "create"]], (
        f"should stop after the failed stash create; got {cmds}"
    )
