"""Host-layout leak scrub for sandboxed children.

A sandboxed child's environment used to reveal the host layout and
identity even when every filesystem layer hid it:

- OLDPWD carried the orchestrator's previous working directory
  (typically the RAPTOR checkout path) through get_safe_env().
- PWD carried the orchestrator's cwd.
- PATH kept home-rooted entries (~/.local/bin, ~/bin) that name the
  operator's home while pointing at directories the sandbox cannot
  read anyway.
- USER/LOGNAME kept the operator's login name even under fake_home,
  where the child is deliberately told it lives somewhere else.
- With no cwd= the Landlock-only subprocess path started the child in
  the ORCHESTRATOR's cwd (host-layout leak; relative writes landed in
  the driver's directory), while the mount-ns path started in "/".

These tests pin the scrubbed shapes end-to-end through sandbox().run()
and at the get_safe_env() unit level.
"""

import json
import os
import sys
import tempfile
import unittest

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="sandbox env scrub paths are Linux-only",
)

_DUMP = (
    "import json, os; "
    "print(json.dumps({'cwd': os.getcwd(), 'env': dict(os.environ)}))"
)


def _run_and_dump(**sandbox_kwargs):
    from core.sandbox import sandbox

    with sandbox(**sandbox_kwargs) as run:
        r = run(
            [sys.executable, "-c", _DUMP],
            capture_output=True, text=True, timeout=60,
        )
    assert r.returncode == 0, f"dump child failed: {r.stderr!r}"
    return json.loads(r.stdout.strip().splitlines()[-1])


class TestGetSafeEnvOldpwd(unittest.TestCase):
    def test_oldpwd_never_in_safe_env(self):
        from core.config import RaptorConfig
        old = os.environ.get("OLDPWD")
        os.environ["OLDPWD"] = "/somewhere/revealing"
        try:
            env = RaptorConfig.get_safe_env()
            self.assertNotIn("OLDPWD", env)
        finally:
            if old is None:
                os.environ.pop("OLDPWD", None)
            else:
                os.environ["OLDPWD"] = old


class TestSandboxedChildLayoutScrub(unittest.TestCase):
    """End-to-end: the child env/cwd reveal no host layout/identity."""

    def setUp(self):
        self._out = tempfile.TemporaryDirectory(prefix="raptor-envscrub-")
        self.addCleanup(self._out.cleanup)
        self.out = os.path.realpath(self._out.name)

    def _dump(self, **kw):
        kw.setdefault("output", self.out)
        return _run_and_dump(**kw)

    def test_no_oldpwd_or_pwd(self):
        env = self._dump()["env"]
        self.assertNotIn("OLDPWD", env)
        self.assertNotIn("PWD", env)

    def test_path_has_no_home_rooted_entries(self):
        env = self._dump()["env"]
        home = os.path.expanduser("~")
        for comp in env.get("PATH", "").split(os.pathsep):
            self.assertFalse(
                comp.startswith("/home/")
                or comp == home
                or comp.startswith(home + os.sep),
                f"home-rooted PATH entry leaked into sandboxed child: "
                f"{comp!r}",
            )

    def test_default_cwd_is_output_dir(self):
        dump = self._dump()
        self.assertEqual(
            os.path.realpath(dump["cwd"]), self.out,
            "sandboxed child with no cwd= must start in the output dir, "
            "not the orchestrator's cwd",
        )

    def test_caller_cwd_still_wins(self):
        with tempfile.TemporaryDirectory(prefix="raptor-cwd-") as want:
            # cwd must be visible inside the sandbox: pass it as target.
            from core.sandbox import sandbox
            with sandbox(output=self.out, target=want) as run:
                r = run(
                    [sys.executable, "-c", _DUMP],
                    cwd=want, capture_output=True, text=True, timeout=60,
                )
            assert r.returncode == 0, r.stderr
            dump = json.loads(r.stdout.strip().splitlines()[-1])
            self.assertEqual(
                os.path.realpath(dump["cwd"]), os.path.realpath(want),
            )

    def test_fake_home_neutralises_user_identity(self):
        env = self._dump(fake_home=True)["env"]
        self.assertEqual(env.get("USER"), "sandbox")
        self.assertEqual(env.get("LOGNAME"), "sandbox")

    def test_caller_env_still_verbatim(self):
        """Caller-supplied env= is documented pass-through — the scrub
        must not touch it."""
        from core.sandbox import sandbox
        caller_env = {
            "PATH": "/usr/bin:/bin",
            "PWD": "/kept/verbatim",
            "OLDPWD": "/kept/verbatim/too",
        }
        with sandbox(output=self.out) as run:
            r = run(
                [sys.executable, "-c", _DUMP],
                env=caller_env, env_caller_filtered=True,
                capture_output=True, text=True, timeout=60,
            )
        self.assertEqual(r.returncode, 0, r.stderr)
        env = json.loads(r.stdout.strip().splitlines()[-1])["env"]
        self.assertEqual(env.get("PWD"), "/kept/verbatim")
        self.assertEqual(env.get("OLDPWD"), "/kept/verbatim/too")


if __name__ == "__main__":
    unittest.main()
