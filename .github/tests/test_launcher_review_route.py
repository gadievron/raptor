"""bin/raptor's direct review route (the fp-ceremony production path).

The review CLI is the operator's query/verdict surface, and its
``verdict <id> fp --ceremony`` typed consent must run at the
operator's own terminal — so, like ``wsl-consent`` and ``sage-setup``,
``bin/raptor review …`` resolves WITHOUT launching a Claude session
(before this route existed, a bare-shell ``raptor review …`` treated
``review`` as a scan target). These tests pin the route mechanically
and exercise the refusal end to end: a piped invocation through the
real launcher (the shape every agent tool-call runs as) must stop at
the ceremony's all-fds TTY gate with zero mutation.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_LAUNCHER = _REPO / "bin" / "raptor"


def _run_launcher(args: list, stdin: str = ""):
    env = {
        "HOME": os.environ.get("HOME", "/tmp"),
        "PATH": "/usr/bin:/bin",
    }
    with tempfile.TemporaryDirectory() as scratch:
        # Isolated session-scratch base (see test_launcher_path_scrub:
        # the shared per-uid /tmp base races concurrent launchers).
        env.setdefault("RAPTOR_WORK_DIR", scratch)
        return subprocess.run(
            ["bash", str(_LAUNCHER), *args],
            capture_output=True, text=True, timeout=60, env=env,
            input=stdin,
        )


def _make_run(base: Path) -> Path:
    """Minimal run fixture the verdict verb can resolve against."""
    target = base / "repo"
    (target / "src").mkdir(parents=True)
    (target / "src" / "a.c").write_text(
        "\n".join(f"int l{i};" for i in range(20)), encoding="utf-8")
    run = base / "run_001"
    run.mkdir()
    (run / ".raptor-run.json").write_text(json.dumps({
        "command": "agentic",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "status": "completed",
        "target_path": str(target),
    }), encoding="utf-8")
    (run / "findings.json").write_text(json.dumps([
        {"id": "find-001", "file": "src/a.c", "function": "parse",
         "line": 3, "rule_id": "cpp/overflow"},
    ]), encoding="utf-8")
    return run


class TestReviewRoutePin(unittest.TestCase):
    """Mechanical pins of the launcher's own route block."""

    def _route_block(self) -> str:
        text = _LAUNCHER.read_text(encoding="utf-8")
        start = text.index('if [[ "${1:-}" == "review" ]]; then')
        return text[start:text.index("fi", start)]

    def test_route_execs_review_cli_with_trust_marker(self):
        block = self._route_block()
        self.assertIn("export _RAPTOR_TRUSTED=1", block)
        self.assertIn("export RAPTOR_DIR", block)
        self.assertIn(
            'exec "$RAPTOR_DIR/libexec/raptor-review" "$@"', block)

    def test_route_resolves_before_the_claude_requirement(self):
        # The ceremony must not depend on a Claude install: the route
        # sits before the "Claude required for everything else" gate,
        # like the other operator-terminal ceremonies.
        text = _LAUNCHER.read_text(encoding="utf-8")
        self.assertLess(
            text.index('if [[ "${1:-}" == "review" ]]; then'),
            text.index("# Claude required for everything else"))


class TestReviewRouteBehaviour(unittest.TestCase):
    def test_review_route_reaches_the_review_cli(self):
        proc = _run_launcher(["review", "--help"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("raptor-review", proc.stdout)
        self.assertIn("verdict", proc.stdout)

    def test_piped_ceremony_refuses_at_the_fd_gate(self):
        # The end-to-end agent shape: real launcher, real provenance
        # detection, all std fds piped (this test process pipes them),
        # the confirmation phrase already waiting on stdin. The
        # ceremony must refuse before ever reading it, with zero
        # mutation — this is the claim the ceremony's authority model
        # rests on for the stock tool-call route.
        with tempfile.TemporaryDirectory() as base:
            run = _make_run(Path(base))
            proc = _run_launcher(
                ["review", "verdict", "find-001", "fp", "--ceremony",
                 "--out", str(run)],
                stdin="suppress find-001\n",
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("Ceremony refused", proc.stderr)
            self.assertIn("must all be terminals", proc.stderr)
            self.assertIn("Nothing was stored or changed", proc.stderr)
            self.assertFalse((run / "suppressions.jsonl").exists())

    def test_piped_plain_fp_refusal_names_the_ceremony(self):
        with tempfile.TemporaryDirectory() as base:
            run = _make_run(Path(base))
            proc = _run_launcher(
                ["review", "verdict", "find-001", "fp",
                 "--out", str(run)],
            )
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertIn("Refused", proc.stderr)
            self.assertIn("--ceremony", proc.stderr)
            self.assertFalse((run / "suppressions.jsonl").exists())


if __name__ == "__main__":
    unittest.main()
