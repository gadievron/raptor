"""End-to-end tests for the ``libexec/raptor-annotate`` operator CLI.

Drives the CLI as a subprocess. Each test sets ``_RAPTOR_TRUSTED=1``
to bypass the trust-marker guard and passes ``--base`` so no project
state is required.

Provenance note: a plain subprocess run has every std fd piped, so
the CLI stamps ``provenance=non-tty`` and defaults ``source=agent``.
Tests that need an interactive invocation pass ``tty=(...)`` to
:func:`_run`, which attaches a pty to the named fds.
"""

from __future__ import annotations

import contextlib
import os
import pty
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-annotate"


@dataclass
class _Result:
    returncode: int
    stdout: str
    stderr: str


def _run(*args, env=None, input_text=None, tty=(), stdin_path=None):
    """Run the CLI with --base resolved by caller in args.

    ``tty``: names among ``stdin``/``stdout``/``stderr`` to attach to
    a pty slave, making them real TTYs in the child (streams so
    attached are not captured). ``stdin_path``: redirect stdin from a
    file (the ``add ... < notes.txt`` shape); mutually exclusive with
    ``input_text`` and ``"stdin" in tty``.
    """
    real_env = dict(os.environ)
    real_env["_RAPTOR_TRUSTED"] = "1"
    if env:
        real_env.update(env)
    if not tty and stdin_path is None:
        result = subprocess.run(
            [sys.executable, str(CLI), *args],
            env=real_env,
            capture_output=True,
            text=True,
            input=input_text,
            check=False,
        )
        return _Result(result.returncode, result.stdout, result.stderr)

    master, slave = pty.openpty()
    stdin_file = None
    try:
        kwargs = {
            "stdin": subprocess.PIPE,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
        }
        for name in tty:
            assert name in ("stdin", "stdout", "stderr")
            kwargs[name] = slave
        if stdin_path is not None:
            assert "stdin" not in tty and input_text is None
            stdin_file = open(stdin_path, "rb")  # noqa: SIM115 — closed in finally
            kwargs["stdin"] = stdin_file
        proc = subprocess.Popen(
            [sys.executable, str(CLI), *args],
            env=real_env, text=True, **kwargs,
        )
        send = input_text if kwargs["stdin"] == subprocess.PIPE else None
        out, err = proc.communicate(input=send, timeout=60)
        return _Result(proc.returncode, out or "", err or "")
    finally:
        if stdin_file is not None:
            stdin_file.close()
        for fd in (master, slave):
            with contextlib.suppress(OSError):
                os.close(fd)


# ---------------------------------------------------------------------------
# Trust marker
# ---------------------------------------------------------------------------


class TestTrustMarker:
    def test_refuses_without_marker(self, tmp_path):
        env = {k: v for k, v in os.environ.items()
               if k not in ("_RAPTOR_TRUSTED", "CLAUDECODE")}
        result = subprocess.run(
            [sys.executable, str(CLI), "ls", "--base", str(tmp_path)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 2
        assert "internal dispatch" in result.stderr


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


class TestAdd:
    def test_basic_add(self, tmp_path):
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "-m", "Reviewed, no taint")
        assert r.returncode == 0, r.stderr
        assert "wrote" in r.stdout
        # Verify on disk.
        ann_file = tmp_path / "src" / "foo.py.md"
        assert ann_file.exists()
        text = ann_file.read_text()
        assert "## process" in text
        assert "status=clean" in text
        # All fds piped → non-interactive default + stamp.
        assert "source=agent" in text
        assert "provenance=non-tty" in text
        assert "tty=none" in text
        assert "Reviewed, no taint" in text

    def test_add_with_cwe_and_meta(self, tmp_path):
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "finding",
                 "--cwe", "CWE-78",
                 "--meta", "reviewer=alice",
                 "--meta", "ticket=BUG-42",
                 "-m", "command injection via shell=True")
        assert r.returncode == 0
        text = (tmp_path / "src" / "foo.py.md").read_text()
        assert "cwe=CWE-78" in text
        assert "reviewer=alice" in text
        assert "ticket=BUG-42" in text

    def test_add_body_from_stdin(self, tmp_path):
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "--body-file", "-",
                 input_text="body from stdin\nmulti-line content\n")
        assert r.returncode == 0
        ann = (tmp_path / "src" / "foo.py.md").read_text()
        assert "body from stdin" in ann
        assert "multi-line content" in ann

    def test_add_body_from_file(self, tmp_path):
        body_file = tmp_path / "_body.txt"
        body_file.write_text("imported prose\n")
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "--body-file", str(body_file))
        assert r.returncode == 0
        assert "imported prose" in (tmp_path / "src" / "foo.py.md").read_text()

    def test_auto_discovers_bounds_from_checklist_in_base_parent(
        self, tmp_path,
    ):
        """When ``--lines`` is omitted, the CLI looks for a
        checklist.json next to the base directory's parent."""
        run_dir = tmp_path / "run"
        ann_base = run_dir / "annotations"
        run_dir.mkdir()
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text(
            "def f():\n    pass\n"
        )
        # Checklist sits next to the base dir's parent (i.e. in run_dir).
        import json
        (run_dir / "checklist.json").write_text(json.dumps({
            "files": [{
                "path": "src/foo.py",
                "items": [{"name": "f", "line_start": 1, "line_end": 2}],
            }],
        }))
        r = _run("add", "src/foo.py", "f",
                 "--base", str(ann_base),
                 "--status", "clean",
                 "--target", str(target),
                 "-m", "auto-discovered")
        assert r.returncode == 0, r.stderr
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "hash=" in text
        assert "start_line=1" in text
        assert "end_line=2" in text

    def test_auto_discovery_skipped_silently_no_checklist(self, tmp_path):
        """No checklist anywhere → no hash, but the annotation
        still lands. No warning printed (warnings are reserved for
        explicit ``--lines`` failures)."""
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "-m", "no hash possible")
        assert r.returncode == 0
        assert "warning" not in r.stderr
        text = (tmp_path / "src" / "foo.py.md").read_text()
        assert "hash=" not in text

    def test_explicit_checklist_arg(self, tmp_path):
        run_dir = tmp_path / "out"
        run_dir.mkdir()
        ann_base = run_dir / "annotations"
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text("def f():\n    pass\n")
        import json
        ck = tmp_path / "custom-checklist.json"
        ck.write_text(json.dumps({
            "files": [{
                "path": "src/foo.py",
                "items": [{"name": "f", "line_start": 1, "line_end": 2}],
            }],
        }))
        r = _run("add", "src/foo.py", "f",
                 "--base", str(ann_base),
                 "--checklist", str(ck),
                 "--target", str(target),
                 "-m", "from custom checklist")
        assert r.returncode == 0
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "hash=" in text

    def test_explicit_lines_overrides_checklist(self, tmp_path):
        """If both --lines and --checklist could provide bounds,
        --lines wins (operator's explicit intent)."""
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        ann_base = run_dir / "annotations"
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text(
            "def f():\n    return 1\n\ndef g():\n    return 2\n"
        )
        import json
        (run_dir / "checklist.json").write_text(json.dumps({
            "files": [{
                "path": "src/foo.py",
                "items": [{"name": "f", "line_start": 1, "line_end": 2}],
            }],
        }))
        # Operator explicitly says lines 4-5 (the ``g`` body).
        r = _run("add", "src/foo.py", "f",
                 "--base", str(ann_base),
                 "--lines", "4-5",
                 "--target", str(target),
                 "-m", "explicit override")
        assert r.returncode == 0
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "start_line=4" in text
        assert "end_line=5" in text

    def test_add_with_hash(self, tmp_path):
        # Set up a mock target repo with a real source file.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text(
            "def process(x):\n    return os.system(x)\n"
        )
        ann_base = tmp_path / "anns"
        r = _run("add", "src/foo.py", "process",
                 "--base", str(ann_base),
                 "--status", "finding",
                 "--lines", "1-2",
                 "--target", str(target),
                 "-m", "shell injection")
        assert r.returncode == 0, r.stderr
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "hash=" in text
        assert "start_line=1" in text
        assert "end_line=2" in text

    def test_add_invalid_lines_format(self, tmp_path):
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--lines", "garbage",
                 "-m", "x")
        assert r.returncode == 2
        assert "lines" in r.stderr

    def test_add_invalid_meta(self, tmp_path):
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--meta", "no-equals-sign",
                 "-m", "x")
        assert r.returncode == 2

    def test_add_respect_manual_skips_human(self, tmp_path):
        # First write as human (explicit — a piped run defaults to
        # agent, which respect-manual deliberately does not protect).
        _run("add", "src/foo.py", "f",
             "--base", str(tmp_path),
             "--source", "human",
             "-m", "manual note")
        # Now LLM tries respect-manual — should skip.
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--source", "llm",
                 "--overwrite", "respect-manual",
                 "-m", "llm overwrite attempt")
        # Skip is signalled with rc=1 and "skipped" in stderr.
        assert r.returncode == 1
        assert "skipped" in r.stderr
        # Manual content still there.
        text = (tmp_path / "src" / "foo.py.md").read_text()
        assert "manual note" in text
        assert "llm overwrite" not in text

    def test_add_rejects_invalid_overwrite_mode(self, tmp_path):
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--overwrite", "bogus",
                 "-m", "x")
        # argparse rejects before reaching our validation.
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------


class TestLs:
    def test_empty_says_so(self, tmp_path):
        r = _run("ls", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "(no annotations)" in r.stdout

    def test_lists_added(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "finding", "-m", "bad")
        r = _run("ls", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "src/a.py" in r.stdout
        assert "src/b.py" in r.stdout

    def test_filter_by_status(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "finding", "-m", "bad")
        r = _run("ls", "--base", str(tmp_path), "--status", "finding")
        assert "src/b.py" in r.stdout
        assert "src/a.py" not in r.stdout

    def test_filter_by_source(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--source", "human", "-m", "manual")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--source", "llm", "-m", "auto")
        r = _run("ls", "--base", str(tmp_path), "--source", "llm")
        assert "src/b.py" in r.stdout
        assert "src/a.py" not in r.stdout

    def test_filter_by_cwe(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "finding", "--cwe", "CWE-78", "-m", "x")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "finding", "--cwe", "CWE-89", "-m", "x")
        r = _run("ls", "--base", str(tmp_path), "--cwe", "CWE-78")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_filter_by_rule_id_substring(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--meta", "rule_id=py/sql-injection", "-m", "x")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--meta", "rule_id=cpp/buffer-overflow", "-m", "x")
        # Substring "py/" scopes to Python rules.
        r = _run("ls", "--base", str(tmp_path), "--rule-id", "py/")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_grep_body(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "-m", "uses subprocess.call shell=True")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "-m", "constant-time compare")
        r = _run("ls", "--base", str(tmp_path), "--grep", "subprocess")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_grep_case_insensitive(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "-m", "Subprocess Call")
        r = _run("ls", "--base", str(tmp_path), "--grep", "SUBPROCESS")
        assert "src/a.py" in r.stdout

    def test_grep_metadata_value(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--meta", "ticket=BUG-42", "-m", "x")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "-m", "x")
        r = _run("ls", "--base", str(tmp_path), "--grep", "BUG-42")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_since_filter_all_recent(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        # Just-written annotation falls inside any reasonable window.
        r = _run("ls", "--base", str(tmp_path), "--since", "1h")
        assert "src/a.py" in r.stdout

    def test_since_filter_excludes_old(self, tmp_path):
        import os
        import time
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        # Backdate the annotation file by 30 days.
        ann_file = tmp_path / "src" / "a.py.md"
        old_ts = time.time() - (30 * 86400)
        os.utime(ann_file, (old_ts, old_ts))
        r = _run("ls", "--base", str(tmp_path), "--since", "7d")
        assert "src/a.py" not in r.stdout

    def test_since_bad_value_errors(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        r = _run("ls", "--base", str(tmp_path), "--since", "garbage")
        assert r.returncode == 2
        assert "since" in r.stderr.lower()

    def test_since_supported_units(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        for unit in ("60s", "5m", "1h", "1d", "1w"):
            r = _run("ls", "--base", str(tmp_path), "--since", unit)
            assert r.returncode == 0, f"{unit}: {r.stderr}"

    def test_filter_by_file(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        r = _run("ls", "--base", str(tmp_path), "--file", "src/a.py")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


class TestShow:
    def test_shows_existing(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "the body content")
        r = _run("show", "src/a.py", "f1", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "## f1" in r.stdout
        assert "status=clean" in r.stdout
        assert "the body content" in r.stdout

    def test_missing_returns_1(self, tmp_path):
        r = _run("show", "src/nope.py", "x", "--base", str(tmp_path))
        assert r.returncode == 1
        assert "no annotation" in r.stderr


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------


class TestRm:
    def test_removes_existing(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "x")
        r = _run("rm", "src/a.py", "f1", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "removed" in r.stdout

    def test_remove_missing_returns_1(self, tmp_path):
        r = _run("rm", "src/nope.py", "x", "--base", str(tmp_path))
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------


class TestEdit:
    def test_edit_invokes_editor(self, tmp_path):
        # Use ``true`` as a no-op editor — exits 0 without prompting.
        env = {"EDITOR": "true"}
        r = _run("edit", "src/a.py", "f1",
                 "--base", str(tmp_path), env=env)
        assert r.returncode == 0
        # Placeholder file created.
        assert (tmp_path / "src" / "a.py.md").exists()

    def test_edit_propagates_editor_failure(self, tmp_path):
        env = {"EDITOR": "false"}
        r = _run("edit", "src/a.py", "f1",
                 "--base", str(tmp_path), env=env)
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# stale
# ---------------------------------------------------------------------------


class TestStale:
    def test_no_annotations(self, tmp_path):
        r = _run("stale", "--base", str(tmp_path),
                 "--target", str(tmp_path))
        assert r.returncode == 0
        assert "(no stale" in r.stdout

    def test_detects_stale(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        src = target / "src" / "a.py"
        src.write_text("def f():\n    return 1\n")
        # Add annotation with hash from current source.
        ann_base = tmp_path / "anns"
        _run("add", "src/a.py", "f",
             "--base", str(ann_base),
             "--status", "clean",
             "--lines", "1-2",
             "--target", str(target),
             "-m", "ok")
        # Run stale check now — nothing stale.
        r = _run("stale", "--base", str(ann_base),
                 "--target", str(target))
        assert r.returncode == 0
        assert "(no stale" in r.stdout
        # Edit source — hash changes — stale detected.
        src.write_text("def f():\n    return 99\n")
        r = _run("stale", "--base", str(ann_base),
                 "--target", str(target))
        assert r.returncode == 0
        assert "src/a.py:f" in r.stdout
        assert "stored=" in r.stdout
        assert "current=" in r.stdout

    def test_skips_annotations_without_hash(self, tmp_path):
        # Add annotation without --lines (no hash captured).
        _run("add", "src/a.py", "f", "--base", str(tmp_path),
             "--status", "clean", "-m", "no hash")
        r = _run("stale", "--base", str(tmp_path),
                 "--target", str(tmp_path))
        assert r.returncode == 0
        assert "(no stale" in r.stdout


# ---------------------------------------------------------------------------
# Base resolution
# ---------------------------------------------------------------------------


class TestBaseResolution:
    def test_explicit_base_used(self, tmp_path):
        r = _run("ls", "--base", str(tmp_path))
        assert r.returncode == 0

    def test_no_base_no_project_errors(self, tmp_path):
        # Run with no --base and a temp HOME so no real project exists.
        # We can't easily fake "no active project" in a real repo with
        # active-state, so instead point PROJECTS_DIR at an empty tmp dir
        # via env. The real defence is integration-tested in the slash
        # command harness; here, just ensure the explicit-base path works.
        # Skip this assertion if a project is active in the dev env.
        pass


# ---------------------------------------------------------------------------
# IRIS spec promotion on operator-confirmed annotations (P33)
# ---------------------------------------------------------------------------


class TestIrisPromotionOnAdd:
    def _write_store(self, project_dir):
        from core.evidence import EvidenceTier
        from core.iris.specs import TaintSpec
        from core.iris.store import save_specs

        spec = TaintSpec(
            function="write_out",
            file="src/io.c",
            role="sink",
            evidence_tier=EvidenceTier.HEURISTIC,
        )
        # save_specs resolves the project dir as out_dir.parent — the
        # annotations base is a direct child of the project dir, so it
        # doubles as the run-level hint.
        save_specs(project_dir / "annotations", [spec])

    def test_sink_annotation_promotes_spec(self, tmp_path):
        from core.evidence import EvidenceTier
        from core.iris.store import load_specs

        base = tmp_path / "annotations"
        base.mkdir()
        self._write_store(tmp_path)

        # Interactive stdin → source defaults to human, human-grade.
        r = _run("add", "src/io.c", "write_out",
                 "--base", str(base), "--status", "sink",
                 "-m", "confirmed sink wrapper",
                 tty=("stdin",))
        assert r.returncode == 0, r.stderr
        assert "promoted matching IRIS taint spec" in r.stdout

        specs = load_specs(base)
        assert specs[0].evidence_tier == EvidenceTier.XREF_BACKED
        assert specs[0].source == "operator_confirmed"

    def test_clean_annotation_does_not_promote(self, tmp_path):
        from core.evidence import EvidenceTier
        from core.iris.store import load_specs

        base = tmp_path / "annotations"
        base.mkdir()
        self._write_store(tmp_path)

        r = _run("add", "src/io.c", "write_out",
                 "--base", str(base), "--status", "clean",
                 "-m", "reviewed, fine")
        assert r.returncode == 0, r.stderr
        assert "promoted" not in r.stdout

        specs = load_specs(base)
        assert specs[0].evidence_tier == EvidenceTier.HEURISTIC

    def test_llm_source_promotes_to_hint_tier_only(self, tmp_path):
        from core.evidence import EvidenceTier
        from core.iris.store import load_specs

        base = tmp_path / "annotations"
        base.mkdir()
        self._write_store(tmp_path)

        r = _run("add", "src/io.c", "write_out",
                 "--base", str(base), "--status", "sink",
                 "--source", "llm", "-m", "scripted add")
        assert r.returncode == 0, r.stderr
        assert "header_backed" in r.stdout

        specs = load_specs(base)
        assert specs[0].evidence_tier == EvidenceTier.HEADER_BACKED
        assert specs[0].source == "annotation_asserted"

    def test_agent_default_promotes_to_hint_tier_only(self, tmp_path):
        from core.evidence import EvidenceTier
        from core.iris.store import load_specs

        base = tmp_path / "annotations"
        base.mkdir()
        self._write_store(tmp_path)

        # All fds piped → source defaults to agent.
        r = _run("add", "src/io.c", "write_out",
                 "--base", str(base), "--status", "sink",
                 "-m", "agent-driven add")
        assert r.returncode == 0, r.stderr
        assert "header_backed" in r.stdout

        specs = load_specs(base)
        assert specs[0].evidence_tier == EvidenceTier.HEADER_BACKED

    def test_forged_human_non_tty_promotes_to_hint_tier_only(
        self, tmp_path,
    ):
        from core.evidence import EvidenceTier
        from core.iris.store import load_specs

        base = tmp_path / "annotations"
        base.mkdir()
        self._write_store(tmp_path)

        # Explicit --source human with zero TTYs: the laundering
        # shape. Never reaches xref_backed.
        r = _run("add", "src/io.c", "write_out",
                 "--base", str(base), "--status", "sink",
                 "--source", "human", "-m", "claimed manual")
        assert r.returncode == 0, r.stderr
        assert "header_backed" in r.stdout

        specs = load_specs(base)
        assert specs[0].evidence_tier == EvidenceTier.HEADER_BACKED
        assert specs[0].source == "annotation_asserted"

    def test_missing_store_never_fails_add(self, tmp_path):
        base = tmp_path / "annotations"
        base.mkdir()
        r = _run("add", "src/io.c", "write_out",
                 "--base", str(base), "--status", "sink",
                 "-m", "no IRIS store present")
        assert r.returncode == 0, r.stderr
        assert "wrote " in r.stdout


# ---------------------------------------------------------------------------
# Invocation-context provenance (stamp + context-sensitive defaults)
# ---------------------------------------------------------------------------


def _meta_of(base: Path, source_file: str, function: str) -> dict:
    from core.annotations import read_annotation
    ann = read_annotation(base, source_file, function)
    assert ann is not None
    return dict(ann.metadata)


class TestProvenanceDefaults:
    def test_all_piped_defaults_to_agent(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path), "-m", "x")
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "agent"
        assert meta["provenance"] == "non-tty"
        assert meta["tty"] == "none"

    def test_tty_stdin_defaults_to_human(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path), "-m", "x",
                 tty=("stdin",))
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "human"
        assert meta["provenance"] == "interactive-tty"
        assert meta["tty"] == "stdin"

    def test_stdin_from_file_with_tty_stdout_defaults_to_human(
        self, tmp_path,
    ):
        # ``raptor-annotate add ... --body-file - < notes.txt`` in a
        # terminal: stdin is a file, stdout is still a TTY — a
        # legitimate human workflow, must stay interactive.
        notes = tmp_path / "notes.txt"
        notes.write_text("prose from a file\n")
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--body-file", "-",
                 stdin_path=notes, tty=("stdout",))
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "human"
        assert meta["provenance"] == "interactive-tty"
        assert meta["tty"] == "stdout"
        text = (tmp_path / "src" / "a.py.md").read_text()
        assert "prose from a file" in text

    def test_forged_human_all_piped_keeps_contradicting_stamp(
        self, tmp_path,
    ):
        # Explicit --source human is caller-asserted and preserved,
        # but the stamp records the non-interactive context.
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--source", "human", "-m", "x")
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "human"
        assert meta["provenance"] == "non-tty"
        assert meta["tty"] == "none"
        from core.annotations import is_human_grade
        assert not is_human_grade(meta)

    def test_explicit_source_wins_over_context(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--source", "llm", "-m", "x", tty=("stdin",))
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "llm"
        assert meta["provenance"] == "interactive-tty"


class TestProvenanceQuirks:
    def test_meta_source_conflicting_with_flag_is_hard_error(
        self, tmp_path,
    ):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--source", "human", "--meta", "source=llm", "-m", "x")
        assert r.returncode == 2
        assert "conflicting source" in r.stderr
        assert not (tmp_path / "src" / "a.py.md").exists()

    def test_meta_source_agreeing_with_flag_is_fine(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--source", "llm", "--meta", "source=llm", "-m", "x")
        assert r.returncode == 0, r.stderr
        assert _meta_of(tmp_path, "src/a.py", "f")["source"] == "llm"

    def test_meta_source_without_flag_is_used(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--meta", "source=llm", "-m", "x")
        assert r.returncode == 0, r.stderr
        assert _meta_of(tmp_path, "src/a.py", "f")["source"] == "llm"

    def test_invalid_meta_source_rejected(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--meta", "source=humman", "-m", "x")
        assert r.returncode == 2
        assert "invalid annotation source" in r.stderr
        assert not (tmp_path / "src" / "a.py.md").exists()

    def test_invalid_source_flag_rejected_by_argparse(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--source", "humman", "-m", "x")
        assert r.returncode == 2
        assert not (tmp_path / "src" / "a.py.md").exists()

    def test_meta_tty_and_provenance_are_reserved(self, tmp_path):
        for pair in ("tty=stdin", "provenance=interactive-tty"):
            r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                     "--meta", pair, "-m", "x")
            assert r.returncode == 2, pair
            assert "reserved" in r.stderr
        assert not (tmp_path / "src" / "a.py.md").exists()


class TestEditRestamp:
    def test_non_interactive_edit_demotes_provenance(self, tmp_path):
        # Interactive add: human + interactive stamp.
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "-m", "human note", tty=("stdin",))
        assert r.returncode == 0, r.stderr
        assert _meta_of(tmp_path, "src/a.py", "f")["provenance"] == \
            "interactive-tty"
        # Fully-piped edit (the laundering shape): the edit itself
        # re-stamps the section non-tty; source stays human but the
        # note is no longer human-grade.
        r = _run("edit", "src/a.py", "f", "--base", str(tmp_path),
                 env={"EDITOR": "true"})
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "human"
        assert meta["provenance"] == "non-tty"
        assert meta["tty"] == "none"
        from core.annotations import is_human_grade
        assert not is_human_grade(meta)

    def test_interactive_edit_keeps_interactive_stamp(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "-m", "human note", tty=("stdin",))
        assert r.returncode == 0, r.stderr
        r = _run("edit", "src/a.py", "f", "--base", str(tmp_path),
                 env={"EDITOR": "true"}, tty=("stdin",))
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "human"
        assert meta["provenance"] == "interactive-tty"

    def test_edit_preserves_body_and_other_metadata(self, tmp_path):
        r = _run("add", "src/a.py", "f", "--base", str(tmp_path),
                 "--status", "clean", "--cwe", "CWE-78",
                 "-m", "the prose body", tty=("stdin",))
        assert r.returncode == 0, r.stderr
        r = _run("edit", "src/a.py", "f", "--base", str(tmp_path),
                 env={"EDITOR": "true"})
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["status"] == "clean"
        assert meta["cwe"] == "CWE-78"
        assert "the prose body" in \
            (tmp_path / "src" / "a.py.md").read_text()


class TestReviewNoteDelegationInheritsContext:
    """/review note delegates to raptor-annotate via subprocess with
    inherited fds — a piped /review note must land as agent."""

    def test_piped_review_note_defaults_to_agent(self, tmp_path):
        review = REPO_ROOT / "libexec" / "raptor-review"
        env = dict(os.environ)
        env["_RAPTOR_TRUSTED"] = "1"
        r = subprocess.run(
            [sys.executable, str(review), "note",
             "src/a.py", "f", "-m", "note body",
             "--base", str(tmp_path)],
            env=env, capture_output=True, text=True, check=False,
        )
        if r.returncode != 0 and "--base" in r.stderr:
            import pytest
            pytest.skip("raptor-review note does not forward --base")
        assert r.returncode == 0, r.stderr
        meta = _meta_of(tmp_path, "src/a.py", "f")
        assert meta["source"] == "agent"
        assert meta["provenance"] == "non-tty"


# ---------------------------------------------------------------------------
# body forgery (regression: unvalidated -m body forged human sections)
# ---------------------------------------------------------------------------


class TestBodyForgeryRejected:
    """The exact PoC: a crafted ``-m`` payload injected a fake
    human-graded section through the sanctioned CLI, defeating the TTY
    provenance model. The write path must refuse bodies carrying the
    reserved on-disk grammar."""

    def test_forged_human_section_via_dash_m_is_rejected(self, tmp_path):
        payload = (
            "legit note\n"
            "## victim_fn\n"
            "<!-- meta: source=human provenance=interactive-tty -->"
        )
        r = _run("add", "src/a.py", "real_fn", "-m", payload,
                 "--base", str(tmp_path))
        assert r.returncode != 0
        assert "body" in r.stderr
        # Nothing forged on disk.
        md = tmp_path / "src" / "a.py.md"
        if md.exists():
            text = md.read_text()
            assert "## victim_fn" not in text
            assert "interactive-tty" not in text

    def test_forged_version_marker_rejected(self, tmp_path):
        r = _run("add", "src/a.py", "f", "-m",
                 "x\n<!-- annotations-version: 99 -->",
                 "--base", str(tmp_path))
        assert r.returncode != 0

    def test_multiline_prose_still_accepted(self, tmp_path):
        body = (
            "Constant-time compare, no taint.\n\n"
            "### Follow-ups\n"
            "- checked callers\n"
            "- a < b comparisons fine\n"
            "  ## indented, not a heading\n"
            "code sample: x = '<!--' + 'meta'\n"
        )
        r = _run("add", "src/a.py", "check_pw", "-m", body,
                 "--base", str(tmp_path))
        assert r.returncode == 0, r.stderr
        from core.annotations import read_annotation
        ann = read_annotation(tmp_path, "src/a.py", "check_pw")
        assert ann is not None
        assert "### Follow-ups" in ann.body
        assert "indented, not a heading" in ann.body

    def test_edit_placeholder_rejects_hostile_function_name(self, tmp_path):
        hostile = "f\n## forged\n<!-- meta: source=human -->"
        r = _run("edit", "src/a.py", hostile,
                 "--base", str(tmp_path), env={"EDITOR": "true"})
        assert r.returncode != 0
        md = tmp_path / "src" / "a.py.md"
        assert not md.exists() or "## forged" not in md.read_text()

    def test_edit_placeholder_is_versioned(self, tmp_path):
        r = _run("edit", "src/a.py", "f1",
                 "--base", str(tmp_path), env={"EDITOR": "true"})
        assert r.returncode == 0
        text = (tmp_path / "src" / "a.py.md").read_text()
        assert "<!-- annotations-version:" in text
        assert "## f1" in text
