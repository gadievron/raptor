"""Hardening of the synthesised raw-javac fallback.

Two properties of the no-build-system Java path:

  * The generated build script must invoke javac with ``-proc:none``.
    The synthesised classpath includes repo-supplied ``lib/*.jar``,
    and javac auto-discovers annotation processors on the classpath
    via ServiceLoader — without the flag a hostile jar's processor
    executes attacker code inside every javac invocation.

  * ``_dry_run`` must pass read confinement (``restrict_reads``) to
    the sandbox — the script compiles untrusted repo content, so on
    Landlock-only hosts the read restriction is what keeps ``$HOME``
    credentials out of reach.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from core.build.build_detector import BuildDetector


def _write_java_script(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "Main.java").write_text("class Main {}\n")
    build_dir = tmp_path / "build"
    build_dir.mkdir()
    script = tmp_path / "build_script.py"
    script.touch()
    det = BuildDetector(repo)
    det._write_build_script(
        script, build_dir,
        [repo / "Main.java"], "javac",
        ["-sourcepath", str(repo)], [],
    )
    return script


def test_generated_script_disables_annotation_processing(tmp_path):
    """Run the generated script against a stub javac that records its
    argv; the recorded invocation must carry ``-proc:none``."""
    script = _write_java_script(tmp_path)

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_log = tmp_path / "javac-argv.txt"
    stub = bin_dir / "javac"
    stub.write_text(
        "#!/bin/sh\n"
        f'printf \'%s\\n\' "$@" > "{argv_log}"\n'
    )
    stub.chmod(0o755)

    env = dict(os.environ)
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    proc = subprocess.run(
        [sys.executable, str(script)],
        env=env, capture_output=True, text=True, timeout=60,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    recorded = argv_log.read_text().splitlines()
    assert "-proc:none" in recorded, (
        "generated javac invocation must disable annotation "
        f"processing; argv was {recorded!r}"
    )


def test_dry_run_passes_read_confinement(tmp_path):
    """The dry-run sandbox call must restrict reads — the script
    executes untrusted-repo-derived compiles."""
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    with mock.patch(
        "core.build.build_detector._sandbox_run", side_effect=fake_run,
    ):
        BuildDetector(tmp_path)._dry_run(tmp_path / "script.py")
    assert captured.get("restrict_reads") is True


def test_cc_suggest_flags_passes_read_confinement(tmp_path, monkeypatch):
    """The flag-inference CC child carries backend credentials in its
    env and reads hostile repo content — the sandbox call must thread
    restrict_reads + the calibrated CC readable-paths floor, same as
    the other CC dispatch sites."""
    import shutil as shutil_mod

    import core.llm.cc_adapter as cc_adapter
    import core.llm.cc_proxy_hosts as cc_proxy_hosts
    import core.security.cc_trust as cc_trust

    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout='{"includes": [], "defines": []}',
            stderr="",
        )

    monkeypatch.setattr(shutil_mod, "which",
                        lambda name: "/usr/bin/claude")
    monkeypatch.setattr(cc_trust, "check_repo_agent_cli_trust",
                        lambda p: False)
    monkeypatch.setattr(cc_adapter, "cc_subprocess_env",
                        lambda **k: {"PATH": "/usr/bin"})
    monkeypatch.setattr(cc_proxy_hosts, "proxy_hosts_for_cc_dispatch",
                        lambda b, **k: ["api.anthropic.com"])
    monkeypatch.setattr(cc_proxy_hosts, "readable_paths_for_cc_dispatch",
                        lambda b: ["/opt/cc-floor"])

    with mock.patch(
        "core.build.build_detector._sandbox_run", side_effect=fake_run,
    ):
        BuildDetector(tmp_path)._cc_suggest_flags(
            [{"file": "a.c", "error": "missing header"}], "cpp",
        )

    assert captured.get("restrict_reads") is True
    readable = captured.get("readable_paths")
    assert readable[0] == "/opt/cc-floor"
    assert len(readable) == 2
    assert Path(readable[1]).name.startswith("cc-sysprompt-")


def test_copilot_suggest_flags_uses_copilot_sandbox(
    tmp_path, monkeypatch,
):
    import shutil as shutil_mod

    import core.llm.copilot_adapter as copilot_adapter
    import core.security.cc_trust as cc_trust

    captured: dict = {}

    def fake_env(**kwargs):
        captured["env_kwargs"] = kwargs
        home = Path(kwargs["copilot_home"])
        captured["settings"] = json.loads(
            (home / "settings.json").read_text(encoding="utf-8")
        )["sandbox"]
        return {"PATH": "/usr/bin"}

    def fake_run(cmd, prompt, **kwargs):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        captured.update(kwargs)
        usage_path = Path(cmd[cmd.index("--usage-output-file") + 1])
        usage_path.write_text(
            '{"currentModel":"gpt-5.6-sol","modelMetrics":{}}\n',
            encoding="utf-8",
        )
        return SimpleNamespace(
            returncode=0,
            stdout=(
                '{"type":"assistant.message","data":'
                '{"content":"{\\"includes\\":[],\\"defines\\":[]}",'
                '"model":"gpt-5.6-sol"}}\n'
                '{"type":"result","exitCode":0}\n'
            ),
            stderr="",
        ), 0.1

    monkeypatch.setenv("RAPTOR_AGENT_CLI", "copilot")
    monkeypatch.setenv("RAPTOR_COPILOT_TRANSPORT_DISABLED", "0")
    monkeypatch.setattr(
        shutil_mod,
        "which",
        lambda name: "/usr/bin/copilot" if name == "copilot" else None,
    )
    monkeypatch.setattr(
        cc_trust,
        "check_repo_agent_cli_trust",
        lambda path: False,
    )
    monkeypatch.setattr(
        copilot_adapter,
        "copilot_subprocess_env",
        fake_env,
    )
    monkeypatch.setattr(
        copilot_adapter,
        "execute_copilot_command",
        fake_run,
    )
    BuildDetector(tmp_path)._cc_suggest_flags(
        [{"file": "a.c", "error": "missing header"}],
        "cpp",
    )

    assert captured["cmd"][0] == "/usr/bin/copilot"
    assert "--no-custom-instructions" in captured["cmd"]
    assert "--sandbox" in captured["cmd"]
    assert captured["prompt"]
    assert captured["cwd"] != str(tmp_path)
    private_home = Path(captured["env_kwargs"]["copilot_home"])
    workspace = Path(captured["cwd"])
    policy = captured["settings"]["userPolicy"]["filesystem"]
    model_roots = (
        workspace,
        tmp_path,
        *(Path(path) for path in policy["readwritePaths"]),
        *(Path(path) for path in policy["readonlyPaths"]),
    )
    for root in model_roots:
        assert not private_home.resolve().is_relative_to(root.resolve())
    assert str(private_home.resolve()) not in (
        *policy["readwritePaths"],
        *policy["readonlyPaths"],
    )
    assert not private_home.exists()
