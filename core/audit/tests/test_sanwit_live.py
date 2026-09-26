"""Live sanitizer-witness matrix — executes a real PHP interpreter.

Skips WITH NOTICE when no tier resolves (no php-cli on PATH and no
usable docker + pinned image): everything above the execution
boundary is covered hermetically by the sibling test files; this
file is the executed ground truth for the two shipped families.

Every case is a KNOWN truth of the PHP builtins + sink-context
parsing rules; a failure here means the witness would mint wrong
verdicts on real targets.
"""

from __future__ import annotations

import pytest

from core.audit.sanwit import run_sanwit_check
from core.audit.sanwit._execute import (
    RuntimeUnavailable,
    resolve_php_runtime,
)


@pytest.fixture(scope="module")
def runtime():
    resolved = resolve_php_runtime()
    if isinstance(resolved, RuntimeUnavailable):
        pytest.skip(
            f"no PHP execution tier on this host: {resolved.reason}",
        )
    return resolved


def _check(hypothesis: str, source: str, cwe: str):
    return run_sanwit_check(
        "/nonexistent", "web/a.php", "f", hypothesis,
        source=source, cwe=cwe,
    )


class TestShellFamilyGroundTruth:
    def test_escapeshellcmd_argument_injection(self, runtime):
        """The founding case: escaping LOOKS applied, but a space
        passes through as an argv separator."""
        res = _check(
            "argument injection despite escapeshellcmd",
            "function f($x) {\n"
            '    $cmd = "prog " . escapeshellcmd($x) . " -v";\n'
            "    system($cmd);\n"
            "}",
            "CWE-88",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "sanwit:insufficient:shell-command"
        ids = {e["payload_id"] for e in res.exhibits}
        assert "space-arg" in ids
        # Metachar payloads ARE neutralized by escapeshellcmd — only
        # the separator class breaks out (exhibit precision).
        assert "semi" not in ids

    def test_escapeshellarg_command_position_sufficient(self, runtime):
        res = _check(
            "command injection despite escapeshellarg quoting",
            "function f($x) {\n"
            '    $cmd = "prog " . escapeshellarg($x);\n'
            "    system($cmd);\n"
            "}",
            "CWE-78",
        )
        assert res.outcome == "inconclusive"
        assert res.rule_id == "sanwit:sufficient:shell-command"
        assert "corpus-bounded" in res.reason

    def test_escapeshellarg_inside_single_quotes_breaks_out(
        self, runtime,
    ):
        """The multi-hop shape: a sufficient-looking sanitizer whose
        own quoting collides with target-authored single quotes."""
        res = _check(
            "quote breakout: escapeshellarg output is embedded in a "
            "single-quoted part of the command",
            "function f($x) {\n"
            "    $v = escapeshellarg($x);\n"
            "    $cmd = \"prog '$v'\";\n"
            "    system($cmd);\n"
            "}",
            "CWE-78",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "sanwit:insufficient:shell-squote"

    def test_stripslashes_after_escapeshellcmd_ordering_bug(
        self, runtime,
    ):
        res = _check(
            "escapeshellcmd is undone: stripslashes after it lets "
            "metacharacters pass through",
            "function f($x) {\n"
            "    $v = escapeshellcmd($x);\n"
            "    $v = stripslashes($v);\n"
            '    $cmd = "prog " . $v;\n'
            "    system($cmd);\n"
            "}",
            "CWE-78",
        )
        assert res.outcome == "confirmed"
        ids = {e["payload_id"] for e in res.exhibits}
        assert ids & {"semi", "pipe", "space-arg"}


class TestHtmlFamilyGroundTruth:
    def test_ent_compat_leaves_single_quote(self, runtime):
        res = _check(
            "XSS: htmlspecialchars without ENT_QUOTES leaves the "
            "single-quoted attribute breakable",
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_COMPAT);\n"
            "    echo \"<a title='$v'>\";\n"
            "}",
            "CWE-79",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "sanwit:insufficient:html-attr-squote"
        first = res.exhibits[0]
        assert "'" in first["output"]

    def test_ent_quotes_single_quote_sufficient(self, runtime):
        res = _check(
            "XSS: htmlspecialchars in the single-quoted attribute is "
            "bypassable",
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_QUOTES);\n"
            "    echo \"<a title='$v'>\";\n"
            "}",
            "CWE-79",
        )
        assert res.outcome == "inconclusive"
        assert res.rule_id == "sanwit:sufficient:html-attr-squote"

    def test_ent_quotes_html5_flag_combination(self, runtime):
        """The `|` flag-combination grammar path, executed: ENT_QUOTES
        keeps escaping the single quote whatever the doctype flag."""
        res = _check(
            "XSS: htmlspecialchars in the single-quoted attribute is "
            "bypassable",
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_QUOTES | ENT_HTML5);\n"
            "    echo \"<a title='$v'>\";\n"
            "}",
            "CWE-79",
        )
        assert res.outcome == "inconclusive"
        assert res.rule_id == "sanwit:sufficient:html-attr-squote"
        assert res.chain == ["htmlspecialchars({DATA},ENT_QUOTES|ENT_HTML5)"]

    def test_any_flag_variant_sufficient_for_text_context(self, runtime):
        res = _check(
            "htmlspecialchars bypass in element content",
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_NOQUOTES);\n"
            "    echo '<div>' . $v . '</div>';\n"
            "}",
            "CWE-79",
        )
        assert res.outcome == "inconclusive"
        assert res.rule_id == "sanwit:sufficient:html-text"

    def test_unquoted_attribute_always_breaks(self, runtime):
        res = _check(
            "htmlspecialchars is insufficient for the unquoted "
            "attribute sink",
            "function f($x) {\n"
            "    $v = htmlspecialchars($x, ENT_QUOTES);\n"
            "    echo \"<a title=$v>\";\n"
            "}",
            "CWE-79",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "sanwit:insufficient:html-attr-unquoted"


class TestDockerContainment:
    def test_flood_terminates_bounded_and_leaves_no_container(
        self, runtime,
    ):
        """A flooding probe must land indeterminate within the drain
        grace (not the full timeout) and leave NO container behind:
        --rm's AutoRemove never fires when the client is killed, so
        the cid-based daemon-side cleanup is the guarantee."""
        import subprocess
        import time

        from core.audit.sanwit._execute import (
            DOCKER_TIMEOUT_S,
            execute_probe,
        )

        if runtime.tier != "docker":
            pytest.skip("containment assertion is docker-tier only")

        def running() -> set:
            proc = subprocess.run(
                ["docker", "ps", "-q", "--filter",
                 f"ancestor={runtime.image}"],
                capture_output=True, text=True, timeout=30,
                check=False,
            )
            return set(proc.stdout.split())

        before = running()
        t0 = time.monotonic()
        out = execute_probe(
            runtime,
            "<?php while(true) echo str_repeat('A', 1 << 20);",
            '{"payloads": {}}',
        )
        elapsed = time.monotonic() - t0
        assert not out.ok
        assert "cap" in out.reason
        # Structural bound, daemon-latency tolerant: overflow must
        # resolve within drain grace + kill waits + the cleanup rm
        # timeout — on a loaded daemon each docker call can take tens
        # of seconds, so the claim proven here is "cap/drain-bounded,
        # never riding the witness timeout", not a fixed small wall
        # time.
        assert elapsed < DOCKER_TIMEOUT_S - 10
        time.sleep(2)
        leftovers = running() - before
        assert not leftovers, (
            f"flood left container(s) running: {sorted(leftovers)}"
        )


class TestOrphanRecovery:
    """Re-enacts the observed incident: a probe client SIGKILL'd
    mid-run leaves its container alive — the parent has no exit path
    to run the cidfile belt and --rm's AutoRemove needs a live
    client (a flood probe orphaned this way burned a core for 75+
    minutes). Two independent recovery legs, pinned live: the
    container-side wall clock and the labelled dead-owner sweep."""

    def _cid_of(self, cidfile, timeout_s: float = 60.0) -> str:
        import time

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if cidfile.exists():
                cid = cidfile.read_text().strip()
                if cid:
                    return cid
            time.sleep(0.2)
        return ""

    def _listed(self, docker: str, cid: str, *, all_states: bool) -> bool:
        import subprocess

        q = subprocess.run(
            [docker, "ps", "-q", "--no-trunc",
             *(["-a"] if all_states else []),
             "--filter", f"id={cid}"],
            capture_output=True, text=True, timeout=30, check=False,
        )
        return bool(q.stdout.strip())

    def test_sigkilled_client_orphan_self_terminates(
        self, runtime, tmp_path, monkeypatch,
    ):
        """The container-side ``timeout -s KILL`` wrapper stops the
        burn with NO host-side help at all."""
        import os
        import signal
        import subprocess
        import time

        from core.audit.sanwit import _execute as ex

        if runtime.tier != "docker":
            pytest.skip("orphan re-enactment is docker-tier only")
        monkeypatch.setattr(ex, "_CONTAINER_WALL_CLOCK_S", 5)
        cidfile = tmp_path / "cid"
        cmd = [
            *ex._docker_base_args(
                runtime.docker_path, cidfile=str(cidfile),
            ),
            "php", "-r", "while(true);",  # the CPU-burn shape
        ]
        proc = subprocess.Popen(  # noqa: S603 — fixed argv
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env=ex._safe_env(),
        )
        cid = self._cid_of(cidfile)
        try:
            assert cid, "container never started (no cid)"
            # Wait for RUNNING before killing the client — a SIGKILL
            # landing between create and start leaves a Created
            # container and the test would pass vacuously.
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline and not self._listed(
                runtime.docker_path, cid, all_states=False,
            ):
                time.sleep(0.2)
            assert self._listed(
                runtime.docker_path, cid, all_states=False,
            ), "container never reached the running state"
            os.kill(proc.pid, signal.SIGKILL)  # the incident, exactly
            proc.wait(timeout=10)
            # Non-vacuity of the orphan condition itself: the client
            # is dead, the container is not (the wrapper's 5s bound
            # dwarfs this check).
            assert self._listed(
                runtime.docker_path, cid, all_states=False,
            ), "client death alone stopped the container (vacuous)"
            # Daemon-latency tolerant: the wrapper fires at 5s; the
            # bound proven is "self-terminates promptly, never rides
            # the 90s witness timeout or worse".
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if not self._listed(
                    runtime.docker_path, cid, all_states=False,
                ):
                    break
                time.sleep(1)
            assert not self._listed(
                runtime.docker_path, cid, all_states=False,
            ), "orphaned container survived the container wall clock"
        finally:
            if cid:
                ex._daemon_remove(runtime.docker_path, cid)

    def test_sweep_shape_matrix_reaps_only_the_dead_owner(
        self, runtime, monkeypatch,
    ):
        """The full live matrix in one daemon pass: a dead-owner
        witness container is reaped; a live verified owner's is
        untouched; a FOREIGN unlabelled container is untouched even
        while a hostile witness container's ``owner.start`` label
        value embeds a newline/tab-forged row naming its cid (the
        executed row-injection shape); the hostile container itself
        is left alone (an unverifiable identity is not evidence of
        death)."""
        import subprocess
        import sys as _sys

        from core.audit.sanwit import _execute as ex

        if runtime.tier != "docker":
            pytest.skip("orphan re-enactment is docker-tier only")

        child = subprocess.run(
            [_sys.executable, "-c", "import os; print(os.getpid())"],
            capture_output=True, text=True, check=True,
        )
        dead_pid = child.stdout.strip()

        def start(
            owner_pid: str | None, owner_start: str | None,
        ) -> str:
            args = ex._docker_base_args(runtime.docker_path)
            args.insert(args.index("run") + 1, "-d")
            keep: list[str] = []
            i = 0
            while i < len(args):
                if args[i] == "--label" and owner_pid is None:
                    i += 2  # foreign container: no witness labels
                    continue
                a = args[i]
                if a.startswith(f"{ex._OWNER_PID_LABEL}="):
                    a = f"{ex._OWNER_PID_LABEL}={owner_pid}"
                elif a.startswith(f"{ex._OWNER_START_LABEL}="):
                    a = f"{ex._OWNER_START_LABEL}={owner_start}"
                keep.append(a)
                i += 1
            keep += ["php", "-r", "sleep(60);"]
            proc = subprocess.run(  # noqa: S603 — fixed argv
                keep, capture_output=True, text=True, timeout=60,
                env=ex._safe_env(), check=True,
            )
            return proc.stdout.strip()

        own_pid, own_start = ex._owner_identity()
        orphan = mine = victim = hostile = ""
        try:
            victim = start(None, None)  # foreign: no witness labels
            orphan = start(dead_pid, "123456")
            mine = start(str(own_pid), own_start)
            # The executed injection shape: a forged, fully-vetted
            # row riding in the label VALUE, naming the victim.
            hostile = start(
                dead_pid, f"0\n{victim}\t{dead_pid}\t123456",
            )
            monkeypatch.setattr(ex, "_SWEEP_DONE", False)
            ex._sweep_dead_owner_containers(runtime.docker_path)
            # The sweep's kill initiates daemon-side AutoRemove on a
            # --rm container; removal completes asynchronously, so
            # poll (bounded) rather than racing it.
            import time

            deadline = time.monotonic() + 30
            while time.monotonic() < deadline and self._listed(
                runtime.docker_path, orphan, all_states=True,
            ):
                time.sleep(1)
            assert not self._listed(
                runtime.docker_path, orphan, all_states=True,
            ), "dead-owner container survived the sweep"
            assert self._listed(
                runtime.docker_path, mine, all_states=True,
            ), "sweep reaped a live verified owner's container"
            assert self._listed(
                runtime.docker_path, victim, all_states=True,
            ), "label-value injection steered a reap at a foreign cid"
            assert self._listed(
                runtime.docker_path, hostile, all_states=True,
            ), "unverifiable identity was treated as death evidence"
        finally:
            for cid in (orphan, mine, victim, hostile):
                if cid:
                    ex._daemon_remove(runtime.docker_path, cid)


class TestReceiptScoping:
    def test_interpreter_version_recorded(self, runtime):
        res = _check(
            "argument injection despite escapeshellcmd",
            "function f($x) {\n"
            "    $v = escapeshellcmd($x);\n"
            '    system("prog " . $v);\n'
            "}",
            "CWE-88",
        )
        version = res.interpreter.get("version", "")
        assert version and version[0].isdigit()
        assert res.interpreter.get("tier") in ("native", "docker")
