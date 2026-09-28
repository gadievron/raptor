"""Live sanitizer-witness matrix — executes a real PHP interpreter.

Skips WITH NOTICE when no tier resolves (no php-cli on PATH and no
usable docker + pinned image): everything above the execution
boundary is covered hermetically by the sibling test files; this
file is the executed ground truth for the two shipped families.

Every case is a KNOWN truth of the PHP builtins + sink-context
parsing rules; a failure here means the witness would mint wrong
verdicts on real targets.

Runtime-degradation discipline: under concurrent test load the
resolved tier itself can fail to carry a probe (the parent-side
witness deadline, a docker client that cannot be spawned) — the
product honestly reports that run as outcome ``error``, which is a
statement about THIS host right now, not about the PHP ground truth
pinned here. Those transport shapes skip with the reason
(``_skip_if_runtime_degraded``); every product-classified error and
every verdict on a healthy runtime keeps its exact assertion.
"""

from __future__ import annotations

import re
from collections.abc import Callable

import pytest

from core.audit.sanwit import SanwitResult, run_sanwit_check
from core.audit.sanwit._execute import (
    ExecOutcome,
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


# Reason shapes minted ONLY by the execution transport
# (core.audit.sanwit._execute) when the runtime fails to carry the
# probe at all: the parent-side witness deadline (both tiers — the
# probe itself is milliseconds of PHP work, so on this matrix a
# deadline hit means the runtime, not the chain), a client that
# could not be spawned or read (Popen/pipe OSError), the pre-exec
# chmod of the bind-mounted script dir, and docker's reserved exit
# code 125 ("docker run itself failed" — the generated probe only
# ever exits 0, 3, or a PHP fatal code, never 125). Every OTHER
# error shape describes what the executed probe DID (per-payload
# indeterminacy, unparseable/unauthenticated output, the stdout
# cap, any other exit code) and stays a hard failure here.
#
# The transport/product partition above is docker-tier-true only:
# on the native tier just the deadline spelling is transport-only —
# the native arm's broad "execution failed: <Exc>" catch also wraps
# the dark_verify script-witness machinery (product code), so it is
# deliberately NOT treated as degradation here.
#
# Anchoring: \Z, not $ — $ also matches before a trailing newline,
# which would widen the deadline arm to suffixed spellings.
_RUNTIME_DEGRADED_RE = re.compile(
    r"witness timed out after \d+s\Z"
    r"|docker execution failed: "
    r"|chmod failed: "
    r"|probe exited 125\b",
)


def _skip_if_runtime_degraded(res: SanwitResult) -> None:
    """Skip (with the transport's reason) when the live runtime
    degraded instead of carrying the probe. Same tier-guard idiom as
    the module fixture's no-tier skip, one layer further down: the
    tier resolved earlier but could not execute NOW. A product
    regression that misclassifies on a healthy runtime — including
    one that mints outcome ``error`` for a reason the transport
    never produces — still fails the exact assertions that follow.
    """
    if (
        res.outcome == "error"
        and res.rule_id == "sanwit:error"
        and _RUNTIME_DEGRADED_RE.match(res.reason or "")
    ):
        pytest.skip(f"live witness runtime degraded: {res.reason}")


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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
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
        _skip_if_runtime_degraded(res)
        assert res.outcome == "confirmed"
        assert res.rule_id == "sanwit:insufficient:html-attr-unquoted"


class TestDockerContainment:
    # A real docker run that must sit through the drain grace before
    # the daemon-side cleanup can be asserted — ~15s of genuine wall
    # cost even unloaded; over the fast tier's budget.
    @pytest.mark.slow
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
        # The daemon-side `docker rm -f` is issued before execute_probe
        # returns, but on a loaded daemon its effect can land seconds
        # later — poll for the empty state instead of trusting one
        # fixed grace, so the assertion tests containment (cleanup WAS
        # issued and completes) rather than daemon latency.
        deadline = time.monotonic() + 30
        while True:
            leftovers = running() - before
            if not leftovers or time.monotonic() >= deadline:
                break
            time.sleep(1)
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
        _skip_if_runtime_degraded(res)
        version = res.interpreter.get("version", "")
        assert version and version[0].isdigit()
        assert res.interpreter.get("tier") in ("native", "docker")


def _error_result(reason: str) -> SanwitResult:
    return SanwitResult(
        tool="sanwit", file_path="web/a.php", function_name="f",
        outcome="error", verdict="error", rule_id="sanwit:error",
        reason=reason,
    )


class TestRuntimeDegradedGuard:
    """The degraded-runtime skip guard, both directions — HERMETIC
    (no PHP, no docker daemon; no ``runtime`` fixture), so the
    guard's own contract is enforced on every host, including the
    ones where the live matrix skips."""

    def _stub(
        self, monkeypatch: pytest.MonkeyPatch, outcome: ExecOutcome,
    ) -> None:
        """Pin resolution + execution at the module seam (the
        sibling test_sanwit_channel.py idiom) so the real live-test
        bodies run against an injected transport outcome."""
        from core.audit.sanwit import _execute as ex

        rt = ex.PhpRuntime(
            tier="docker", version="8.3.0",
            docker_path="/usr/bin/docker", image=ex.DOCKER_IMAGE,
        )
        monkeypatch.setattr(
            ex, "resolve_php_runtime", lambda refresh=False: rt,
        )
        monkeypatch.setattr(
            ex, "execute_probe", lambda *a, **k: outcome,
        )

    @staticmethod
    def _fail_on_skip(call: Callable[[], None]) -> None:
        """No-skip-direction fence: an unexpected ``pytest.skip``
        raised by the code under test would otherwise propagate as
        SKIPPED — straight through ``pytest.raises``, which re-raises
        it — and the test would pass silently, the exact masking this
        class exists to rule out. An unexpected skip is a hard
        failure."""
        try:
            call()
        except pytest.skip.Exception as exc:
            pytest.fail(
                f"guard skipped a product-visible shape: {exc}",
            )

    def test_degraded_transport_skips_the_live_assertions(
        self, monkeypatch,
    ) -> None:
        """Direction one: the transport-deadline shape turns the
        ground-truth hard failure into a skip naming the reason."""
        from core.audit.sanwit import _execute as ex

        self._stub(monkeypatch, ex.ExecOutcome(
            ok=False,
            reason=f"witness timed out after {ex.DOCKER_TIMEOUT_S}s",
        ))
        with pytest.raises(
            pytest.skip.Exception, match="runtime degraded",
        ):
            TestShellFamilyGroundTruth(
            ).test_escapeshellarg_command_position_sufficient(
                runtime=None,
            )

    def test_product_misclassification_still_fails(
        self, monkeypatch,
    ) -> None:
        """Direction two: on a HEALTHY runtime (execution succeeded)
        a product regression that lands in outcome ``error`` — here
        unauthenticated probe output — must still fail the exact
        ground-truth assertion, never skip."""
        from core.audit.sanwit import _execute as ex

        self._stub(monkeypatch, ex.ExecOutcome(
            ok=True, stdout="not the probe's authenticated json",
        ))

        def body() -> None:
            with pytest.raises(AssertionError):
                TestShellFamilyGroundTruth(
                ).test_escapeshellarg_command_position_sufficient(
                    runtime=None,
                )

        self._fail_on_skip(body)

    @pytest.mark.parametrize("reason", [
        "witness timed out after 90s",   # docker-tier deadline
        "witness timed out after 30s",   # native-tier deadline
        "docker execution failed: FileNotFoundError",
        "docker execution failed: OSError",
        "chmod failed: PermissionError",
        "probe exited 125: docker: error response from daemon",
    ])
    def test_transport_reasons_skip(self, reason: str) -> None:
        with pytest.raises(
            pytest.skip.Exception, match="runtime degraded",
        ):
            _skip_if_runtime_degraded(_error_result(reason))

    @pytest.mark.parametrize("reason", [
        # Adjudication of what the probe DID — product territory.
        "chain execution indeterminate for 2/6 payloads — "
        "sufficiency cannot be adjudicated",
        "unauthenticated/unparseable probe output: no JSON document "
        "in probe output",
        "probe stdout exceeded the 65536-byte cap — terminated, "
        "indeterminate",
        "probe exited 255: PHP Fatal error",
        "probe exited 3",       # the probe's own bad-payload exit
        "probe exited 1",
        # Prefix look-alikes that are NOT the transport shapes.
        "witness timed out after 90s of deliberation",
        "witness timed out after 90s\n",  # \Z: trailing newline out
        "probe exited 1255",
    ])
    def test_product_error_reasons_do_not_skip(
        self, reason: str,
    ) -> None:
        self._fail_on_skip(
            lambda: _skip_if_runtime_degraded(_error_result(reason)),
        )

    def test_non_error_outcomes_never_skip(self) -> None:
        """The guard keys on the full error identity, not the reason
        text alone: a classified verdict whose reason merely QUOTES a
        transport phrase passes through to its assertions."""
        res = SanwitResult(
            tool="sanwit", file_path="web/a.php", function_name="f",
            outcome="confirmed", verdict="insufficient",
            rule_id="sanwit:insufficient:shell-command",
            reason="witness timed out after 90s",
        )
        self._fail_on_skip(lambda: _skip_if_runtime_degraded(res))

    def test_guard_matches_the_reason_the_transport_mints(
        self, monkeypatch,
    ) -> None:
        """Anti-drift pin: the deadline reason the guard keys on is
        the one ``_run_capped_pipes`` actually produces (a real
        client process, no docker — the deadline shrunk to keep the
        pin cheap)."""
        from core.audit.sanwit import _execute as ex

        monkeypatch.setattr(ex, "DOCKER_TIMEOUT_S", 1)
        out = ex._run_capped_pipes(
            ["/bin/sleep", "30"], env=ex._safe_env(),
        )
        assert not out.ok
        assert _RUNTIME_DEGRADED_RE.match(out.reason), out.reason

    def test_guard_matches_the_spawn_failure_reason(
        self, tmp_path,
    ) -> None:
        """Anti-drift pin for the client-spawn shape (Popen OSError
        inside the transport)."""
        from core.audit.sanwit import _execute as ex

        out = ex._run_capped_pipes(
            [str(tmp_path / "no-such-client")], env=ex._safe_env(),
        )
        assert not out.ok
        assert _RUNTIME_DEGRADED_RE.match(out.reason), out.reason

    # Every live body that runs a `_check`, enumerated: adding a new
    # live check test WITHOUT the guard (or without extending this
    # set) must be a deliberate decision, never a silent gap.
    _GUARDED_LIVE_TESTS: frozenset[str] = frozenset({
        "test_escapeshellcmd_argument_injection",
        "test_escapeshellarg_command_position_sufficient",
        "test_escapeshellarg_inside_single_quotes_breaks_out",
        "test_stripslashes_after_escapeshellcmd_ordering_bug",
        "test_ent_compat_leaves_single_quote",
        "test_ent_quotes_single_quote_sufficient",
        "test_ent_quotes_html5_flag_combination",
        "test_any_flag_variant_sufficient_for_text_context",
        "test_unquoted_attribute_always_breaks",
        "test_interpreter_version_recorded",
    })

    def test_every_check_site_carries_the_guard(self) -> None:
        """Structural fence: the hermetic direction tests route ONE
        live body through the guard; nothing else would notice the
        guard dropped from the other nine. Parse this file and pin
        the placement — every `_check` site is followed by
        `_skip_if_runtime_degraded` before its first assert, and the
        set of guarded bodies is exactly the enumeration above."""
        import ast
        from pathlib import Path

        def calls(stmt: ast.stmt, name: str) -> bool:
            return any(
                isinstance(n, ast.Call)
                and isinstance(n.func, ast.Name)
                and n.func.id == name
                for n in ast.walk(stmt)
            )

        tree = ast.parse(
            Path(__file__).read_text(encoding="utf-8"),
        )
        seen: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            check_at = [
                i for i, stmt in enumerate(node.body)
                if calls(stmt, "_check")
            ]
            if not check_at:
                continue
            seen.add(node.name)
            guard_at = [
                i for i, stmt in enumerate(node.body)
                if calls(stmt, "_skip_if_runtime_degraded")
            ]
            assert guard_at, (
                f"{node.name} runs a live check without "
                "_skip_if_runtime_degraded"
            )
            assert min(guard_at) > max(check_at), (
                f"{node.name}: the guard must run AFTER the check"
            )
            assert_at = [
                i for i, stmt in enumerate(node.body)
                if isinstance(stmt, ast.Assert)
            ]
            assert not assert_at or min(guard_at) < min(assert_at), (
                f"{node.name}: the guard must run before the first "
                "ground-truth assert"
            )
        assert seen == self._GUARDED_LIVE_TESTS
