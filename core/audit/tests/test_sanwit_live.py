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
