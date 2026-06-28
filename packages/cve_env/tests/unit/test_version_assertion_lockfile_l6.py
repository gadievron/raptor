"""L6 re-instatement (2026-06-05) — lockfile-grep + versioned-dir finds count as
version-assertion commands.

History: the 4 arms were added (7a5a653, Phase 58-EXP), then reverted (f794d70) as
DORMANT — the 12-CVE experimental corpus never exercised them (0/22 firings). The
revert was a precondition-miss, NOT a correctness problem. Re-instated now because the
precondition is MET: composer.lock / package-lock.json appear in 77 audit files across the
broader corpus (lockfile-based version discovery is in real use).

Safety: VERSION_ASSERTION_CMD_PATTERN only *recognizes* the command as a version assertion;
the Phase 52.1 strict-marker gate (loop._has_specific_version_marker) still requires the
exec_check's expected_stdout_contains to carry the actual version digits, so a bare
lockfile-grep without a version marker cannot false-promote a broken build to `success`.
"""

from cve_env.config import VERSION_ASSERTION_CMD_PATTERN as P


def test_composer_lock_grep_recognized() -> None:
    assert P.search("grep symfony/http-kernel composer.lock")


def test_package_lock_json_grep_recognized() -> None:
    assert P.search("cat package-lock.json | grep lodash")


def test_pipfile_lock_grep_recognized() -> None:
    assert P.search("grep django Pipfile.lock")


def test_versioned_dir_find_recognized() -> None:
    assert P.search("find /opt -name 'wlserver_10.3'")


def test_unrelated_command_not_matched() -> None:
    # guard against over-broad matching — a plain listing is NOT a version assertion.
    assert not P.search("ls -la /app")
    assert not P.search("cat /app/index.php")
