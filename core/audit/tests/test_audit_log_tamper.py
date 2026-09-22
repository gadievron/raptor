"""A validly-stamped audit-log row edited in place loses all authority.

The forged-row and cross-run pins cover rows an attacker writes whole
(no token, or a token minted for a sibling run). The remaining lever
is TAMPERING: take a row this install genuinely minted for this run —
its token verifies as written — and mutate a meaningful field in the
``.audit-log.jsonl`` file (upgrade an outcome, redirect a site, flip a
status). The token covers the WHOLE row, so any field edit must fail
verification: :func:`core.audit.record.load_verified_audit_log` drops
the row, and every authority consumer behaves as if it was never
written (the site re-reviews / the function re-enters the workqueue —
the fail-toward-NOT-suppressing direction). Both tamper shapes are
covered: stamped-then-field-mutated (token present but stale) and
token-field-strip (demoted to the unstamped tier).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable


def _rows(out_dir: Path) -> list[dict[str, Any]]:
    log = out_dir / ".audit-log.jsonl"
    return [
        json.loads(line)
        for line in log.read_text().splitlines() if line.strip()
    ]


def _mutate_row(
    out_dir: Path,
    match: Callable[[dict[str, Any]], bool],
    mutate: Callable[[dict[str, Any]], Any],
) -> None:
    """Edit the matching row(s) in place on disk — the attacker's
    post-write edit. The integrity token is left exactly as minted
    unless ``mutate`` touches it."""
    rows = _rows(out_dir)
    hit = False
    for row in rows:
        if match(row):
            mutate(row)
            hit = True
    assert hit, "fixture bug: no row matched the mutation predicate"
    log = out_dir / ".audit-log.jsonl"
    log.write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows)
    )


class TestLoaderDropsTamperedRow:
    """load_verified_audit_log keeps the intact stamped rows around a
    mutated one and drops exactly the mutated row."""

    def _seed(self, out_dir: Path) -> None:
        from core.audit.record import append_audit_log

        append_audit_log(out_dir, {"action": "context", "key": "a"})
        append_audit_log(out_dir, {
            "action": "orchestrator_review", "key": "src/a.c:f:1",
            "status": "suspicious",
        })
        append_audit_log(out_dir, {"action": "context", "key": "b"})

    def test_field_mutated_row_drops_neighbors_survive(
        self, tmp_path: Path,
    ):
        from core.audit.record import load_verified_audit_log

        self._seed(tmp_path)
        _mutate_row(
            tmp_path,
            lambda r: r.get("action") == "orchestrator_review",
            lambda r: r.update(status="clean"),
        )
        kept = load_verified_audit_log(tmp_path)
        assert [r.get("key") for r in kept] == ["a", "b"]

    def test_token_stripped_row_drops(self, tmp_path: Path):
        from core.audit.record import load_verified_audit_log
        from core.coverage import journal_mac

        self._seed(tmp_path)
        _mutate_row(
            tmp_path,
            lambda r: r.get("action") == "orchestrator_review",
            lambda r: r.pop(journal_mac.TOKEN_KEY, None),
        )
        kept = load_verified_audit_log(tmp_path)
        assert [r.get("key") for r in kept] == ["a", "b"]


class TestFailOpenSiteNotDeferredByTamperedRow:
    """A ``fail_open_check`` row edited after minting must not earn
    its CWE-252 census-site deferral (deferral SUPPRESSES the site)."""

    def test_outcome_upgrade_does_not_defer(self, tmp_path: Path):
        # Genuinely minted with a NON-granting outcome, then upgraded
        # on disk to "confirmed" — the strongest tamper shape: every
        # field except one matches a real row this install wrote.
        from core.audit.orchestrator import _fail_open_adjudicated_sites
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, {
            "action": "fail_open_check", "outcome": "skipped",
            "file": "src/a.c", "handler": {"line": 12},
        })
        _mutate_row(
            tmp_path,
            lambda r: r.get("action") == "fail_open_check",
            lambda r: r.update(outcome="confirmed"),
        )
        assert _fail_open_adjudicated_sites(tmp_path) == set()

    def test_site_redirect_does_not_defer_either_site(
        self, tmp_path: Path,
    ):
        # A genuinely adjudicated site redirected to another file:
        # neither the planted site nor the original may defer, while
        # an intact stamped row alongside keeps ITS deferral — the
        # drop is per-row, not per-log.
        from core.audit.orchestrator import _fail_open_adjudicated_sites
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, {
            "action": "fail_open_check", "outcome": "confirmed",
            "file": "src/a.c", "handler": {"line": 12},
        })
        append_audit_log(tmp_path, {
            "action": "fail_open_check", "outcome": "confirmed",
            "file": "src/ok.c", "handler": {"line": 3},
        })
        _mutate_row(
            tmp_path,
            lambda r: r.get("file") == "src/a.c",
            lambda r: r.update(file="src/b.c"),
        )
        assert _fail_open_adjudicated_sites(tmp_path) == {
            ("src/ok.c", 3),
        }


class TestResumeNotSuppressedByTamperedRow:
    """A review row edited after minting must not suppress re-review
    on resume (``get_reviewed_set`` drops functions from the
    workqueue)."""

    def test_status_upgrade_does_not_suppress(self, tmp_path: Path):
        # "error" rows are excluded from the reviewed set (transient,
        # must retry); upgrading one to "clean" on disk must not turn
        # it into a suppression.
        from core.audit.orchestrator import get_reviewed_set
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, {
            "action": "orchestrator_review", "key": "src/a.c:f:1",
            "status": "error",
        })
        append_audit_log(tmp_path, {
            "action": "orchestrator_review", "key": "src/a.c:g:9",
            "status": "clean",
        })
        _mutate_row(
            tmp_path,
            lambda r: r.get("key") == "src/a.c:f:1",
            lambda r: r.update(status="clean"),
        )
        reviewed = get_reviewed_set(tmp_path)
        assert "src/a.c:f:1" not in reviewed
        assert "src/a.c:f" not in reviewed
        # The intact stamped row alongside still suppresses ITS key.
        assert "src/a.c:g:9" in reviewed

    def test_key_redirect_does_not_suppress(self, tmp_path: Path):
        # Redirecting a genuine reviewed key at an unreviewed
        # function must not suppress either function.
        from core.audit.orchestrator import get_reviewed_set
        from core.audit.record import append_audit_log

        append_audit_log(tmp_path, {
            "action": "orchestrator_review", "key": "src/a.c:f:1",
            "status": "clean",
        })
        _mutate_row(
            tmp_path,
            lambda r: r.get("key") == "src/a.c:f:1",
            lambda r: r.update(key="src/b.c:victim:7"),
        )
        reviewed = get_reviewed_set(tmp_path)
        assert reviewed == set()
