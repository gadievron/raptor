"""Phase 32 — rename cryptic give_up_reason internal names.

User feedback 2026-05-14 mid-bench: *"reasonable names and explanations"*
after seeing `⊘no_image_without_resolve` in live bench narrative. Phase 24A
renamed STATUSES with back-compat alias map. Phase 32 does same for the
give_up_reason internal values:

  silent_end_turn          → quit_without_verify_or_giveup
  no_image_without_resolve → skipped_image_lookup
  refusal_persistent       → refusal_no_recovery

Engine emits NEW canonical names. Read-path consumers normalize via
`GIVE_UP_REASON_ALIAS_MAP` for back-compat with historical audit JSONLs.

Per Phase 21.1 / 26.1 / 24B.1 pattern: xfail(strict=True) RED → markers
removed atomically when Phase 32.2 lands.
"""
from __future__ import annotations


def _try_import_alias_map():
    try:
        from cve_env.models import GIVE_UP_REASON_ALIAS_MAP
        return GIVE_UP_REASON_ALIAS_MAP
    except ImportError:
        return None


# ---------------------------------------------------------------------------
# RED tests via xfail(strict=True). Removed atomically by Stage 32.2.
# ---------------------------------------------------------------------------


def test_alias_map_silent_end_turn():
    """silent_end_turn → quit_without_verify_or_giveup."""
    m = _try_import_alias_map()
    assert m is not None
    assert m["silent_end_turn"] == "quit_without_verify_or_giveup"


def test_alias_map_no_image_without_resolve():
    """no_image_without_resolve → skipped_image_lookup."""
    m = _try_import_alias_map()
    assert m is not None
    assert m["no_image_without_resolve"] == "skipped_image_lookup"


def test_alias_map_refusal_persistent():
    """refusal_persistent → refusal_no_recovery."""
    m = _try_import_alias_map()
    assert m is not None
    assert m["refusal_persistent"] == "refusal_no_recovery"


def test_loop_py_emits_new_names():
    """loop.py emits the 3 NEW canonical names; no occurrences of old names
    in production code paths.

    Constraint: search only string-literal emit sites (`give_up_reason = "..."`),
    NOT docstrings or comments (which may discuss old names for back-compat
    historical context).
    """
    from pathlib import Path

    import cve_env
    src = (Path(cve_env.__file__).resolve().parent / "agent" / "loop.py").read_text()
    # NEW names must appear in emit sites
    assert 'give_up_reason = "quit_without_verify_or_giveup"' in src
    assert 'give_up_reason = "skipped_image_lookup"' in src
    assert 'give_up_reason = "refusal_no_recovery"' in src
    # OLD names should NOT appear in string-literal emit sites
    assert 'give_up_reason = "silent_end_turn"' not in src
    assert 'give_up_reason = "no_image_without_resolve"' not in src
    assert 'give_up_reason = "refusal_persistent"' not in src
