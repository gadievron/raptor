"""Tests for the typosquat-denylist candidate generator (Stages 1–2).

Mechanical, LLM-free, offline. Stage 1 (`generate_candidates`) is the validated
rank+distance heuristic emitting candidates; Stage 2 (`pending_candidates`)
subtracts the denylist + reviewed-legit so the delta de-noises.
"""

from __future__ import annotations

import json

from packages.sca.supply_chain import typosquat_audit as A
from packages.sca.supply_chain.typosquat_audit import (
    Candidate,
    _load_name_set,
    audit,
    generate_candidates,
    pending_candidates,
    render_markdown,
    render_text,
)

_FILL = [f"pkg{i}" for i in range(60)]   # pad past the default min_pos=50


# ---------------------------------------------------------------------------
# Stage 1 — generate_candidates
# ---------------------------------------------------------------------------

def test_flags_distance1_lower_ranked_twin():
    ranked = ["lodash"] + _FILL + ["loadash"]
    cands = generate_candidates(ranked)
    c = next((c for c in cands if c.name == "loadash"), None)
    assert c is not None
    assert c.near_twin == "lodash" and c.distance == 1
    assert c.twin_rank == 1 and c.rank == len(ranked)


def test_short_names_skipped_by_default_min_len():
    # 3-char near-pair (abc/abd) — below default min_len=6, so not a candidate
    # (short names' distance-1 neighbours are dominated by natural collisions).
    ranked = ["abc"] + _FILL + ["abd"]
    assert generate_candidates(ranked) == []


def test_min_len_is_tunable():
    ranked = ["abcdef"] + _FILL + ["abcxef"]
    assert any(c.name == "abcxef" for c in generate_candidates(ranked, min_len=6))
    assert generate_candidates(ranked, min_len=7) == []


def test_distance2_not_flagged():
    ranked = ["abcdef"] + _FILL + ["abxxef"]   # two substitutions
    assert generate_candidates(ranked) == []


def test_similar_rank_pair_not_flagged():
    # Two near-names at adjacent ranks: the twin does not out-rank by `ratio`,
    # so neither is a candidate (the rule that spares legit color/colors pairs).
    ranked = _FILL + ["abcdef", "abcdeg"]
    assert generate_candidates(ranked) == []


def test_top_names_never_flagged():
    # A near-twin inside the protected top-min_pos window is not a candidate.
    ranked = ["lodash", "loadash"] + _FILL
    assert not any(c.name == "loadash" for c in generate_candidates(ranked))


def test_ratio_zero_does_not_crash():
    # Guarded with max(1, ratio); must not ZeroDivisionError.
    generate_candidates(["abcdef"] + _FILL + ["abcdeg"], ratio=0)


# ---------------------------------------------------------------------------
# loader — _load_name_set (tolerant of both file shapes)
# ---------------------------------------------------------------------------

def test_load_name_set_bare_list(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"npm": ["loadash", "EvilPkg"]}))
    assert _load_name_set(p, "npm") == {"loadash", "evilpkg"}
    assert _load_name_set(p, "PyPI") == set()


def test_load_name_set_enriched_dict_and_comment(tmp_path):
    p = tmp_path / "d.json"
    p.write_text(json.dumps({"_comment": "x",
                             "npm": {"LoAdAsh": {"near_twin": "lodash"}}}))
    assert _load_name_set(p, "npm") == {"loadash"}


def test_load_name_set_missing_or_malformed(tmp_path):
    assert _load_name_set(tmp_path / "nope.json", "npm") == set()
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert _load_name_set(bad, "npm") == set()


# ---------------------------------------------------------------------------
# Stage 2 — pending_candidates
# ---------------------------------------------------------------------------

def test_pending_subtracts_denylist_and_reviewed_legit(tmp_path):
    dl = tmp_path / "dl.json"
    dl.write_text(json.dumps({"npm": ["loadash"]}))
    rl = tmp_path / "rl.json"
    rl.write_text(json.dumps({"npm": {"preact": {"near_twin": "react"}}}))
    ranked = (["lodash", "react", "express"] + _FILL
              + ["loadash", "preact", "expresss"])
    pending = pending_candidates(ranked, "npm",
                                 denylist_path=dl, reviewed_legit_path=rl)
    # loadash → denylist, preact → reviewed_legit; only the unclassified
    # near-name survives as pending.
    assert {c.name for c in pending} == {"expresss"}


def test_pending_against_bundled_files_filters_loadash():
    # The shipped denylist carries loadash; pending must not re-surface it.
    ranked = ["lodash"] + _FILL + ["loadash"]
    assert not any(c.name == "loadash"
                   for c in pending_candidates(ranked, "npm"))


# ---------------------------------------------------------------------------
# audit() — fetch + delta per ecosystem
# ---------------------------------------------------------------------------

def test_audit_uses_stub_feed_and_bundled_denylist(monkeypatch):
    ranked = ["express", "lodash"] + _FILL + ["expresss", "loadash"]
    monkeypatch.setitem(A._RANKED_FETCHERS, "npm",
                        lambda http, top_n: ranked)
    res = audit(object(), ["npm"])
    names = {c.name for c in res["npm"]}
    assert "expresss" in names          # new near-name → pending
    assert "loadash" not in names       # bundled denylist filters it


def test_audit_fail_soft_on_fetch_error(monkeypatch):
    def boom(http, top_n):
        raise RuntimeError("feed down")
    monkeypatch.setitem(A._RANKED_FETCHERS, "npm", boom)
    assert audit(object(), ["npm"]) == {}     # skipped, not raised


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def test_render_empty_is_blank_markdown_and_none_text():
    assert render_markdown({"npm": []}) == ""
    assert "No pending" in render_text({"npm": []})


def test_render_markdown_lists_candidate():
    md = render_markdown({"npm": [Candidate("expresss", "express", 3000, 5, 1)]})
    assert "expresss" in md and "express" in md
    assert "pending triage" in md


def test_main_writes_report_and_empty_skips(monkeypatch, tmp_path):
    monkeypatch.setattr(
        A, "audit",
        lambda *a, **k: {"npm": [Candidate("expresss", "express", 3000, 5, 1)]})
    out = tmp_path / "r.md"
    assert A.main(["--format", "markdown", "--out", str(out)]) == 0
    assert "expresss" in out.read_text()

    monkeypatch.setattr(A, "audit", lambda *a, **k: {"npm": []})
    out2 = tmp_path / "r2.md"
    A.main(["--format", "markdown", "--out", str(out2)])
    assert out2.read_text() == ""        # empty → workflow's [ -s ] skips nudge


# ---------------------------------------------------------------------------
# shipped data-file guards
# ---------------------------------------------------------------------------

def test_bundled_reviewed_legit_valid_and_seeded():
    raw = json.loads(A._REVIEWED_LEGIT_PATH.read_text(encoding="utf-8"))
    assert "preact" in raw.get("npm", {})


def test_triage_subcommand_registered():
    from packages.sca.cli import SUBCOMMANDS
    assert "triage" in SUBCOMMANDS


def test_run_llm_triage_falls_back_without_llm(monkeypatch):
    # No configured LLM → the --llm path degrades to listing the candidates
    # (never blocks), and fetches no registry evidence.
    import packages.sca.llm as llm
    monkeypatch.setattr(llm, "get_llm_client", lambda: None)
    out = A.run_llm_triage(
        {"npm": [Candidate("through3", "through", 1858, 74, 1)]},
        reviewed_legit_path=A._REVIEWED_LEGIT_PATH)
    assert "No LLM" in out and "through3" in out


def test_render_reaudit_empty_and_flagged():
    assert A._render_reaudit({}) == ""        # nothing flagged → workflow skips
    out = A._render_reaudit(
        {"npm": [("evil", "now carries a malicious (MAL-) advisory")]})
    assert "evil" in out and "flagged" in out


def test_render_reaudit_llm():
    from packages.sca.supply_chain.typosquat_triage import Verdict
    enriched = {"npm": [("evil", "now deprecated",
                         Verdict("evil", "typosquat", "high", "looks like a squat"),
                         "MOVE TO DENYLIST (confirm)")]}
    out = A._render_reaudit_llm(enriched)
    assert "evil" in out and "typosquat" in out and "DENYLIST" in out
    assert A._render_reaudit_llm({}) == "No reviewed-legit entries flagged.\n"
