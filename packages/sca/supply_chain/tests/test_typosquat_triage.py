"""Tests for the triage gate (Stage 4) — the false-positive asymmetry that
keeps the curation loop sound. Pure, offline; no network or LLM."""

from __future__ import annotations

import json

from packages.sca.supply_chain.typosquat_audit import Candidate
from packages.sca.supply_chain.typosquat_triage import (
    Disposition,
    Evidence,
    Verdict,
    _age_days,
    _to_verdict,
    apply_auto_legit,
    collect_evidence,
    collect_evidence_rich,
    gate,
    osv_malicious,
    reaudit_recommendation,
    reaudit_reviewed_legit,
    render_evidence,
    triage_ecosystem,
    triage_pending,
)

_CAND = Candidate(name="loadash", near_twin="lodash", rank=3851,
                  twin_rank=1, distance=1)


def _ev(**kw) -> Evidence:
    base = dict(candidate=_CAND, description="x", num_versions=10,
                age_days=2000, has_repo=True, deprecated=False)
    base.update(kw)
    return Evidence(**base)


def _v(verdict, confidence="high") -> Verdict:
    return Verdict(name="loadash", verdict=verdict, confidence=confidence)


# ---------------------------------------------------------------------------
# The FP-creating direction is NEVER auto-applied
# ---------------------------------------------------------------------------

def test_typosquat_verdict_always_routes_to_human_confirm():
    # Even high-confidence + strong evidence: adding to the denylist flags the
    # name for every user, so it must be human-confirmed, never auto.
    r = gate(_ev(), _v("typosquat", "high"))
    assert r.disposition is Disposition.CONFIRM_SQUAT


def test_typosquat_never_yields_auto_legit():
    for conf in ("high", "medium", "low"):
        r = gate(_ev(), _v("typosquat", conf))
        assert r.disposition is not Disposition.AUTO_LEGIT


# ---------------------------------------------------------------------------
# The FP-safe direction may auto-resolve — but only past the evidence floor
# ---------------------------------------------------------------------------

def test_legit_with_strong_evidence_auto_files():
    r = gate(_ev(age_days=2000, num_versions=10, has_repo=True), _v("legit"))
    assert r.disposition is Disposition.AUTO_LEGIT


def test_legit_but_young_escalates():
    r = gate(_ev(age_days=30), _v("legit"))
    assert r.disposition is Disposition.ESCALATE
    assert "30d" in r.reason


def test_legit_but_thin_release_history_escalates():
    r = gate(_ev(num_versions=1), _v("legit"))
    assert r.disposition is Disposition.ESCALATE
    assert "release" in r.reason


def test_legit_but_no_repo_escalates():
    r = gate(_ev(has_repo=False), _v("legit"))
    assert r.disposition is Disposition.ESCALATE
    assert "repo" in r.reason.lower()


def test_legit_but_deprecated_escalates():
    # The loadash shape: an npm deprecation-holder must never auto-clear as legit.
    r = gate(_ev(deprecated=True), _v("legit"))
    assert r.disposition is Disposition.ESCALATE
    assert "deprecated" in r.reason


def test_legit_but_unknown_age_escalates():
    r = gate(_ev(age_days=None), _v("legit"))
    assert r.disposition is Disposition.ESCALATE


def test_legit_below_high_confidence_escalates_not_auto():
    # Adversarial: a description crafted to steer the verdict trips run_stage's
    # preflight, which halves confidence to medium. Strong evidence + a
    # 'legit' verdict at medium/low confidence must ESCALATE, never auto-file —
    # closes the prompt-injection -> auto-suppress path.
    for conf in ("medium", "low"):
        r = gate(_ev(age_days=2000, num_versions=20, has_repo=True),
                 _v("legit", conf))
        assert r.disposition is Disposition.ESCALATE, conf
    # Clean high-confidence legit still auto-files.
    assert gate(_ev(), _v("legit", "high")).disposition is Disposition.AUTO_LEGIT


# ---------------------------------------------------------------------------
# Unsure → human
# ---------------------------------------------------------------------------

def test_unsure_escalates():
    assert gate(_ev(), _v("unsure")).disposition is Disposition.ESCALATE


def test_unknown_verdict_string_escalates():
    assert gate(_ev(), _v("")).disposition is Disposition.ESCALATE


def test_floor_thresholds_are_tunable():
    # A 100-day-old pkg passes a min_age_days=90 floor but fails the default 180.
    ev = _ev(age_days=100)
    assert gate(ev, _v("legit")).disposition is Disposition.ESCALATE
    assert gate(ev, _v("legit"), min_age_days=90).disposition is Disposition.AUTO_LEGIT


# ---------------------------------------------------------------------------
# orchestration + writer
# ---------------------------------------------------------------------------

def _cand(name, twin):
    return Candidate(name=name, near_twin=twin, rank=3000, twin_rank=5, distance=1)


def test_triage_pending_applies_gate_per_candidate():
    cands = [_cand("goodpkg", "goodpkglib"), _cand("evilpkg", "express")]

    def evidence_fn(c):
        return _ev(candidate=c, age_days=2000, num_versions=20, has_repo=True)

    def triage_fn(c, ev):
        return Verdict(name=c.name,
                       verdict="legit" if c.name == "goodpkg" else "typosquat",
                       confidence="high")

    outcomes = triage_pending(cands, evidence_fn, triage_fn)
    by_name = {o.candidate.name: o.gate_result.disposition for o in outcomes}
    assert by_name["goodpkg"] is Disposition.AUTO_LEGIT
    assert by_name["evilpkg"] is Disposition.CONFIRM_SQUAT


def test_apply_auto_legit_writes_only_legit_with_provenance(tmp_path):
    rl = tmp_path / "reviewed_legit.json"
    rl.write_text(json.dumps({"_comment": "keep me",
                              "npm": {"preact": {"near_twin": "react"}}}))
    cands = [_cand("goodpkg", "goodpkglib"), _cand("evilpkg", "express")]
    outcomes = triage_pending(
        cands,
        lambda c: _ev(candidate=c, age_days=2000, num_versions=20, has_repo=True),
        lambda c, ev: Verdict(c.name,
                              "legit" if c.name == "goodpkg" else "typosquat",
                              "high", rationale="real project, 20 releases"),
    )
    filed = apply_auto_legit(outcomes, "npm", rl, model="test-model",
                             now="2026-05-28")
    assert filed == ["goodpkg"]
    data = json.loads(rl.read_text())
    # auto-filed legit recorded with provenance
    assert data["npm"]["goodpkg"]["decided_by"] == "llm"
    assert data["npm"]["goodpkg"]["model"] == "test-model"
    assert data["npm"]["goodpkg"]["near_twin"] == "goodpkglib"
    # the suspected squat is NOT written (human-gated denylist action)
    assert "evilpkg" not in data["npm"]
    # existing entries + comment preserved
    assert "preact" in data["npm"] and data["_comment"] == "keep me"


def test_apply_auto_legit_noop_when_nothing_auto(tmp_path):
    rl = tmp_path / "reviewed_legit.json"      # does not exist
    outcomes = triage_pending(
        [_cand("evilpkg", "express")],
        lambda c: _ev(candidate=c),
        lambda c, ev: Verdict(c.name, "typosquat", "high"),
    )
    assert apply_auto_legit(outcomes, "npm", rl) == []
    assert not rl.exists()                      # nothing written


# ---------------------------------------------------------------------------
# Stage 3 — evidence collection
# ---------------------------------------------------------------------------

def test_age_days_parses_and_degrades():
    assert _age_days(None) is None
    assert _age_days("not-a-date") is None
    assert _age_days("2016-01-01T00:00:00Z") > 3000


def test_collect_evidence_npm():
    doc = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"0.9.0": {}, "1.0.0": {"deprecated": "use lodash",
                                            "homepage": "https://x"}},
        "time": {"created": "2016-09-22T14:15:37.699Z"},
    }
    ev = collect_evidence(_cand("loadash", "lodash"), "npm", lambda n: doc)
    assert ev.num_versions == 2
    assert ev.deprecated is True
    assert ev.has_repo is True
    assert ev.age_days is not None and ev.age_days > 3000


def test_collect_evidence_crates_is_rich():
    doc = {"crate": {"description": "serde framework", "num_versions": 315,
                     "created_at": "2014-12-05T20:20:39Z",
                     "repository": "https://gh/serde", "recent_downloads": 999}}
    ev = collect_evidence(_cand("serdex", "serde"), "Cargo", lambda n: doc)
    assert ev.description == "serde framework"
    assert ev.num_versions == 315 and ev.has_repo
    assert ev.downloads_per_month == 999


def test_collect_evidence_pypi_is_thin():
    doc = {"info": {"yanked": False}, "releases": {"1.0": [], "1.1": []}}
    ev = collect_evidence(_cand("reqursts", "requests"), "PyPI", lambda n: doc)
    assert ev.num_versions == 2 and ev.age_days is None


def test_collect_evidence_miss_or_unmapped_is_empty():
    c = _cand("x", "y")
    assert collect_evidence(c, "Maven", lambda n: {"crate": {}}).num_versions == 0
    assert collect_evidence(c, "npm", lambda n: None).num_versions == 0

    def boom(n):
        raise RuntimeError("registry down")
    ev = collect_evidence(c, "npm", boom)
    assert ev.num_versions == 0 and not ev.has_repo   # → escalates


class _FakeHttp:
    def __init__(self, doc=None, raise_exc=None):
        self.doc, self.raise_exc = doc, raise_exc

    def get_json(self, url, **kw):
        if self.raise_exc:
            raise self.raise_exc
        return self.doc


def test_collect_evidence_rich_npm_recovers_description_and_readme():
    raw = {"dist-tags": {"latest": "2.0"},
           "versions": {"1.0": {}, "2.0": {"homepage": "https://x"}},
           "time": {"created": "2015-01-01T00:00:00Z"},
           "description": "Fast 3kb React alternative",
           "readme": "A" * 2000}
    ev = collect_evidence_rich(_cand("preact", "react"), "npm",
                               _FakeHttp(raw), lambda n: None)
    assert ev.description == "Fast 3kb React alternative"
    assert ev.readme and len(ev.readme) <= 600        # capped
    assert ev.num_versions == 2 and ev.has_repo and ev.age_days > 3000


def test_collect_evidence_rich_pypi_recovers_summary_and_age():
    raw = {"info": {"summary": "HTTP for humans", "description": "long readme",
                    "project_urls": {"Source": "https://gh"}},
           "releases": {"1.0": [{"upload_time_iso_8601": "2012-01-01T00:00:00Z"}],
                        "2.0": [{"upload_time_iso_8601": "2020-01-01T00:00:00Z"}]}}
    ev = collect_evidence_rich(_cand("reqursts", "requests"), "PyPI",
                               _FakeHttp(raw), lambda n: None)
    assert ev.description == "HTTP for humans"
    assert ev.num_versions == 2 and ev.has_repo
    assert ev.age_days and ev.age_days > 4000          # earliest = 2012


def test_collect_evidence_rich_crates_falls_back_to_get_metadata():
    doc = {"crate": {"description": "d", "num_versions": 5,
                     "created_at": "2018-01-01T00:00:00Z",
                     "repository": "https://gh"}}
    ev = collect_evidence_rich(_cand("serdex", "serde"), "Cargo",
                               object(), lambda n: doc)
    assert ev.description == "d" and ev.num_versions == 5


def test_collect_evidence_rich_fetch_failure_is_thin():
    ev = collect_evidence_rich(_cand("x", "y"), "npm",
                               _FakeHttp(raise_exc=RuntimeError("down")),
                               lambda n: None)
    assert ev.num_versions == 0 and ev.description is None   # → escalate


def test_render_evidence_includes_readme():
    assert "README" in render_evidence(_ev(readme="this is the readme"))


def test_render_evidence_includes_fields():
    ev = _ev(description="d", num_versions=5, age_days=100,
             has_repo=True, deprecated=False, downloads_per_month=7)
    t = render_evidence(ev)
    assert "release count: 5" in t
    assert "deprecated: no" in t
    assert "downloads/month: 7" in t
    assert "age (days since first publish): 100" in t


def test_render_evidence_caps_long_description():
    ev = _ev(description="A" * 5000)
    line = next(ln for ln in render_evidence(ev).splitlines()
                if ln.startswith("description:"))
    # "description: " prefix + <=300 chars of payload
    assert len(line) <= len("description: ") + 300


def test_to_verdict_none_is_unsure():
    v = _to_verdict(None, _CAND)
    assert v.verdict == "unsure" and v.confidence == "low"


def test_to_verdict_maps_llm_object():
    from types import SimpleNamespace
    llm_v = SimpleNamespace(verdict="legit", confidence="high",
                            rationale="real", evidence_cited=["20 releases"])
    v = _to_verdict(llm_v, _CAND)
    assert v.verdict == "legit" and v.evidence_cited == ["20 releases"]


def test_triage_ecosystem_auto_files_legit_and_routes_squat(tmp_path):
    rl = tmp_path / "rl.json"
    rl.write_text(json.dumps({"npm": {}}))
    good, evil = _cand("goodpkg", "goodlib"), _cand("evilpkg", "express")
    docs = {
        "goodpkg": {"dist-tags": {"latest": "9.0"},
                    "versions": {f"{i}.0": {"homepage": "https://x"}
                                 for i in range(20)},
                    "time": {"created": "2015-01-01T00:00:00Z"}},
        "evilpkg": {"dist-tags": {"latest": "1.0"},
                    "versions": {"1.0": {"deprecated": "use express"}},
                    "time": {"created": "2016-01-01T00:00:00Z"}},
    }
    outcomes = triage_ecosystem(
        [good, evil], "npm",
        get_metadata=lambda n: docs.get(n),
        verdict_fn=lambda c, ev: Verdict(
            c.name, "legit" if c.name == "goodpkg" else "typosquat", "high"),
        reviewed_legit_path=rl, model="m",
    )
    disp = {o.candidate.name: o.gate_result.disposition for o in outcomes}
    assert disp["goodpkg"] is Disposition.AUTO_LEGIT
    assert disp["evilpkg"] is Disposition.CONFIRM_SQUAT
    data = json.loads(rl.read_text())
    assert "goodpkg" in data["npm"]          # auto-filed
    assert "evilpkg" not in data["npm"]      # squat stays human-gated


# ---------------------------------------------------------------------------
# Step 3 — re-audit (Tier 1, mechanical)
# ---------------------------------------------------------------------------

def test_osv_malicious_flags_only_mal_records():
    class _H:
        def post_json(self, url, body, **kw):
            return {"results": [
                {"vulns": [{"id": "MAL-1"}]} if q["package"]["name"] == "evil"
                else {"vulns": [{"id": "CVE-2020-1"}]}
                for q in body["queries"]]}
    assert osv_malicious(_H(), "npm", ["good", "evil"]) == {"evil"}


def test_osv_malicious_fail_soft():
    class _H:
        def post_json(self, *a, **k):
            raise RuntimeError("osv down")
    assert osv_malicious(_H(), "npm", ["x"]) == set()
    assert osv_malicious(object(), "Maven", ["x"]) == set()   # unmapped eco


def test_reaudit_flags_removed_deprecated_and_malicious(tmp_path):
    rl = tmp_path / "rl.json"
    rl.write_text(json.dumps({"npm": {"alive": {}, "gone": {}, "dep": {}}}))
    docs = {
        "alive": {"dist-tags": {"latest": "1.0"}, "versions": {"1.0": {}}},
        "dep": {"dist-tags": {"latest": "1.0"},
                "versions": {"1.0": {"deprecated": "use x"}}},
    }   # "gone" absent → get_metadata returns None → removed
    flagged = reaudit_reviewed_legit(
        rl, ["npm"],
        get_metadata=lambda eco, name: docs.get(name),
        osv_malicious_fn=lambda eco, names: {"alive"})   # alive now malicious
    d = dict(flagged["npm"])
    assert "removed" in d["gone"]
    assert "deprecated" in d["dep"]
    assert "malicious" in d["alive"]


def test_reaudit_recommendation_tier2():
    # MAL- flag is ground truth — denylist regardless of LLM verdict.
    assert "DENYLIST" in reaudit_recommendation(
        "now carries a malicious (MAL-) advisory", _v("legit"))
    # deprecated + LLM now says typosquat → denylist.
    assert "DENYLIST" in reaudit_recommendation("now deprecated", _v("typosquat"))
    # deprecated + LLM still legit → likely keep (benign deprecation).
    assert "KEEP" in reaudit_recommendation("now deprecated", _v("legit"))
    # unsure → review.
    assert "REVIEW" in reaudit_recommendation("now deprecated", _v("unsure"))


def test_reaudit_clean_list_returns_nothing(tmp_path):
    rl = tmp_path / "rl.json"
    rl.write_text(json.dumps({"npm": {"ok": {}}}))
    docs = {"ok": {"dist-tags": {"latest": "1.0"}, "versions": {"1.0": {}}}}
    flagged = reaudit_reviewed_legit(
        rl, ["npm"], get_metadata=lambda e, n: docs.get(n),
        osv_malicious_fn=lambda e, n: set())
    assert flagged == {}


def test_evidence_to_gate_deprecated_npm_never_auto_legit():
    # End-to-end Stage 3→4: a deprecated npm package (loadash shape) the LLM
    # somehow calls "legit" still escalates — the floor catches it.
    doc = {"dist-tags": {"latest": "1.0.0"},
           "versions": {"1.0.0": {"deprecated": "use lodash"}},
           "time": {"created": "2016-09-22T00:00:00Z"}}
    outcomes = triage_pending(
        [_cand("loadash", "lodash")],
        lambda c: collect_evidence(c, "npm", lambda n: doc),
        lambda c, ev: Verdict(c.name, "legit", "high"),   # adversarial verdict
    )
    assert outcomes[0].gate_result.disposition is Disposition.ESCALATE
