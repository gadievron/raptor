"""The rationale check and race-gate protection prose never change a verdict.

The rationale-consistency gate and the speculative race gate read the
review's own prose with phrase lists ("properly validated", "protected
by") and used to record ``clean`` on a match. A phrase list cannot
tell an asserted clean claim from a negated, contrasted, conceded or
attributed one ("is NOT properly validated", "tools found no
vulnerability, YET ...", "ALTHOUGH bounded, ...", "the comment CLAIMS
it is protected by ..."), so the clean verdict was a coin flip on
truth and an unexported one.

The rule pinned here: a phrase match decides nothing. A finding whose
rationale reads clean stays a finding with an annotation in
review_result only; its status, body and every lane it enters (G2,
in-review all-refuted block, post-loop self-contradiction pass,
--adversarial refuter, end-of-run gate resolution, deepen) are exactly
what the same row gets without the phrase. The race gate never
returns clean; its remaining step (finding -> suspicious) is
keyword-triggered on the hypothesis text, only moves toward
suspicious, and is exempted by a concurrency-relevant receipt (see
TestRaceGateNeverClean). Two pre-existing lanes where model wording
still decides a verdict are outside this file's rule (docs/audit.md):
the all-refuted demotion's delegation-phrase grounding, and class
coverage read from hypothesis text when ``cwe`` is empty. Hermetic —
LLM stubbed.
"""

from __future__ import annotations

import itertools
import re
import time
from pathlib import Path
from typing import Any

import pytest

import core.audit.adversarial_refute as _adv
import core.audit.llm_review as _lr
import core.audit.orchestrator as _orch
from core.audit.findings_export import export_findings
from core.audit.llm_review import (
    _rationale_consistency_should_demote,
    make_review_fn,
)
from core.audit.orchestrator import (
    _RACE_KW,
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _adversarial_refute_pass,
    _apply_speculative_race_demotion,
    _check_finding_gates,
    _deepen_demotion_refereed,
    _deepen_suspicious,
    _demote_outcome,
    _demote_self_contradictions,
    _resolve_gate_demoted,
)
from core.audit.sweep import SarifCache

NOTE_KEY = "rationale_consistency_note"

HYP = "SQL injection via $id concatenation"

# (phrase body, phrase-free twin). The phrase body trips the phrase
# function (negated, contrast, attribution, concession, reversal,
# "does not mean", asserted); the twin says the same thing without a
# listed phrase. ``test_pairs_discriminate_the_phrase_gate`` pins both
# halves, so the property tests below compare a gate hit with a miss.
PAIRS = {
    "negated": (
        "The $id parameter is not properly validated before it is "
        "concatenated into the query string.",
        "The $id parameter is never checked before it is "
        "concatenated into the query string.",
    ),
    "double-negated": (
        "It would be incorrect to call this input properly validated: "
        "the cast happens after the concatenation.",
        "It would be incorrect to call this input checked: the cast "
        "happens after the concatenation.",
    ),
    "contrast": (
        "Semgrep reported no vulnerability, yet $id from the request "
        "reaches the WHERE clause unescaped.",
        "Semgrep reported nothing, yet $id from the request reaches "
        "the WHERE clause unescaped.",
    ),
    "attribution": (
        "The header comment claims all paths are guarded; the search "
        "path at line 40 is not, and splices $id into SQL.",
        "The header comment claims every path checks input; the search "
        "path at line 40 does not, and splices $id into SQL.",
    ),
    "concessive": (
        "Although the page size is correctly bounded, $id is "
        "attacker-controlled and concatenated unescaped.",
        "The page size is capped, and $id is attacker-controlled and "
        "concatenated unescaped.",
    ),
    "reversal": (
        "It is wrong to say there is no exploitable path: a quote in "
        "$id closes the literal and appends a UNION SELECT.",
        "An attack path exists: a quote in $id closes the literal and "
        "appends a UNION SELECT.",
    ),
    "does-not-mean": (
        "A clean scanner run does not mean the function is safe; $id "
        "is concatenated into the query.",
        "A quiet scanner run proves little; $id is concatenated into "
        "the query.",
    ),
    "asserted": (
        "The function is safe: $id is cast to int on line 2 before use.",
        "$id is cast to int on line 2 before use.",
    ),
}

COMPELLING_COUNTER = (
    "an attacker-controlled length reaching memcpy can overflow the "
    "stack buffer when the caller passes tainted input"
)

# Every hypothesis refuted with a grounded (local, non-delegated)
# counter: the record the in-review all-refuted block and the
# post-loop self-contradiction pass act on.
REFUTED = [{
    "mechanism": "SQL injection via $id",
    "confidence": "refuted",
    "counter": "$id is cast with (int) on line 2 inside this function",
    "counter_scope": "local",
}]

PHP_SOURCE = "<?php\nfunction f($c, $id) { return $id + 1; }\n"


class _StubResponse:
    def __init__(self, result: dict[str, Any]):
        self.result = result
        self.cost = 0.1
        self.model = "stub"
        self.input_tokens = 1
        self.output_tokens = 1
        self.cache_read_tokens = 0
        self.cache_write_tokens = 0


class _StubClient:
    def __init__(self, result: dict[str, Any]):
        self._result = result

    def supports_prompt_caching_for(self) -> bool:
        return False

    def generate_structured(self, prompt, schema, **kwargs):
        return _StubResponse(dict(self._result))


def _review(result_dict: dict[str, Any]) -> ReviewOutcome:
    review_fn = make_review_fn(_StubClient(result_dict))
    ctx = {
        "file": "app.php", "function": "f", "source": PHP_SOURCE,
        "line_start": 2, "line_end": 2,
    }
    config = OrchestratorConfig(target_path=Path("."), out_dir=None)
    outcome = review_fn(ctx, config)
    outcome.line = 2
    return outcome


def _emit(status: str, body: str, **extra: Any) -> ReviewOutcome:
    return _review({
        "status": status, "body": body, "hypothesis": HYP,
        "cwe": "CWE-89", "mechanism": "SQL injection", **extra,
    })


def _exported(outcome: ReviewOutcome) -> int:
    return len(export_findings([outcome])["findings"])


def _result(*outcomes: ReviewOutcome) -> OrchestratorResult:
    res = OrchestratorResult()
    res.outcomes = list(outcomes)
    for o in outcomes:
        attr = {"finding": "findings"}.get(o.status, o.status)
        if hasattr(res, attr):
            setattr(res, attr, getattr(res, attr) + 1)
    return res


def _target(tmp_path: Path) -> OrchestratorConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    (tmp_path / "app.php").write_text(PHP_SOURCE)
    return OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)


CHECKLIST = {"files": [{"path": "app.php", "items": [
    {"name": "f", "line_start": 2, "line_end": 2},
]}]}

_MARKER_RE = re.compile(r"^\[([a-z0-9 _-]+):", re.MULTILINE)


def _lanes(o: ReviewOutcome) -> tuple:
    """The machine markers stamped on the body = the lanes that acted."""
    return tuple(_MARKER_RE.findall(o.body or ""))


def _pipeline(tmp_path, status, body, *, hyps=None, refute=None,
              joern=False, dispatched=(), ev="", monkeypatch=None):
    """REAL review_fn -> G2 finding gates -> post-loop self-contradiction
    pass -> [--adversarial pass] -> end-of-run gate resolution -> export.
    Returns the final (status, exported, clean_basis, lanes, refuter
    calls) — the comparison key of every property test below."""
    extra = {"hypotheses": hyps} if hyps else {}
    o = _emit(status, body, **extra)
    if ev:
        o.evidence_tool = ev  # a mechanical receipt stamped in-review
    if o.status == "finding":
        violations = _check_finding_gates(o)
        if violations:
            o = _demote_outcome(
                o, f"[gate violation: {'; '.join(violations)}]",
            )
    o.tools_dispatched = set(dispatched)
    o.tools_inconclusive = set()
    res = _result(o)
    _demote_self_contradictions(res)
    calls: list[str] = []
    cfg = _target(tmp_path)
    if refute is not None:
        def fake(llm, **kw):
            calls.append(kw["body"])
            return _adv.RefutationResult(
                verdict=refute, counter_argument="the id is cast upstream",
            )

        monkeypatch.setattr(_adv, "run_refutation", fake)
        cfg.llm_client = object()
        _adversarial_refute_pass(res, cfg, CHECKLIST)
    _resolve_gate_demoted(
        res, cfg, SarifCache(), CHECKLIST,
        available_tools={"joern": joern, "semgrep": True},
        mechanical_findings={},
    )
    f = res.outcomes[0]
    return (f.status, _exported(f), getattr(f, "clean_basis", None),
            _lanes(f), len(calls)), calls


def _check_off(monkeypatch):
    monkeypatch.setattr(
        _lr, "_rationale_consistency_should_demote", lambda *a: False,
    )


class TestRationaleCheckAnnotatesOnly:
    """The rationale-consistency check may only leave a note in review_result;
    it must never change a finding's status or body. A phrase list cannot tell
    an asserted clean claim from a negated or conceded one, so letting it
    decide the verdict would be a coin flip."""

    def test_pairs_discriminate_the_phrase_gate(self):
        """Each phrase body must trip the phrase check and each phrase-free
        twin must not. Without this, the comparison tests below could pass
        trivially because neither side ever hit the check."""
        for phrase, twin in PAIRS.values():
            assert _rationale_consistency_should_demote(
                "finding", phrase, HYP, "",
            ), phrase
            assert not _rationale_consistency_should_demote(
                "finding", twin, HYP, "",
            ), twin

    @pytest.mark.parametrize("kind", sorted(PAIRS))
    def test_finding_kept_with_note(self, kind):
        """A finding whose rationale reads clean, in any phrasing family, must
        stay a finding with its body untouched and still be exported, carrying
        only the note. If the check demoted it, real vulnerabilities would
        vanish from the report on wording alone."""
        body = PAIRS[kind][0]
        outcome = _emit("finding", body)
        assert outcome.status == "finding"
        assert outcome.body == body
        rr = outcome.review_result
        assert rr["status"] == "finding"
        assert NOTE_KEY in rr
        assert "rationale_consistency_mismatch" not in rr
        assert _exported(outcome) == 1

    @pytest.mark.parametrize("kind", sorted(PAIRS))
    def test_phrase_free_twin_carries_no_note(self, kind):
        """A finding written without any listed phrase must carry no note. This
        confirms the note tracks the phrase match and nothing else, so the two
        halves of each pair really differ."""
        outcome = _emit("finding", PAIRS[kind][1])
        assert outcome.status == "finding"
        assert NOTE_KEY not in outcome.review_result

    @pytest.mark.parametrize("status", ["suspicious", "clean", "dormant"])
    def test_other_emissions_untouched(self, status):
        """The check acts only on findings; suspicious, clean and dormant
        emissions keep their status and body and get no note. Applying it
        elsewhere would let prose rewrite verdicts the check was never meant to
        touch."""
        body = PAIRS["asserted"][0]
        outcome = _emit(status, body)
        assert outcome.status == status
        assert outcome.body == body
        assert NOTE_KEY not in outcome.review_result

    def test_tool_evidenced_finding_unaffected(self):
        """A finding backed by a tool receipt is outside the check entirely and
        gets no note. The tool evidence, not the prose, is what that verdict
        rests on."""
        outcome = _emit(
            "finding", PAIRS["contrast"][0],
            evidence_tool="semgrep:raptor-php-sqli",
        )
        assert outcome.status == "finding"
        assert NOTE_KEY not in outcome.review_result

    def test_counter_escalation_untouched(self):
        """The counter-hypothesis escalation must still lift a clean to
        suspicious and stamp its marker, with no rationale note added. This
        guards against the annotation-only change disturbing a separate,
        structured lane."""
        outcome = _emit(
            "clean", PAIRS["asserted"][0],
            counter_hypothesis=COMPELLING_COUNTER,
        )
        assert outcome.status == "suspicious"
        assert outcome.body.startswith("[counter-hypothesis escalation:")
        assert NOTE_KEY not in outcome.review_result

    def test_note_key_read_by_no_stage(self):
        # No reader anywhere outside the check itself (every runtime
        # module under core/, packages/ and libexec/): the annotation
        # cannot steer a verdict, a journal row or a reuse decision.
        """No runtime module outside the check itself may read the
        rationale-consistency keys, apart from the registry that strips them
        from model output. If any stage read the note, the annotation could
        quietly steer a verdict, a journal row or a reuse decision."""
        repo = Path(_orch.__file__).resolve().parents[2]
        own = Path(_lr.__file__).resolve()
        readers = []
        for sub in ("core", "packages", "libexec"):
            for f in (repo / sub).rglob("*"):
                if (not f.is_file() or "tests" in f.parts
                        or f.resolve() == own
                        or f.suffix not in ("", ".py")):
                    continue
                try:
                    text = f.read_text()
                except (UnicodeDecodeError, OSError):
                    continue
                if f.name == "evidence_grade.py":
                    # The pipeline-owned key registry names the keys so
                    # the parse boundaries can DROP them from model
                    # output — that is the only allowed mention.
                    import core.audit.evidence_grade as eg
                    for k in ("rationale_consistency_demotion",
                              "rationale_consistency_mismatch",
                              "rationale_consistency_note"):
                        assert k in eg.PIPELINE_OWNED_REVIEW_KEYS
                        text = text.replace(f'"{k}"', "", 1)
                if "rationale_consistency" in text:
                    readers.append(str(f.relative_to(repo)))
        assert readers == []

    @pytest.mark.parametrize("ev", ["", "semgrep:raptor-php-sqli"])
    def test_noted_finding_journals_like_its_twin(self, tmp_path, ev):
        # Round trip through the REAL journal writer: a noted finding
        # journals exactly like its phrase-free twin (same verdict and
        # basis; the journal-write promotion gate treats both alike),
        # never as a clean, and the note is not persisted.
        """Through the real journal writer, a noted finding must journal with
        the same verdict and basis as its phrase-free twin, never as clean, and
        the note must not be persisted. Otherwise the phrase would leak into
        cross-run state."""
        from core.audit.collector import append_journal_for_outcome
        from core.coverage.journal import load_entries

        def journal(body, sub):
            out = tmp_path / sub
            outcome = _emit("finding", body)
            if ev:
                outcome.evidence_tool = ev
            cfg = _target(out)
            append_journal_for_outcome(
                out_dir=out, target_path=cfg.target_path,
                run_id="r1", outcome=outcome,
                gap={"file": "app.php", "name": "f", "line_start": 2,
                     "line_end": 2},
            )
            row = load_entries(out)[-1]
            assert NOTE_KEY not in row.to_dict()
            return row.verdict, getattr(row, "clean_basis", None)

        noted = journal(PAIRS["negated"][0], "p")
        assert noted == journal(PAIRS["negated"][1], "t")
        assert noted[0] == ("finding" if ev else "suspicious")

# --- property: the phrase decides nothing ----------------------------------
#
# Every routing scenario below (plain, all-refuted hypotheses, the
# adversarial refuter either way, the coverage resolver states, tool
# evidence) plus deepen, replayed twice: (a)
# the phrase body vs its phrase-free twin, (b) the phrase body with the
# check switched off. The final (status, exported, clean_basis, lanes
# entered, refuter calls) must be identical.

SCENARIOS = {
    "plain": {},
    "all-refuted": {"hyps": REFUTED},
    "adversarial-refuted": {"refute": "refuted"},
    "adversarial-stands": {"refute": "stands"},
    "joern-up-uncovered": {"joern": True},
    "joern-up-covered": {"joern": True, "dispatched": ("semgrep",)},
    "joern-down-covered": {"dispatched": ("semgrep",)},
    "joern-up-covered-smt": {"joern": True, "dispatched": ("semgrep",),
                             "ev": "smt:sat"},
    "tool-evidenced": {"ev": "semgrep:raptor-php-sqli",
                       "dispatched": ("semgrep",)},
}


class TestPhraseDecidesNothing:
    """Across every routing scenario of the audit pipeline, a phrase body and
    its phrase-free twin, or the same body with the check on and off, must end
    with identical status, export, clean basis, lanes and refuter calls. This
    is the core property that model wording cannot decide a verdict."""

    @pytest.mark.parametrize("scenario", sorted(SCENARIOS))
    @pytest.mark.parametrize("status", ["finding", "suspicious"])
    @pytest.mark.parametrize("kind", sorted(PAIRS))
    def test_phrase_vs_twin(self, monkeypatch, tmp_path, kind, status,
                            scenario):
        """For each phrasing family, input status and routing scenario, the
        phrase body and its twin must reach the same final outcome. Any
        difference would mean a phrase match still changes a verdict somewhere
        in the pipeline."""
        kw = SCENARIOS[scenario]
        phrase, twin = PAIRS[kind]
        got, _ = _pipeline(tmp_path / "p", status, phrase,
                           monkeypatch=monkeypatch, **kw)
        ctl, _ = _pipeline(tmp_path / "t", status, twin,
                           monkeypatch=monkeypatch, **kw)
        assert got == ctl

    @pytest.mark.parametrize("scenario", sorted(SCENARIOS))
    @pytest.mark.parametrize("kind", sorted(PAIRS))
    def test_check_on_vs_off(self, monkeypatch, tmp_path, kind, scenario):
        """Switching the rationale check off must change nothing in the final
        outcome, and the adversarial refuter must see byte-identical text
        either way. This catches the check leaking into the body or any later
        lane."""
        kw = SCENARIOS[scenario]
        body = PAIRS[kind][0]
        on, seen_on = _pipeline(tmp_path / "on", "finding", body,
                                monkeypatch=monkeypatch, **kw)
        _check_off(monkeypatch)
        off, seen_off = _pipeline(tmp_path / "off", "finding", body,
                                  monkeypatch=monkeypatch, **kw)
        assert on == off
        # The refuter is shown byte-identical text either way.
        assert seen_on == seen_off

    @pytest.mark.parametrize("scenario,status,expect", [
        ("plain", "finding", ("dark", 1)),
        ("plain", "suspicious", ("suspicious", 1)),
        ("all-refuted", "finding", ("clean", 0)),
        ("adversarial-refuted", "suspicious", ("clean", 0)),
        ("adversarial-stands", "suspicious", ("suspicious", 1)),
        ("joern-up-covered", "finding", ("clean", 0)),
        ("joern-down-covered", "suspicious", ("suspicious", 1)),
        ("tool-evidenced", "finding", ("finding", 1)),
    ])
    def test_scenarios_discriminate(self, monkeypatch, tmp_path, scenario,
                                    status, expect):
        # Anti-vacuity: the pipeline actually routes differently per
        # scenario (an evidence-free finding meets G2 and is resolved
        # by silence admissibility; a tool-evidenced one stays a finding).
        # These are base behaviours of the lanes, identical with or
        # without the phrase (tests above).
        """Each scenario must actually route differently, for example a bare
        finding ending dark and a tool-evidenced one staying a finding. Without
        this the equality tests could pass because every scenario collapsed to
        the same result."""
        got, _ = _pipeline(tmp_path, status, PAIRS["negated"][0],
                           monkeypatch=monkeypatch, **SCENARIOS[scenario])
        assert got[:2] == expect


RACE_HYP = "data race on count read concurrently"

# Bodies the old protection regex matched (no negator in the 30-char
# window before it) although none of them says the access is
# protected.
RACE_BODIES = {
    "attribution": (
        "The header comment claims count is protected by dev->lock, "
        "the reader takes no lock: data race."
    ),
    "concessive": (
        "Although writers are serialized by the queue lock, the reader "
        "at line 30 takes no lock and races with them."
    ),
    "negated-far": (
        "Nothing in this reader path is ever, at any point, protected "
        "by dev->lock, so count races."
    ),
    "asserted": "The counter is protected by the socket lock.",
}

# Every phrase family the retired step 2 keyed on.
PROTECTION_PHRASES = (
    "protected by", "under lock", "held lock", "held by lock",
    "rcu_read_lock", "single-threaded", "single_threaded", "init-only",
    "init_only", "serialized by", "serialised by", "mutex_held",
    "mutex held", "spin_lock", "sequential init", "sequential_init",
)


def _race(status: str, body: str, evidence: str = "",
          hyp: str = RACE_HYP) -> ReviewOutcome:
    o = ReviewOutcome(
        file="a.c", function="f", status=status, body=body,
        hypothesis=hyp,
    )
    if evidence:
        o.evidence_tool = evidence
    return _apply_speculative_race_demotion(o)


class TestRaceGateNeverClean:
    """The race gate never returns clean (protection prose is no
    receipt). Its remaining step — finding -> suspicious for a race
    hypothesis without a CONCURRENCY-relevant receipt — is kept: it is
    triggered by race keywords in the hypothesis text (so it can fire on
    a negated mention and miss a paraphrase), only moves toward
    suspicious, and enforces that consistency:/fail_open receipts, which
    G2 accepts as tool evidence, do not shield a race claim they say
    nothing about.
    """

    @pytest.mark.parametrize("kind", sorted(RACE_BODIES))
    def test_suspicious_race_stays_suspicious(self, kind):
        """A suspicious race whose body mentions protection, whether
        attributed, conceded, negated or asserted, must stay suspicious with
        its body unchanged. The gate used to turn such prose into clean, which
        a phrase match cannot justify."""
        result = _race("suspicious", RACE_BODIES[kind])
        assert result.status == "suspicious"
        assert result.body == RACE_BODIES[kind]

    @pytest.mark.parametrize("kind", sorted(RACE_BODIES))
    def test_finding_race_stops_at_suspicious(self, kind):
        # Step 1 (finding -> suspicious, evidence-free race) is the
        # review-bucket direction and stays.
        """An evidence-free race finding is still moved down to suspicious, and
        no further. That remaining step only points toward review and must
        never reach clean from protection prose."""
        assert _race("finding", RACE_BODIES[kind]).status == "suspicious"

    def test_tool_evidenced_race_unaffected(self):
        """A race finding with a concurrency-relevant tool receipt must stay a
        finding. The gate must not demote claims that a lock-region analysis
        actually supports."""
        assert _race(
            "finding", RACE_BODIES["asserted"],
            evidence="lock_region:callback_under_lock",
        ).status == "finding"

    def test_no_body_ever_returns_clean(self):
        # Property over every race keyword x protection phrase x
        # position (bare phrase, sentence start, mid-sentence, after a
        # negator, capitalised) x {finding, suspicious}: the gate's
        # output is never clean, whatever the prose says.
        """Over every race keyword, protection phrase, sentence position and
        input status, the race gate's output is never clean. This exhaustive
        check stops any phrase from bringing back the retired
        protection-to-clean step."""
        shapes = (
            "{p}", "{P} the lock.", "{p} the socket lock.",
            "The field is {p} dev->lock.", "Not {p} anything; it races.",
            "x" * 40 + " {p}",
        )
        checked = 0
        for kw, phrase, shape, status in itertools.product(
            _RACE_KW, PROTECTION_PHRASES, shapes,
            ("finding", "suspicious"),
        ):
            body = shape.format(p=phrase, P=phrase.capitalize())
            out = _race(status, body, hyp=f"{kw} on the shared counter")
            assert out.status == "suspicious", (kw, body, status)
            checked += 1
        assert checked == len(_RACE_KW) * len(PROTECTION_PHRASES) * 12


def _deepen_outcome(file, func, status="suspicious", body="review prose",
                    review_result=None, evidence_tool=""):
    return ReviewOutcome(
        file=file, function=func, status=status, body=body,
        hypothesis=HYP, evidence_tool=evidence_tool,
        review_result=(
            {"body": body} if review_result is None else review_result
        ),
    )


def _run_deepen(monkeypatch, tmp_path, prior, review):
    result = OrchestratorResult(outcomes=[prior], suspicious=1)
    monkeypatch.setattr(
        _orch, "_build_context",
        lambda cfg, gap, *a, **kw: {
            "file": gap["file"], "function": gap["name"],
            "source": "int foo(void){}", "line_start": 1, "line_end": 1,
        },
    )
    monkeypatch.setattr(_orch, "_check_budget", lambda *a, **kw: False)
    cfg = OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path,
        sweep_validate_findings=False, deepen_suspicious=True,
        enable_session_context=False, blind_first_pass=False,
    )
    checklist = {"files": [{"path": "a.c", "functions": [
        {"name": "foo", "line_start": 1, "line_end": 100},
    ]}]}
    _deepen_suspicious(
        result, cfg, review, checklist,
        None, None, [], None, set(), time.time(), None,
        max_workers=1,
    )
    return [
        o for o in result.outcomes if (o.file, o.function) == ("a.c", "foo")
    ]


class TestDeepenTrustsNoProseBasis:
    """The deepen re-review must not accept a clean on the strength of prose or
    of retired rationale flags; only the structured all-refuted demotion counts
    as a basis. Otherwise a second review could overturn a suspicious verdict
    on wording alone."""

    @pytest.mark.parametrize("refuted", [False, True],
                             ids=["no-record", "all-refuted"])
    @pytest.mark.parametrize("status", ["finding", "suspicious"])
    @pytest.mark.parametrize("kind", ["negated", "contrast", "asserted"])
    def test_deepen_phrase_vs_twin(self, monkeypatch, tmp_path, kind,
                                   status, refuted):
        # A deepen re-review through the REAL review path: the prior's
        # fate is the same whether the re-review's prose trips the
        # phrase list or not.
        """Through the real review path, the prior's fate under deepen must be
        the same whether the re-review's prose trips the phrase list or not. A
        difference would let phrasing decide whether a suspicious verdict
        survives."""
        def fate(body, sub):
            prior = _deepen_outcome("a.c", "foo")
            extra = {"hypotheses": REFUTED} if refuted else {}
            review = make_review_fn(_StubClient({
                "status": status, "body": body, "hypothesis": HYP,
                **extra,
            }))
            kept = _run_deepen(monkeypatch, tmp_path / sub, prior, review)
            assert len(kept) == 1
            return kept[0].status, _lanes(kept[0])

        phrase, twin = PAIRS[kind]
        assert fate(phrase, "p") == fate(twin, "t")

    @pytest.mark.parametrize("flag", [
        "rationale_consistency_demotion",  # retired
        "rationale_consistency_mismatch",  # retired: never produced
    ])
    def test_rationale_flags_are_not_a_structured_basis(
        self, monkeypatch, tmp_path, flag,
    ):
        # A clean carrying either rationale flag is a bare LLM clean:
        # the dominated branch keeps the prior instead of accepting it
        # as a structured demotion. No reader branches on the flags.
        """A deepen clean carrying a retired rationale-consistency flag is just
        a bare model clean, so the prior suspicious verdict must be kept.
        Treating the flag as structured would let a retired gate's output
        overturn verdicts."""
        prior = _deepen_outcome("a.c", "foo")

        def review(ctx, cfg):
            return _deepen_outcome(
                ctx["file"], ctx["function"], "clean",
                body="looks fine", review_result={flag: True},
            )

        kept = _run_deepen(monkeypatch, tmp_path, prior, review)
        assert len(kept) == 1
        assert kept[0] is prior
        assert prior.status == "suspicious"

    def test_all_refuted_demotion_is_the_structured_basis(
        self, monkeypatch, tmp_path,
    ):
        # Control for the flag tests above: the one structured basis
        # deepen still trusts. A deepen clean carrying it supersedes a
        # probe-less prior; the same clean without it is dominated.
        """The all-refuted demotion is the one structured basis deepen still
        trusts: with it a deepen clean replaces a prior with no tool backing,
        and without it the prior stays. This control shows the flag tests above
        fail for the right reason."""
        def run(rr):
            prior = _deepen_outcome("a.c", "foo")

            def review(ctx, cfg):
                return _deepen_outcome(
                    ctx["file"], ctx["function"], "clean",
                    body="all refuted", review_result=rr,
                )

            kept = _run_deepen(monkeypatch, tmp_path, prior, review)
            assert len(kept) == 1
            return kept[0].status

        assert run({"all_refuted_demotion": True}) == "clean"
        assert run({}) == "suspicious"

    @pytest.mark.parametrize("flag", [
        "rationale_consistency_demotion", "rationale_consistency_mismatch",
    ])
    def test_referee_ignores_rationale_flags(self, flag):
        # Control (all_refuted_demotion) holds; the rationale flags on
        # the same probe-backed prior do not.
        """The demotion referee must accept the all-refuted basis but not
        either rationale flag when weighing a clean against a tool-backed
        suspicious prior. Otherwise a retired flag could be used to override a
        tool observation."""
        prior = ReviewOutcome(
            file="a.c", function="foo", status="suspicious",
            body="prose", evidence_tool="smt:check-overflow",
        )

        def clean(rr):
            return ReviewOutcome(
                file="a.c", function="foo", status="clean", body="ok",
                review_result=rr,
            )

        assert _deepen_demotion_refereed(
            prior, clean({"all_refuted_demotion": True}),
        )
        assert not _deepen_demotion_refereed(prior, clean({flag: True}))
