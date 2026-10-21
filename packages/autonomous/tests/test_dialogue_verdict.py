"""Verdict-parsing and refinement-contract tests for dialogue.py.

Covers:
- _parse_crash_analysis prefers an explicit verdict line over
  whole-response keyword co-occurrence (which parsed
  "Exploitability: LOW ... heap address is high" as high@0.8);
- keyword fallback checks conservative levels first with reduced
  confidence;
- an explicit verdict line outranks the bare "not exploitable" phrase;
  without one the parse equals the pre-change parse (differential), and
  an explicit turn-1 line is replaced only by an explicit turn-2 line or
  a bare "Exploitability is high|medium" reply (upgrade only);
- whole-line echoes of the verdict-line instruction are dropped before
  the turn-2 free-text read, never creating an explicit verdict;
- the turn-2 confidence boost fires only when the clarification's level
  is used and agrees with the initial verdict;
- refine_exploit_iteratively honors its "None if refinement failed"
  contract.
"""

from __future__ import annotations

import random
import re
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock

import pytest

from packages.autonomous.dialogue import (
    MultiTurnAnalyser,
    _drop_echo_lines,
    _explicit_verdict,
)


@dataclass
class FakeCrashContext:
    signal: int = 11
    function_name: Optional[str] = "vuln_func"
    stack_trace: str = "STACK_TRACE_MARKER_abc123"
    # dict[str, str], matching the real CrashContext contract
    # (registers parsed from the debugger, not a pre-rendered string).
    registers: dict = field(default_factory=lambda: {
        "rax": "0xdeadbeef", "rbx": "0x41414141",
    })
    binary_info: dict = field(default_factory=lambda: {"aslr_enabled": True})
    size: int = 256


def _analyser(llm=None):
    return MultiTurnAnalyser(llm_client=llm or MagicMock())


def _mock_llm(responses):
    llm = MagicMock()
    replies = []
    for text in responses:
        r = MagicMock()
        r.content = text
        replies.append(r)
    llm.generate.side_effect = replies
    return llm


class TestParseCrashAnalysis:
    def test_explicit_low_wins_over_incidental_high(self):
        r = _analyser()._parse_crash_analysis(
            "Exploitability: LOW. The heap address is high in memory "
            "and any exploit would require a separate info leak.")
        assert r["exploitability"] == "low"
        assert r["confidence"] == 0.6

    def test_explicit_anchor_first(self):
        r = _analyser()._parse_crash_analysis(
            "Buffer overflow. Exploitability: High. Use ROP.")
        assert r["exploitability"] == "high"
        assert r["confidence"] == 0.8

    def test_level_before_anchor(self):
        r = _analyser()._parse_crash_analysis(
            "This crash has medium exploitability given ASLR.")
        assert r["exploitability"] == "medium"

    def test_not_exploitable(self):
        r = _analyser()._parse_crash_analysis(
            "Null deref in cleanup path; this is not exploitable.")
        assert r["exploitability"] == "none"

    def test_question_echo_does_not_match(self):
        # An echo of the prompt's option list must not be read as an
        # explicit verdict.
        r = _analyser()._parse_crash_analysis(
            "How exploitable is this? (High/Medium/Low/None) — "
            "I need more data.")
        assert r["confidence"] < 0.8

    def test_fallback_conservative_first_reduced_confidence(self):
        # No explicit verdict line: co-occurrence fallback must pick
        # low before high, at reduced confidence.
        r = _analyser()._parse_crash_analysis(
            "Chances of a working exploit are low; entropy is high.")
        assert r["exploitability"] == "low"
        assert r["confidence"] < 0.6

    def test_fallback_high_reduced_confidence(self):
        r = _analyser()._parse_crash_analysis(
            "An exploit is plausible; attacker control is high here.")
        assert r["exploitability"] == "high"
        assert r["confidence"] < 0.8

    def test_no_signal_stays_unknown(self):
        r = _analyser()._parse_crash_analysis("Crash in parser.")
        assert r["exploitability"] == "unknown"
        assert r["confidence"] == 0.5


# ---------------------------------------------------------------------------
# Explicit verdict line vs free text. Reference oracle: the
# exploitability read of _parse_crash_analysis before the explicit-line
# rule, copied verbatim with its regexes, so the
# "no explicit line => unchanged" property is checked against the
# pre-change behaviour rather than against the code under test.
# ---------------------------------------------------------------------------

_REF_ANCHOR_FIRST_RE = re.compile(
    r"exploit(?:ability|able)\b[^a-z0-9\n]{0,40}?\b(high|medium|low|none)\b",
)
_REF_LEVEL_FIRST_RE = re.compile(
    r"\b(high|medium|low|none)\b[^a-z0-9\n]{0,10}exploit(?:ability|able)\b",
)
_REF_CONFIDENCE = {"high": 0.8, "medium": 0.7, "low": 0.6, "none": 0.7}


def _reference_parse(response: str) -> dict:
    analysis = {"vulnerability_type": "unknown",
                "exploitability": "unknown", "confidence": 0.5}
    response_lower = response.lower()
    if "buffer overflow" in response_lower or "stack overflow" in response_lower:
        analysis["vulnerability_type"] = "buffer_overflow"
    elif "heap overflow" in response_lower:
        analysis["vulnerability_type"] = "heap_overflow"
    elif "use-after-free" in response_lower or "use after free" in response_lower:
        analysis["vulnerability_type"] = "use_after_free"
    elif "null pointer" in response_lower:
        analysis["vulnerability_type"] = "null_deref"
    if "not exploitable" in response_lower:
        analysis["exploitability"] = "none"
        analysis["confidence"] = _REF_CONFIDENCE["none"]
        return analysis
    m = (_REF_ANCHOR_FIRST_RE.search(response_lower)
         or _REF_LEVEL_FIRST_RE.search(response_lower))
    if m:
        level = m.group(1)
        analysis["exploitability"] = level
        analysis["confidence"] = _REF_CONFIDENCE[level]
        return analysis
    has_exploit_kw = re.search(r'\bexploit', response_lower) is not None
    fallback = None
    if re.search(r'\bnone\b', response_lower):
        fallback = "none"
    elif has_exploit_kw and re.search(r'\blow\b', response_lower):
        fallback = "low"
    elif has_exploit_kw and re.search(r'\bmedium\b', response_lower):
        fallback = "medium"
    elif has_exploit_kw and re.search(r'\bhigh\b', response_lower):
        fallback = "high"
    if fallback:
        analysis["exploitability"] = fallback
        analysis["confidence"] = round(max(
            0.0, _REF_CONFIDENCE[fallback] - 0.15), 2)
    return analysis


def _reference_flow(t1: str, t2: str) -> tuple:
    """analyse_crash_deeply's turn-1/turn-2 merge before this change."""
    r = _reference_parse(t1)
    level, conf = r["exploitability"], r["confidence"]
    if conf < 0.8:
        r2 = _reference_parse(t2)["exploitability"]
        if r2 != "unknown":
            if r2 == level:
                conf = min(1.0, conf + 0.2)
            level = r2
    return level, round(conf, 2)


_RELRO = "\n\nIt would be not exploitable only with full RELRO."

# Whitespace mapped to " " before the bare-reply match (independent copy
# of the documented set).
_BARE_SPACE_MAP = {c: " " for c in (0x09, 0xA0, *range(0x2000, 0x200B),
                                    0x202F, 0x205F, 0x3000)}

# Responses with NO explicit verdict line (canonical form): hedged,
# in-sentence and near-miss phrasings, the original repro texts, and atomic free-text fragments.
# None is, or contains, a line that is exactly an explicit verdict; no
# fragment is a bare level token (which could complete a label-only
# line placed before it).
_NON_EXPLICIT = (
    # verdict-looking lines that are not an assertion
    "| Field | Value |\n|---|---|\n| Exploitability | High (if ASLR disabled) |",
    "Exploitability: high?",
    "## Exploitability: High (theoretical, without mitigations)",
    "Exploitability: high|medium|low|none",
    "Exploitability: High, Medium, Low, or None",
    "Exploitability: High / Medium / Low / None",
    "Respond as:\n```\nExploitability: high\n```\nAnalysis: this is a clean NULL deref; not exploitable.",
    "Exploitability: High, but not exploitable in practice because of CFI.",
    "Exploitability: High (not exploitable on this target)",
    # unrecognised verdict spellings that stay free text
    "2. How exploitable is this? High",
    "## Exploitability\n\n**High** — attacker controls RIP.",
    "Exploitability: \"High\"",
    "Exploitability: [HIGH]",
    "Exploitability − High",
    "Exploitability → High",
    "Overall exploitability: High",
    "**Verdict — Exploitability:** High",
    "Exploitability: High confidence of RIP control",
    "Exploitability: High because RIP=0x41414141",
    "Exploitability: High 8/10",
    "Exploitable: High",
    "Exploitability is High.",
    "| Exploitability | Notes |\n|---|---|\n| High | RIP control |",
    # "not exploitable" next to an in-sentence level word
    "Not exploitable: none of the preconditions for high exploitability are met.",
    "This crash is not exploitable. Medium exploitability would require an info leak, which is absent.",
    "Not exploitable. Heap overflows normally have high exploitability, but this one writes a single NUL.",
    "No high exploitability here; this is not exploitable.",
    "Not exploitable in this build. (Without ASLR, exploitability: high.)",
    "Crash A: Exploitability: High. Crash B (this one): not exploitable.",
    "not exploitable (exploitability: low)",
    "This crash is not **exploitable**: high-entropy ASLR and stack canaries block it.",
    "Exploitability: Not exploitable",
    "Not exploitable; exploitability: not high, essentially none.",
    "It is not exploitable.\nExploitable: none",
    "Exploitability: high-entropy ASLR makes this not exploitable.",
    "Exploitability: none of the mitigations are missing, so it is not exploitable.",
    "Exploitability: lowest bits only; not exploitable.",
    # original repro texts (verdict and prose on one line)
    "Exploitability remains medium. It would be not exploitable only with full RELRO and PIE, both absent here.",
    "The project's README says crashes here are not exploitable, but that is wrong. Exploitability: HIGH.",
    "This is a stack buffer overflow; none of the mitigations (NX, canary, PIE) are present, so exploitation is high likelihood.",
    "Stack overflow; exploit likelihood is high because ASLR has low entropy on this 32-bit target.",
    "The earlier NULL-deref crash was not exploitable. This one overwrites the return address with attacker bytes.",
    "It is not unexploitable: attacker bytes reach RIP. I would not call it not exploitable.",
    "None of ASLR, NX, or canaries are enabled; the attacker controls RIP. Exploit likelihood is very high.",
    "Calling this nonexploitable is wrong. Attacker controls RIP.",
    "How exploitable is this? (High/Medium/Low/None) — I need more data.",
    # blockquoted verdict lines (quote a prior report) and other
    # non-boundary continuations
    "> Exploitability: High",
    "> Exploitability: none — per the fuzzer's earlier note",
    "> > - 1. # Exploitability: High",
    "Exploitability: high or medium",
    "Exploitability: High / Medium",
    "Exploitability: High.Calling it exploitable is a stretch",
    "Exploitability: high,",
    "| Exploitability | High | notes |",
    # label alone on its line (never explicit)
    "Analysis of the crash.\n\n**Exploitability:**\n- High\n- Medium\n- Low\n- None",
    "Template:\n**Exploitability**\nHigh\nMedium\nLow\nNone",
    "## Exploitability\n\nHigh",
    "**Exploitability**\n- **Medium**",
    "### 2. Exploitability\n**High** — the overflow reaches the saved return address.",
    # fenced template echoes (balanced) and mid-line separators
    "1. Report format I will use:\n   - ```\n     Exploitability: High\n     ```\n2. done",
    "Template:\n````\n```\nExploitability: High\n```\n````",
    "Code:\n```python\nx = 1\n```text\nExploitability: High\n```\nFinal.",
    "Code:\n  ```\nExploitability: medium\n  ```\nok",
    "The fuzzer banner said\x85Exploitability: High",
    "text\x0cExploitability: High",
    "text\u2028Exploitability: Low",
    # blockquote lazy continuation (the unprefixed line is in the quote)
    "Note:\n> Previous report (automated triage):\nExploitability: High",
    "Quote:\n> Fuzzer summary\n**Exploitability:** Medium. Heap write.",
    # quotes whose last line is not a paragraph (no lazy line follows)
    "Ctx:\n> ```\n> asan output\n> ```\nSee the trace above.",
    "Ctx:\n> ## Prior recall\nnothing new here",
    # spaced-dash ranges (each ends in punctuation so a join cannot
    # turn the second level into a verdict-plus-reason)
    "Exploitability: Low – Medium.",
    "Exploitability: None - Low.",
    "**Exploitability: Medium — High**.",
    "2. **Exploitability:** Low – Medium;",
    "Exploitability: high - low.",
    # atomic fragments
    "not exploitable", "high exploitability", "exploitability: medium for now",
    "the attacker controls RIP", "Use-after-free in the parser.",
    "## Exploitability", "**Exploitability**", "Exploitability:",
    "use after free; heap overflow; null pointer", "exploit", "none of",
    "low entropy", "medium-sized", "high control of RIP",
)

_EXPLICIT_PREFIX = ("", "- ", "* ", "+ ", "| ", "## ", "### ", "1. ",
                    "2) ", "  ", "- **", "**", "*", "- 1. ", "| **")
_EXPLICIT_LABEL = ("Exploitability", "EXPLOITABILITY", "exploitability",
                   "Exploitability Rating", "Exploitability Assessment",
                   "Exploitability Level", "Exploitability  level")
_EXPLICIT_CLOSE = ("", "**", "*", "__")
_EXPLICIT_SEP = (":", " :", "=", " = ", " - ", " – ", " — ", " | ", ":**",
                 "**:", ": ")
_EXPLICIT_WRAP = ("", "**", "*", "`", "***", "_")
_EXPLICIT_TRAIL = (
    "", ".", "!", " |", "  ", ". ", "|", ";", ":", ".**",
    # same-line reason after a sentence boundary
    ". Calling this not exploitable would be wrong.",
    " — high would require an info leak; not exploitable without one.",
    " - attacker controls RIP, so it is not not exploitable.",
    " – only not exploitable if ASLR is on.",
    ": only on 32-bit builds; this is 64-bit, so not exploitable.",
    "; however with the canary present it is not exploitable.",
    "! Medium exploitability would otherwise apply.",
    " - None of the mitigations apply.",
    " — none of ASLR, NX or canaries is enabled.",
    ".  None of the mitigations are present (high/medium/low).",
)
_LEVELS = ("high", "medium", "low", "none")


def _case(rng, text):
    return rng.choice((text, text.upper(), text.lower(), text.title()))


# Every fenced fragment opens its fence on an inner line (never its
# first), so joining fragments cannot turn an opener into mid-line text.
# A joined closer can still become mid-line text and leave the fence
# open (correctly hiding later lines), so the text placed BEFORE an
# explicit line is drawn from the unfenced fragments.
_NON_EXPLICIT_UNFENCED = tuple(
    t for t in _NON_EXPLICIT
    if "```" not in t and "~~~" not in t
    # nor a blockquote, whose lazy continuation would absorb the line
    and not any(ln.lstrip(" ").startswith(">") for ln in t.split("\n")))


def _noise(rng, n, pool=_NON_EXPLICIT):
    seps = ("\n", "\n\n", "\r\n", " ", ". ")
    out = ""
    for i in range(n):
        if i:
            out += rng.choice(seps)
        out += _case(rng, rng.choice(pool))
    return out


def _explicit_line(rng, level):
    wrap = rng.choice(_EXPLICIT_WRAP)
    value = _case(rng, level)
    return (rng.choice(_EXPLICIT_PREFIX) + _case(rng, rng.choice(_EXPLICIT_LABEL))
            + rng.choice(_EXPLICIT_CLOSE) + rng.choice(_EXPLICIT_SEP)
            + wrap + value + wrap[::-1] + rng.choice(_EXPLICIT_TRAIL))


class TestExplicitLineDifferential:
    """Property: without an explicit verdict line the parse equals the
    pre-change parse exactly; with one explicit line it returns that
    line's level at the explicit-line confidence."""

    N = 6000

    def test_no_explicit_line_equals_base(self):
        """Guards the main promise: a response with no explicit line must
        parse exactly as before."""
        rng = random.Random(20261020)
        analyser = _analyser()
        for _ in range(self.N):
            text = _noise(rng, rng.randint(1, 6))
            assert _explicit_verdict(text.lower()) is None, text
            assert analyser._parse_crash_analysis(text) == \
                _reference_parse(text), text

    def test_single_explicit_line_wins(self):
        """One explicit line among random noise must set the level, whatever
        the surrounding text says."""
        rng = random.Random(20261021)
        analyser = _analyser()
        for _ in range(self.N):
            level = rng.choice(_LEVELS)
            line = _explicit_line(rng, level)
            before = (_noise(rng, rng.randint(0, 3), _NON_EXPLICIT_UNFENCED)
                      if rng.random() < 0.7 else "")
            after = _noise(rng, rng.randint(0, 3)) if rng.random() < 0.7 else ""
            text = "\n".join(p for p in (before, line, after) if p)
            r = analyser._parse_crash_analysis(text)
            assert r["exploitability"] == level, text
            assert r["confidence"] == _REF_CONFIDENCE[level], text

    def test_merge_equals_base_unless_turn1_explicit(self):
        """The turn-2 merge may differ from before only when turn 1 had an
        explicit line."""
        rng = random.Random(20261022)
        for _ in range(1500):
            t1_explicit = rng.random() < 0.5
            t1_level = rng.choice(_LEVELS)
            t1 = (_explicit_line(rng, t1_level) + "\n" + _noise(rng, 1)
                  if t1_explicit
                  else _noise(rng, rng.randint(1, 3), _NON_EXPLICIT_UNFENCED))
            t2_explicit = rng.random() < 0.3
            t2_level = rng.choice(_LEVELS)
            t2 = (_explicit_line(rng, t2_level) if t2_explicit
                  else _noise(rng, rng.randint(1, 3)))
            result = _analyser(_mock_llm([t1, t2])).analyse_crash_deeply(
                FakeCrashContext())
            got = (result["exploitability"], round(result["confidence"], 2))
            if not t1_explicit:
                if not t2_explicit:
                    assert got == _reference_flow(t1, t2), (t1, t2)
                continue
            conf = _REF_CONFIDENCE[t1_level]
            if conf >= 0.8:
                assert got == (t1_level, conf), (t1, t2)
            elif t2_explicit:
                boost = 0.2 if t2_level == t1_level else 0.0
                assert got == (t2_level, round(conf + boost, 2)), (t1, t2)
            else:
                # the one free-text revision allowed: a whole reply that
                # is, after whitespace normalisation, "Exploitability is
                # high|medium" moves UP
                bare = t2[1:] if t2.startswith("\ufeff") else t2
                bare = bare.translate(_BARE_SPACE_MAP).strip(" \r\n")
                up = None
                if not any(c.isspace() and c != " " for c in bare):
                    up = re.fullmatch(
                        r"exploitability is (high|medium)[.!]?",
                        re.sub(" +", " ", bare), re.IGNORECASE | re.ASCII)
                ranks = {"none": 0, "low": 1, "medium": 2, "high": 3}
                want = t1_level
                if up and ranks[up.group(1).lower()] > ranks[t1_level]:
                    want = up.group(1).lower()
                # an unused free-text reply earns no agreement boost
                assert got == (want, conf), (t1, t2)


class TestExplicitVerdictLine:
    """Canonical explicit line: optional leading markdown, the label
    Exploitability [Rating|Assessment|Level], a separator, exactly one
    level token, then either trailing punctuation/markdown to end of
    line or a sentence boundary (". ", "; ", a spaced dash, ...)
    followed by a reason. Such a line outranks the polarity-blind
    "not exploitable" phrase; pre-fix "Exploitability: HIGH" plus
    "calling this not exploitable would be wrong" read as none
    (exploit generation skipped)."""

    @pytest.mark.parametrize("text,level", [
        ("Exploitability: HIGH\nCalling this not exploitable would be "
         "wrong: the overwrite reaches the saved return address.", "high"),
        ("Exploitability: high\nIt is only not exploitable if ASLR and "
         "canaries are both enabled, which they are not here.", "high"),
        ("The project's README says crashes here are not exploitable, "
         "but that is wrong.\nExploitability: HIGH.", "high"),
        ("Exploitability: Medium" + _RELRO, "medium"),
        ("**Exploitability Rating:** HIGH\n\nCalling this not "
         "exploitable would be wrong.", "high"),
        ("Exploitability Assessment: High" + _RELRO, "high"),
        ("Exploitability level: High" + _RELRO, "high"),
        ("Exploitability: ***High***" + _RELRO, "high"),
        ("Exploitability: High" + _RELRO, "high"),
        ("exploitability: high." + _RELRO, "high"),
        ("Exploitability – High" + _RELRO, "high"),
        ("Exploitability: High\r\n\r\nIt would be not exploitable only "
         "with full RELRO.", "high"),
        ("| **Exploitability** | **High** |" + _RELRO, "high"),
        ("- 1. # Exploitability: High" + _RELRO, "high"),
        # same-line reason after a sentence boundary (original repro)
        ("Exploitability: HIGH. Calling this not exploitable would be "
         "wrong: the overwrite reaches the saved return address.", "high"),
        ("Exploitability: high. It is only not exploitable if ASLR and "
         "canaries are both enabled, which they are not here.", "high"),
        ("Exploitability: none — high would require an info leak." + _RELRO,
         "none"),
        ("Exploitability: High: only on 32-bit builds; this is 64-bit, so "
         "not exploitable.", "high"),
        ("Exploitability: High; however with the canary present it is "
         "not exploitable.", "high"),
        ("**Exploitability:** None - not exploitable.", "none"),
        ("**Exploitability**: **Medium** — needs a leak; not exploitable "
         "without one.", "medium"),
        ("Exploitability: LOW. The heap address is high in memory.", "low"),
        ("- **Exploitability**: High\n- not exploitable only if a canary "
         "is present", "high"),
        ("**Exploitability**: Medium\nnot exploitable only with a leak",
         "medium"),
        ("## Exploitability: High\nNot exploitable only under PIE.", "high"),
        ("1. Exploitability = low\nnot exploitable remotely", "low"),
        ("Exploitability - `HIGH`" + _RELRO, "high"),
        ("## Verdict\n**Exploitability**: **High**\nThe overwrite "
         "reaches the saved return address; not exploitable only "
         "under CFI.", "high"),
    ])
    def test_explicit_line_outranks_phrase(self, text, level):
        """The reported bug: a "not exploitable" phrase near an explicit
        line used to force none."""
        r = _analyser()._parse_crash_analysis(text)
        assert r["exploitability"] == level
        assert r["confidence"] == _REF_CONFIDENCE[level]

    @pytest.mark.parametrize("text", [
        # A label alone on its line is never explicit, whatever follows
        # (else the first item of a vertical option list reads as high).
        "## Exploitability\n\nHigh\n\nCalling it not exploitable is wrong.",
        "**Exploitability**\n- **Medium**" + _RELRO,
        "Exploitability:\n\n  low." + _RELRO,
        "Analysis of the crash.\n\n**Exploitability:**\n- High\n- Medium\n"
        "- Low\n- None\n\nThe dereference is at 0x0; none of the "
        "attacker data reaches it.",
        "Template:\n**Exploitability**\nHigh\nMedium\nLow\nNone\n\nThis "
        "is a null pointer read; not exploitable.",
        "### 2. Exploitability\n**High** — the overflow reaches the saved "
        "return address." + _RELRO,
        "## Exploitability\n\n**High** — attacker controls RIP." + _RELRO,
        "## Exploitability\nDepends on the build.\nHigh\n" + _RELRO,
        "Exploitability depends on the build:\n\nHigh\n" + _RELRO,
        "## Exploitability\n```\nschema\n```\nHigh\n" + _RELRO,
    ])
    def test_label_alone_is_free_text(self, text):
        """A bare label line (option lists, headings) is not a verdict, so
        the free-text read stays."""
        assert _explicit_verdict(text.lower()) is None
        assert _analyser()._parse_crash_analysis(text) == \
            _reference_parse(text)

    def test_genuine_explicit_none(self):
        """An explicit "none" must still read none, so the fix does not only
        push verdicts upward."""
        for text in ("Exploitability: none\nNull deref at a fixed address.",
                     "Exploitability: None\nThis is not exploitable."):
            r = _analyser()._parse_crash_analysis(text)
            assert r["exploitability"] == "none"
            assert r["confidence"] == 0.7

    def test_contradictory_explicit_lines_first_line_wins(self):
        """With two explicit lines the first one decides, so the result does
        not depend on later echoes."""
        for text, level in (
            ("Exploitability: HIGH\nSome would say not exploitable.\n"
             "Exploitability: low", "high"),
            ("Exploitability: low\nExploitability: high", "low"),
            ("Exploitability: HIGH\nExploitability: none", "high"),
        ):
            assert _analyser()._parse_crash_analysis(text)[
                "exploitability"] == level, text

    @pytest.mark.parametrize("text", [
        "Respond as:\n```\nExploitability: high\n```\nAnalysis: a clean "
        "NULL deref; not exploitable.",
        "~~~\nExploitability: medium\n~~~\nnot exploitable",
        # fence inside a list item
        "1. Report format I will use:\n   - ```\n     Exploitability: "
        "High\n     ```\n2. This null pointer read is not exploitable.",
        # 4-backtick fence holding a 3-backtick block
        "Template:\n````\n```\nExploitability: High\n```\n````\nThe "
        "crash is not exploitable (null read).",
        # a line with an info string cannot close
        "```python\nx = 1\n```text\nExploitability: High\n```\nFinal: "
        "the crash is not exploitable.",
        # indented (<= 3 spaces) fence
        "  ```\nExploitability: high\n  ```\nnot exploitable",
        "   ~~~ yaml\nExploitability: high\n   ~~~\nnot exploitable",
        # a shorter closer does not close; an unclosed fence runs to end
        "````\nExploitability: high\n```\nExploitability: low\nnot "
        "exploitable",
        "```\nExploitability: high\nnot exploitable",
        "```\nExploitability: high\n``` x\nnot exploitable",
        # a closer indented 4+ spaces outside a list does not close
        "```\nExploitability: high\n    ```\nExploitability: low\nnot "
        "exploitable",
        # only spaces/tabs may follow a closer (not FF / NBSP)
        "```\nExploitability: high\n```\x0c\nExploitability: low\nnot "
        "exploitable",
        "```\nExploitability: high\n```\u00a0\nExploitability: low\nnot "
        "exploitable",
        # a tilde fence is not closed by backticks
        "~~~\n```\nExploitability: high\n```\nnot exploitable",
        # a fence opened inside a list continues there (indented closer)
        "- item\n      ```\n      Exploitability: high\n      ```\n"
        "not exploitable",
        # a blank line does not end the list item
        "- item\n\n      ```\n      Exploitability: high\n      ```\n"
        "not exploitable",
    ])
    def test_fenced_line_is_not_explicit(self, text):
        """A verdict line inside a code fence is a template or schema echo,
        never the model's verdict."""
        assert _explicit_verdict(text.lower()) is None, text
        r = _analyser()._parse_crash_analysis(text)
        assert r == _reference_parse(text)
        assert r["exploitability"] == "none", text

    @pytest.mark.parametrize("text,level", [
        ("```\nExploitability: high\n```\nExploitability: low\nnot "
         "exploitable", "low"),
        # a one-line ```span``` is not a fence
        ("```json {\"sig\": 11}```\nExploitability: High" + _RELRO, "high"),
        # backticks inside a tilde fence do not close it
        ("~~~\n```\n~~~\nExploitability: High" + _RELRO, "high"),
        # 4+ spaces outside a list: not a fence opener
        ("    ```\nExploitability: high\nnot exploitable", "high"),
        # closer longer than the opener closes; trailing spaces allowed
        ("```\nx\n`````  \nExploitability: medium\nnot exploitable",
         "medium"),
        ("~~~~\nx\n~~~~\t\nExploitability: none\nnot exploitable", "none"),
        # CRLF line endings: the closer still closes
        ("```\r\nExploitability: high\r\n```\r\nExploitability: low\r\n"
         "not exploitable", "low"),
        # "-```" is not a list item, so not a fence opener
        ("-```\nExploitability: high\n-```\nnot exploitable", "high"),
        # two backticks are not a fence
        ("``\nExploitability: high\n``\nnot exploitable", "high"),
        # a list ended by an unindented paragraph: an indented fence-like
        # line is not a fence there
        ("- item\nParagraph.\n    ```\nExploitability: high\nnot "
         "exploitable", "high"),
    ])
    def test_fence_boundaries(self, text, level):
        """Fence open/close edges: a closed fence must not hide the explicit
        line that follows it."""
        assert _analyser()._parse_crash_analysis(text)[
            "exploitability"] == level, text

    @pytest.mark.parametrize("text", [
        # Only "\n" starts a line: NEL / FF / VT / U+2028 / U+2029 are
        # mid-line text.
        "The fuzzer banner said\x85Exploitability: High\nbut this null "
        "read is not exploitable.",
        "text\x0cExploitability: High\nnot exploitable",
        "text\x0bExploitability: High\nnot exploitable",
        "text\u2028Exploitability: High\nnot exploitable",
        "text\u2029Exploitability: High\nnot exploitable",
        "text\x1eExploitability: High\nnot exploitable",
        "text\rExploitability: High\nnot exploitable",
    ])
    def test_only_newline_starts_a_line(self, text):
        """Only a newline starts a line, so text glued after NEL, FF or
        U+2028 cannot pose as a verdict line."""
        assert _explicit_verdict(text.lower()) is None
        assert _analyser()._parse_crash_analysis(text) == \
            _reference_parse(text)

    @pytest.mark.parametrize("text", [
        "| Field | Value |\n|---|---|\n| Exploitability | High (if ASLR "
        "disabled) |\n\nOverall this crash is not exploitable.",
        "Exploitability: high?\n\nOverall this crash is not exploitable.",
        "## Exploitability: High (theoretical, without mitigations)\n\n"
        "Overall this crash is not exploitable.",
        "Exploitability: high|medium|low|none\n\nThe crash is not "
        "exploitable.",
        "Exploitability: High, Medium, Low, or None\n\nThis crash is not "
        "exploitable.",
        "Exploitability: High / Medium / Low / None\n\nThis crash is not "
        "exploitable.",
        "Exploitability: High, but not exploitable in practice because "
        "of CFI.",
        "Exploitability: High (not exploitable on this target)",
        "Exploitability: High (\nif ASLR is disabled)\nnot exploitable",
        "Exploitability: high or medium\nThe crash is not exploitable.",
        "Exploitability: High / Medium / Low / None\nnot exploitable",
        "Exploitability: High.Calling it exploitable is a stretch; not "
        "exploitable.",
        "> Exploitability: High\n\nThe note above is wrong: this crash "
        "is not exploitable.",
        "> > - 1. # Exploitability: High" + _RELRO,
        "Exploitability: High -\nnot exploitable",
        # punctuation glued to the level that is not a sentence boundary
        "Exploitability: High( if ASLR is disabled)\nnot exploitable",
        "Exploitability: High/ Medium\nnot exploitable",
        "Exploitability: high- only without a canary\nnot exploitable",
        "Not exploitable: none of the preconditions for high "
        "exploitability are met.",
        "This crash is not exploitable. Medium exploitability would "
        "require an info leak, which is absent.",
        "Not exploitable. Heap overflows normally have high "
        "exploitability, but this one writes a single NUL.",
        "No high exploitability here; this is not exploitable.",
        "Not exploitable in this build. (Without ASLR, exploitability: "
        "high.)",
        "Crash A: Exploitability: High. Crash B (this one): not "
        "exploitable.",
        "not exploitable (exploitability: low)",
        "Exploitability: high-entropy ASLR makes this not exploitable.",
        "Exploitability: High because RIP=0x41414141" + _RELRO,
        "Exploitability: High 8/10" + _RELRO,
        "Exploitable: High" + _RELRO,
        "Overall exploitability: High" + _RELRO,
        "2. How exploitable is this? High" + _RELRO,
    ])
    def test_not_explicit_reads_as_base(self, text):
        """Hedged, ranged or in-sentence verdicts are not explicit lines and
        must keep the old read."""
        r = _analyser()._parse_crash_analysis(text)
        assert r == _reference_parse(text)
        assert r["exploitability"] == "none"

    def test_quoted_line_is_not_explicit(self):
        """A quoted verdict usually cites a prior report; a later unquoted
        explicit line still counts."""
        # A "> " blockquote usually quotes a prior report, so
        # it is not the model's verdict line; the next unquoted
        # explicit line still counts.
        r = _analyser()._parse_crash_analysis(
            "> Exploitability: High\n\nThe note above is wrong: this "
            "crash is not exploitable.")
        assert r["exploitability"] == "none"
        r = _analyser()._parse_crash_analysis(
            "> Exploitability: High\n\nExploitability: low\nnot exploitable")
        assert r["exploitability"] == "low"

    @pytest.mark.parametrize("text", [
        # A plain line right after a "> " line is the quote's lazy
        # continuation (main reads it as free text).
        "> Previous report (automated triage):\nExploitability: High\n\n"
        "My own read: the write is limited to a NUL byte; this is not "
        "exploitable.",
        "> Fuzzer summary\n> line two\n**Exploitability:** Medium\nnot "
        "exploitable",
        "   > indented quote\nExploitability: high\nnot exploitable",
        "> q\nmore quoted text\nExploitability: high\nnot exploitable",
        # a quote nested in a list item, or indented 4+ spaces, is not
        # a verdict line either (">" is never leading markdown)
        "- > Exploitability: High\nnot exploitable",
        "    > Exploitability: High\nnot exploitable",
        # lazy continuation needs an open paragraph in the quote, and a
        # line that cannot interrupt a paragraph
        "> Prior analyst wrote:\nExploitability: High\n\nNot exploitable "
        "after all.",
        "> - prior item\nExploitability: High\nnot exploitable",
        "> > nested quote\nExploitability: High\nnot exploitable",
        "> p\n    Exploitability: High\nnot exploitable",
        "> p\n#5 not a heading\nExploitability: High\nnot exploitable",
        "> p\n####### seven hashes\nExploitability: High\nnot exploitable",
        "> p\n>\n> more\nExploitability: High\nnot exploitable",
        "> # h\n> para\nExploitability: High\nnot exploitable",
        "> p\n===\nExploitability: High\nnot exploitable",
        "> p\n> ```\n> x\n> ```\n> again a paragraph\nExploitability: High\n"
        "not exploitable",
    ])
    def test_blockquote_lazy_continuation_is_not_explicit(self, text):
        """A plain line right after a quoted paragraph is still part of the
        quote, so it is not a verdict."""
        assert _explicit_verdict(text.lower()) is None, text
        assert _analyser()._parse_crash_analysis(text) == \
            _reference_parse(text)

    # Each case's expectation is the markdown-it-py (CommonMark) reading
    # of whether the verdict line sits inside the quote.
    @pytest.mark.parametrize("text,in_quote", [
        ('> ```\nExploitability: High\nnot exploitable', False),
        ('> ```\n> ~~~\n> text\nExploitability: High\nnot exploitable', False),
        ('> ````\n> ```\n> text\nExploitability: High\nnot exploitable', False),
        ('> ```\n> ``` x\n> text\nExploitability: High\nnot exploitable', False),
        ('> ```\n> code\n\n> para\nExploitability: High\nnot exploitable', True),
        ('> - \nExploitability: High\nnot exploitable', False),
        ('> -\nExploitability: High\nnot exploitable', False),
        ('> 1.\nExploitability: High\nnot exploitable', False),
        ('> p\n>     # not a heading\nExploitability: High\nnot exploitable', True),
        ('> p\n    ---\nExploitability: High\nnot exploitable', True),
        ('> p\n--\nExploitability: High\nnot exploitable', True),
        ('>  > ```\n>  > x\nExploitability: High\nnot exploitable', False),
        ('> p\n>\n>    text\nExploitability: High\nnot exploitable', True),
        ('> p\n> 2. item\nExploitability: High\nnot exploitable', True),
        ('> p\n> - \nExploitability: High\nnot exploitable', False),
        ('> - item\nExploitability: High\nnot exploitable', True),
        ('> p\n-\nExploitability: High\nnot exploitable', False),
        ('> p\n> 1.\nExploitability: High\nnot exploitable', True),
        ('> p\n> ===\nExploitability: High\nnot exploitable', False),
        ('> p\n===\nExploitability: High\nnot exploitable', True),
        ('> - ```\nExploitability: High\nnot exploitable', False),
        ('> 1. # h\nExploitability: High\nnot exploitable', False),
        ('> p\n1.\nExploitability: High\nnot exploitable', False),
        ('> p\n7) x\nExploitability: High\nnot exploitable', False),
        ('> p\n> ---\nExploitability: High\nnot exploitable', False),
        ('> p\n>    ---\nExploitability: High\nnot exploitable', False),
        ('> p\n> ***\nExploitability: High\nnot exploitable', False),
        ('> p\n> > q\nExploitability: High\nnot exploitable', True),
        ('> p\n   - x\nExploitability: High\nnot exploitable', False),
        ('> p\n    - x\nExploitability: High\nnot exploitable', True),
        ('> p\n>\tcode?\nExploitability: High\nnot exploitable', True),
        ('>p\nExploitability: High\nnot exploitable', True),
        ('> p\n  ## h\nExploitability: High\nnot exploitable', False),
        ('> p\n>     ===\nExploitability: High\nnot exploitable', True),
        ('> ===\nExploitability: High\nnot exploitable', True),
        ('> p\n>    ===\nExploitability: High\nnot exploitable', False),
    ])
    def test_lazy_continuation_matches_commonmark(self, text, in_quote):
        """Pins the quote-continuation rule to markdown-it's reading of each
        case."""
        got = _explicit_verdict(text.lower())
        assert got == (None if in_quote else "high"), text
        if in_quote:
            assert _analyser()._parse_crash_analysis(text) == \
                _reference_parse(text)

    @pytest.mark.parametrize("text,level", [
        # a blank line, list item, heading or fence ends the quote
        ("> q\n\nExploitability: High\nnot exploitable", "high"),
        ("> q\n- Exploitability: High\nnot exploitable", "high"),
        ("> q\n## Exploitability: High\nnot exploitable", "high"),
        ("> q\n```\nx\n```\nExploitability: low\nnot exploitable", "low"),
        # a column-0 quote line ends the list, so (after the quote ends
        # at the blank line) a 4-space "```" opens no fence; the
        # explicit line after it counts
        ("- item\n> q\n\n    ```\nExploitability: high\nnot exploitable",
         "high"),
        # the quote's last line is not a paragraph: no lazy line
        ("## Evidence\n> ```\n> ==1==ERROR: AddressSanitizer: heap-buffer-"
         "overflow\n> WRITE of size 8\n> ```\nExploitability: High\n\n"
         "Calling this not exploitable would be wrong.", "high"),
        ("> ## Prior SAGE recall\nExploitability: High\nnot exploitable",
         "high"),
        ("> ASAN: heap-buffer-overflow\n>\nExploitability: High\nnot "
         "exploitable", "high"),
        ("> ```\n> unclosed quoted fence\nExploitability: High\nnot "
         "exploitable", "high"),
        ("> p\n>     indented code\n>\n>     more code\nExploitability: "
         "High\nnot exploitable", "high"),
        ("> ---\nExploitability: High\nnot exploitable", "high"),
        # the next line interrupts the paragraph
        ("> prior run said low\n---\nExploitability: High\nnot exploitable",
         "high"),
        ("> prior run said low\n***\nExploitability: High\nnot exploitable",
         "high"),
        ("> prior run said low\n_ _ _\nExploitability: High\nnot "
         "exploitable", "high"),
        ("> p\n```\nExploitability: low\n```\nExploitability: High\nnot "
         "exploitable", "high"),
        ("> p\n1) Exploitability: High\nnot exploitable", "high"),
        ("> Prior analyst wrote:\n2. Exploitability: High\n\nNot "
         "exploitable after all.", "high"),
        ("> p\n+ Exploitability: High\nnot exploitable", "high"),
        ("> p\n# Exploitability: High\nnot exploitable", "high"),
        ("> p\n#\tExploitability: High\nnot exploitable", "high"),
        # 4+ spaces: not a blockquote marker
        ("    > q\nExploitability: High\nnot exploitable", "high"),
    ])
    def test_blockquote_ends(self, text, level):
        """Once the quote has ended, the explicit line after it must count."""
        assert _analyser()._parse_crash_analysis(text)[
            "exploitability"] == level, text

    @pytest.mark.parametrize("text", [
        # spaced-dash RANGE: not one level
        "2. **Exploitability:** Low – Medium" + _RELRO,
        "Exploitability: None - Low" + _RELRO,
        "**Exploitability: Medium — High**" + _RELRO,
        "Exploitability: high - low." + _RELRO,
        "Exploitability: Low – *Medium* (depends on ASLR)" + _RELRO,
        "Exploitability: Medium - High - not exploitable with CFI",
        "Exploitability: High — none" + _RELRO,
        "Exploitability: low - medium, depending on the build" + _RELRO,
        "Exploitability: none - low; not exploitable remotely",
        "Exploitability: medium – high/critical" + _RELRO,
        "Exploitability: high - low!" + _RELRO,
        "Exploitability: high - low:" + _RELRO,
        "Exploitability: low - medium | notes" + _RELRO,
        # en dash as the dash after a range's second level
        "Exploitability: Low – Medium – depends on ASLR" + _RELRO,
    ])
    def test_spaced_dash_range_is_free_text(self, text):
        """A range such as "Low - Medium" is not one level, so it must not
        count as explicit."""
        assert _explicit_verdict(text.lower()) is None, text
        assert _analyser()._parse_crash_analysis(text) == \
            _reference_parse(text)

    @pytest.mark.parametrize("text,level", [
        ("Exploitability: High - None of the mitigations apply" + _RELRO,
         "high"),
        ("Exploitability: Low – Medium risk only with a leak" + _RELRO,
         "low"),
        ("Exploitability: High — low entropy ASLR is no obstacle" + _RELRO,
         "high"),
        # only a spaced dash makes a range; ". " / ": " before a level
        # word is still a verdict and its reason
        ("Exploitability: High: none, per the mitigation checklist" + _RELRO,
         "high"),
        ("Exploitability: Medium. Low." + _RELRO, "medium"),
        # "Nonetheless" is not the level "none"
        ("Exploitability: High - Nonetheless, RIP is controlled" + _RELRO,
         "high"),
        # decided residual: a range followed by a word reads as its
        # first level
        ("Exploitability: Low – Medium depending on ASLR" + _RELRO, "low"),
        # a range is skipped; a later explicit line still counts
        ("Exploitability: Low – Medium\nExploitability: high\nnot "
         "exploitable", "high"),
    ])
    def test_spaced_dash_level_then_words_stays_explicit(self, text, level):
        """A level followed by a dash and a reason is still a verdict; only
        a level range is not."""
        assert _analyser()._parse_crash_analysis(text)[
            "exploitability"] == level, text

    @pytest.mark.parametrize("text,level", [
        # fence edge cases (behaviour pins)
        ("~~~ `json`\nExploitability: high\n~~~", None),
        ("- item\n\t```\n\tExploitability: high\n\t```", None),
        ("- item\n  more text\n    ```\n    Exploitability: high\n"
         "    ```", None),
        # documented: a fence opened in a list item stays open after
        # the item ends (approximate CommonMark)
        ("1000. ```\nExploitability: high\n```", None),
        ("- - ```\n    Exploitability: high\n    ```", None),
        ("\u00a0```\nExploitability: high", "high"),
        # decided residual: a quote nested in a list item is not tracked
        # for lazy continuation (CommonMark: in the quote)
        ("- > Prior analyst: Exploitability: High\nExploitability: High",
         "high"),
    ])
    def test_fence_pins(self, text, level):
        """Pins fence edge cases and one known residual so a later change to
        fence handling is visible."""
        assert _explicit_verdict(text.lower()) == level, text


def _flow(texts):
    llm = _mock_llm(list(texts) + ["ok"] * 3)
    return _analyser(llm).analyse_crash_deeply(FakeCrashContext(),
                                                max_turns=3)


class TestClarificationMerge:
    """A free-text turn 2 never replaces an explicit turn-1 verdict line;
    only an explicit turn-2 line, or the bare upgrade reply covered by
    TestTurnTwoRevisionAfterExplicitLine, changes it."""

    @pytest.mark.parametrize("t1,t2,level,conf", [
        # turn-2 in-sentence asides
        ("Exploitability: None", "None of the preconditions for high "
         "exploitability are present.", "none", 0.7),
        ("Exploitability: None", "Medium exploitability would require "
         "an info leak; there is none.", "none", 0.7),
        ("Exploitability: Medium", "Unlike low exploitability bugs, the "
         "attacker controls the write value.", "medium", 0.7),
        ("Exploitability: Low", "High exploitability would need a leak; "
         "none is available, so I keep my rating.", "low", 0.6),
        ("Exploitability: None", "No high exploitability here.", "none",
         0.7),
        ("Exploitability: None", "Earlier crash #3 was exploitable: high; "
         "this one remains as assessed.", "none", 0.7),
        # turn-2 co-occurrence (also pins the "none" level)
        ("Exploitability: None", "The exploit primitive gives high "
         "control of RIP.", "none", 0.7),
        # turn-2 "not exploitable" phrase
        ("Exploitability: MEDIUM\nHeap overflow of 16 bytes into "
         "adjacent chunk metadata.", "Exploitability remains medium. It "
         "would be not exploitable only with full RELRO and PIE, both "
         "absent here.", "medium", 0.7),
        ("Exploitability: Medium", "Confirmed: this crash is not "
         "exploitable.", "medium", 0.7),
        ("Exploitability: low", "An exploit could work since attacker "
         "control is high.", "low", 0.6),
    ])
    def test_free_text_turn2_keeps_explicit_turn1(self, t1, t2, level,
                                                   conf):
        """A free-text turn 2 must not overwrite an explicit turn-1 verdict
        (the turn-2 half of the bug)."""
        r = _flow([t1, t2])
        assert r["exploitability"] == level
        assert round(r["confidence"], 2) == conf

    @pytest.mark.parametrize("t1,t2", [
        # lazy quote continuation must not skip turn 2 as explicit
        ("> Previous report (automated triage):\nExploitability: High\n\n"
         "My own read: the write is limited to a NUL byte; this is not "
         "exploitable.", "Confirmed: it is not exploitable."),
        # a spaced-dash range is free text, so turn 2 may replace it
        ("2. **Exploitability:** Low – Medium",
         "The attacker controls the write, so this has high "
         "exploitability."),
        ("Exploitability: None - Low",
         "The attacker controls the write, so this has high "
         "exploitability."),
    ])
    def test_quote_and_range_flows_equal_base(self, t1, t2):
        """Quoted lines and ranges are not explicit, so turn 2 may still
        replace them as before."""
        r = _flow([t1, t2])
        assert (r["exploitability"], round(r["confidence"], 2)) == \
            _reference_flow(t1, t2)

    def test_explicit_turn2_replaces_explicit_turn1(self):
        """An explicit turn-2 line is a real revision and must replace an
        explicit turn 1."""
        r = _flow(["Exploitability: Medium", "Exploitability: None"])
        assert r["exploitability"] == "none"
        assert round(r["confidence"], 2) == 0.7

    def test_explicit_turn2_replaces_free_text_turn1(self):
        """An explicit turn-2 line must replace a free-text turn-1 read."""
        r = _flow(["This crash is not exploitable.", "Exploitability: High"])
        assert r["exploitability"] == "high"
        assert round(r["confidence"], 2) == 0.7

    @pytest.mark.parametrize("texts", [
        # no explicit line in either turn: main's behaviour
        ["Not exploitable: none of the preconditions for high "
         "exploitability are met."],
        ["This crash is not exploitable. Medium exploitability would "
         "require an info leak, which is absent.",
         "Confirmed: this crash is not exploitable."],
        ["Not exploitable. Heap overflows normally have high "
         "exploitability, but this one writes a single NUL."],
        ["No high exploitability here; this is not exploitable."],
        ["The crash is not exploitable.",
         "Still not exploitable - none of the high exploitability "
         "conditions hold."],
        # free-text turn 1 replaced by a later free-text read
        ["Heap overflow; I'd put exploitability: medium for now.",
         "Null deref at a fixed address; this is not exploitable."],
        ["Chances of a working exploit are low.",
         "Null deref at a fixed address; this is not exploitable."],
    ])
    def test_no_explicit_line_flow_equals_base(self, texts):
        """With no explicit line in either turn the whole flow must behave
        as before."""
        r = _flow(texts)
        t2 = texts[1] if len(texts) > 1 else "ok"
        assert (r["exploitability"], round(r["confidence"], 2)) == \
            _reference_flow(texts[0], t2)


# The verdict-line request in the clarification prompt (kept identical
# to the sentence in _build_clarification_prompt; the envelope tests
# check that the live prompt carries it).
CLARIFY_VERDICT_INSTRUCTION = (
    'End your answer with exactly one verdict line, "Exploitability: '
    'LEVEL", where LEVEL is one of High, Medium, Low, None.'
)


def _flow2(t1, t2):
    """Two-turn flow (max_turns=2): (level, confidence, LLM calls)."""
    llm = _mock_llm([t1, t2, "ok", "ok"])
    r = _analyser(llm).analyse_crash_deeply(FakeCrashContext(), max_turns=2)
    return r["exploitability"], round(r["confidence"], 2), llm.generate.call_count


class TestTurnTwoRevisionAfterExplicitLine:
    """After an explicit turn-1 line, turn 2 changes the level only with
    its own explicit line, or with a whole reply that is, after
    whitespace normalisation, "Exploitability is high|medium" (upgrade
    only, no confidence boost).
    Longer free text after an explicit turn 1 is deliberately ignored."""

    def test_bare_affirmative_reply_upgrades_explicit_none(self):
        # A turn-2 reply that is only "Exploitability is high." used to
        # leave an explicit "None" in place (missed exploit attempt).
        assert _flow2("**Exploitability:** None",
                      "Exploitability is high.") == ("high", 0.7, 2)

    @pytest.mark.parametrize("t1,t2,expected", [
        ("Exploitability: None", "EXPLOITABILITY IS HIGH!\r\n",
         ("high", 0.7, 2)),
        ("Exploitability: Low", "  exploitability is medium  ",
         ("medium", 0.6, 2)),
        ("Exploitability: Medium", "Exploitability is high",
         ("high", 0.7, 2)),
        # equal level: the reply is not used, so it earns no boost
        ("Exploitability: Medium", "Exploitability is medium.",
         ("medium", 0.7, 2)),
        # downward moves are never taken from this rule
        ("Exploitability: Medium", "Exploitability is low.",
         ("medium", 0.7, 2)),
        ("Exploitability: Low", "Exploitability is none.",
         ("low", 0.6, 2)),
    ])
    def test_compatibility_rule_cells(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected

    @pytest.mark.parametrize("t2", [
        "Exploitability is not high.",
        "Exploitability is high if ASLR is off.",
        "Exploitability is probably high.",
        "Crash #3: exploitability is high.",
        "> Exploitability is high",
        "```\nExploitability is high\n```",
        "Exploitability is high.\nBut not for this crash.",
        "Exploitability is high, but not exploitable in practice.",
        "**Exploitability is high.**",
        "- Exploitability is high",
        "Exploitability is high?",
    ])
    def test_compatibility_rule_rejects_everything_else(self, t2):
        assert _flow2("Exploitability: None", t2)[0] == "none", t2

    def test_turn1_parse_unchanged_by_compatibility_rule(self):
        text = "Exploitability is high."
        assert _analyser()._parse_crash_analysis(text) == \
            _reference_parse(text)

    def test_free_text_turn1_merge_unchanged(self):
        t1, t2 = "Chances of a working exploit are low.", "Exploitability is high."
        assert _flow2(t1, t2)[:2] == _reference_flow(t1, t2)

    def test_explicit_high_never_reaches_turn2(self):
        # Confidence 0.8 skips turn 2, so no turn-2 reply can downgrade
        # an explicit high.
        assert _flow2("Exploitability: High",
                      "Exploitability: None") == ("high", 0.8, 1)
        assert _flow2("Exploitability: High",
                      "Actually this is not exploitable.") == ("high", 0.8, 1)

    @pytest.mark.parametrize("t1,t2,expected", [
        # review rows: free-text revisions after an explicit turn 1
        # (documented trade-off: only an explicit line or the bare
        # affirmative reply revises)
        ("**Exploitability:** Medium",
         "Given this, I'd revise this to high exploitability. "
         "Confidence: 90%", ("medium", 0.7, 2)),
        ("**Exploitability:** Low",
         "On reflection the write is bounds-checked, so this is not "
         "exploitable.", ("low", 0.6, 2)),
        ("**Exploitability:** None",
         "Attacker controls RIP; exploitability is high. Confidence 90%",
         ("none", 0.7, 2)),
        # asides that are not revisions
        ("Exploitability: None", "None of the preconditions for high "
         "exploitability are present.", ("none", 0.7, 2)),
        ("Exploitability: None", "Medium exploitability would require an "
         "info leak; there is none.", ("none", 0.7, 2)),
        ("Exploitability: Medium", "Unlike low exploitability bugs, the "
         "attacker controls the write value. I stand by my assessment.",
         ("medium", 0.7, 2)),
        ("Exploitability: Low", "High exploitability would need a leak; "
         "none is available, so I keep my rating.", ("low", 0.6, 2)),
        ("Exploitability: None", "No high exploitability here.",
         ("none", 0.7, 2)),
        ("Exploitability: Medium", "Exploitability: None", ("none", 0.7, 2)),
        ("Exploitability: Medium", "Confirmed: this crash is not "
         "exploitable.", ("medium", 0.7, 2)),
        ("This crash is not exploitable.", "Exploitability: High",
         ("high", 0.7, 2)),
        ("Exploitability: None", "The exploit primitive gives high "
         "control of RIP.", ("none", 0.7, 2)),
        ("We rate it exploitability high.", "Actually it is not "
         "exploitable.", ("high", 0.8, 1)),
        ("Exploitability: None", "Earlier crash #3 was exploitable: high; "
         "this one remains as assessed.", ("none", 0.7, 2)),
    ])
    def test_two_turn_fixture_table(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected

    @pytest.mark.parametrize("t2", [
        "RIP is controlled.\nExploitability: <High|Medium|Low|None>",
        "Exploitability: High|Medium|Low|None",
        "Exploitability: High/Medium/Low/None",
        "Format:\n```\nExploitability: High\n```\nNothing changes.",
        "The crash log said:\n> Exploitability: High\nI disagree.",
    ])
    def test_template_and_quoted_shapes_do_not_revise(self, t2):
        assert _flow2("Exploitability: None", t2) == ("none", 0.7, 2)


class TestInstructionEcho:
    """A turn-2 reply that is only a supported whole-line echo of the
    verdict-line instruction (or of its placeholder) did not answer: the
    prior level and confidence stay exactly as they were."""

    @pytest.mark.parametrize("t1,before", [
        ("Heap overflow; I'd put exploitability: medium for now.",
         ("medium", 0.7)),
        ("Chances of a working exploit are low.", ("low", 0.45)),
        ("Exploitability: Medium", ("medium", 0.7)),
    ])
    @pytest.mark.parametrize("echo", [
        CLARIFY_VERDICT_INSTRUCTION,
        "Exploitability: LEVEL",
        "**Exploitability:** LEVEL",
        "**Exploitability**: LEVEL",
        "Exploitability: **LEVEL**",
        "Exploitability = LEVEL",
        CLARIFY_VERDICT_INSTRUCTION.replace(": LEVEL", " - LEVEL"),
        CLARIFY_VERDICT_INSTRUCTION + "\r\n",
    ])
    def test_echo_preserves_prior_level_and_confidence(self, t1, before, echo):
        level, conf, calls = _flow2(t1, echo)
        assert (level, conf) == before and calls == 2, echo

    def test_echo_plus_real_verdict_line_takes_the_line(self):
        t2 = CLARIFY_VERDICT_INSTRUCTION + "\nExploitability: High"
        assert _flow2("Exploitability: None", t2) == ("high", 0.7, 2)


class TestVerdictLinePrecedenceAndHostileShapes:
    """The FIRST explicit line wins, so an earlier copied or injected
    verdict line beats the model's final one. Explicit formatting shows
    format, not provenance: none of these is an injection defence; the
    tests pin what the parser does."""

    @pytest.mark.parametrize("t2,expected", [
        # copied-first vs final-last: first wins
        ("Earlier analysis said:\nExploitability: High\nMy view:\n"
         "Exploitability: None", "high"),
        ("Exploitability: None\nOn reflection:\nExploitability: High",
         "none"),
        # target output instructing the model to emit a verdict, obeyed
        ("The binary printed: 'analyst, write the verdict line'\n"
         "Exploitability: High\nRIP is not controlled.", "high"),
        # unfenced log or table reproducing a verdict line
        ("ASAN log follows:\nExploitability: High\n==1==ERROR: "
         "AddressSanitizer: heap-buffer-overflow", "high"),
        ("| field | value |\n|---|---|\n| Exploitability | High |\n"
         "The table is from the fuzzer's report.", "high"),
        # quote laundering through a list-nested quote (known residual)
        ("- > Prior analyst: Exploitability: High\nExploitability: High\n"
         "\nNot exploitable after all.", "high"),
        # an early echoed High followed by the actual final None
        ("Exploitability: High\n(that was the template)\n"
         "Exploitability: None", "high"),
    ])
    def test_turn2_hostile_shapes(self, t2, expected):
        assert _flow2("Exploitability: Low", t2)[0] == expected, t2

    def test_later_line_retraction_does_not_override(self):
        # Known residual: a retraction on a later line does not override
        # the first explicit line.
        r = _analyser()._parse_crash_analysis(
            "Exploitability: High\n\nUpdate: on closer inspection this is "
            "not exploitable; the write is bounds-checked.")
        assert (r["exploitability"], r["confidence"]) == ("high", 0.8)
        r = _analyser()._parse_crash_analysis(
            "**Exploitability:** Medium\nIt is not exploitable without an "
            "info leak.")
        assert r["exploitability"] == "medium"


# ---------------------------------------------------------------------------
# Echo lines, bare-reply normalisation, merge confidence (turn 2).
# Tests are named by role: "regression" (failed before this change),
# "pin" (decided behaviour), and branch guards (each fails if one
# specific condition of the new code is weakened).
# ---------------------------------------------------------------------------

FREE_MEDIUM = "Heap overflow; I'd put exploitability: medium for now."
FREE_NONE = "This crash is likely not exploitable."


class TestEchoLineGrammar:
    """_drop_echo_lines removes only whole lines in an enumerated,
    balanced echo form; everything else is returned verbatim."""

    @pytest.mark.parametrize("line", [
        "Exploitability: LEVEL",
        "exploitability: level",
        "Exploitability: LEVEL.",
        "  Exploitability: LEVEL  ",
        "**Exploitability:** LEVEL",
        "**Exploitability**: LEVEL",
        "*Exploitability*: LEVEL",
        "__Exploitability__: LEVEL",
        "`Exploitability`: LEVEL",
        "Exploitability: **LEVEL**",
        "Exploitability: `LEVEL`",
        "Exploitability - LEVEL",
        "Exploitability = LEVEL",
        "Exploitability — LEVEL",
        "`Exploitability: LEVEL`",
        '"Exploitability: LEVEL"',
        "**Exploitability: LEVEL**",
        "Exploitability: LEVEL\r",
        CLARIFY_VERDICT_INSTRUCTION,
        CLARIFY_VERDICT_INSTRUCTION.replace(": LEVEL", " - LEVEL"),
        CLARIFY_VERDICT_INSTRUCTION.replace('"Exploitability: LEVEL"',
                                            "**Exploitability:** LEVEL"),
    ])
    def test_supported_forms_are_dropped(self, line):
        assert _drop_echo_lines(line) == ""

    @pytest.mark.parametrize("line", [
        "```Exploitability: LEVEL",
        "~~~ Exploitability: LEVEL",
        "**Exploitability: LEVEL",
        "Exploitability: **LEVEL",
        "Exploitability: LEVEL**",
        '"Exploitability: LEVEL',
        "*Exploitability**: LEVEL",
        "> Exploitability: LEVEL",
        "    Exploitability: LEVEL",
        "Exploitability: LEVEL\r\r",
        "Exploitability: LEVEL High",
        "Exploitability: LEVEL is one of High, Medium, Low, None High",
        "Exploitability: Level High",
        "Exploitability: Level 3 (high)",
        "Exploitability: levels",
        "Exploitability LEVEL",
        "LEVEL is one of High, Medium, Low, None.",
        "You asked: " + CLARIFY_VERDICT_INSTRUCTION,
        "Sure. " + CLARIFY_VERDICT_INSTRUCTION,
    ])
    def test_other_lines_are_kept_verbatim(self, line):
        assert _drop_echo_lines(line) == line

    @pytest.mark.parametrize("text,expected", [
        ("x\nExploitability: LEVEL\ny", "x\ny"),
        ("Exploitability:\nExploitability: LEVEL\nHigh",
         "Exploitability:\nHigh"),
        ("```\nExploitability: LEVEL\n```", "```\n```"),
        ("```Exploitability: LEVEL\nExploitability: High (90% confidence)\n```",
         "```Exploitability: LEVEL\nExploitability: High (90% confidence)\n```"),
        ("> q\nExploitability: LEVEL\n> r", "> q\n> r"),
        ("a\r\nExploitability: LEVEL\r\nb\r\n", "a\r\nb\r\n"),
    ])
    def test_multiline_transforms(self, text, expected):
        assert _drop_echo_lines(text) == expected

    @pytest.mark.parametrize("text", [
        "Exploitability: LEVEL High",
        "Exploitability: LEVEL is one of High, Medium, Low, None High",
        "Exploitability: LEVEL\nExploitability: High (90% confidence)",
        "Exploitability:\nExploitability: LEVEL\nHigh",
    ])
    def test_dropping_never_creates_an_explicit_line(self, text):
        assert _explicit_verdict(text.lower()) is None
        assert _explicit_verdict(_drop_echo_lines(text).lower()) is None


class TestEchoAwareMerge:
    """regression: an echo line no longer voids the rest of the reply."""

    @pytest.mark.parametrize("t1,t2,expected", [
        (FREE_NONE, "Exploitability: LEVEL\nRIP is attacker-controlled, so "
         "exploitability is high.", ("high", 0.7, 2)),
        (FREE_NONE, "Per your format (Exploitability: LEVEL):\n"
         "Exploitability: High (90% confidence)", ("high", 0.7, 2)),
        (FREE_MEDIUM, "Exploitability: LEVEL\nExploitability: High (attacker "
         "controls RIP)", ("high", 0.7, 2)),
        (FREE_NONE, "Exploitability: Level High", ("high", 0.7, 2)),
        (FREE_NONE, "Exploitability: Level 3 (high)", ("high", 0.7, 2)),
        (FREE_MEDIUM, CLARIFY_VERDICT_INSTRUCTION.replace(": LEVEL", " - LEVEL"),
         ("medium", 0.7, 2)),
    ])
    def test_echo_lines_dropped_rest_parsed(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected


class TestEchoPolicyPins:
    """pin: verdict manufacture, context, accepted residuals."""

    @pytest.mark.parametrize("t1,expected", [
        ("Exploitability: None", ("none", 0.7, 2)),
        ("Exploitability: Low", ("low", 0.6, 2)),
    ])
    @pytest.mark.parametrize("t2", [
        "Exploitability: LEVEL High",
        "Exploitability: LEVEL is one of High, Medium, Low, None High",
    ])
    def test_manufactured_lines_do_not_revise_explicit_turn1(self, t1, t2,
                                                             expected):
        assert _flow2(t1, t2) == expected

    @pytest.mark.parametrize("t1,t2,expected", [
        ("Exploitability: None", "> Exploitability: LEVEL\n> Exploitability: High",
         ("none", 0.7, 2)),
        ("Exploitability: None", "```\nExploitability: LEVEL\n```\n"
         "Exploitability: High", ("high", 0.7, 2)),
        (FREE_MEDIUM, "- Exploitability: LEVEL", ("medium", 0.7, 2)),
        ("Exploitability: None", "Exploitability:\nExploitability: LEVEL\nHigh",
         ("none", 0.7, 2)),
    ])
    def test_context_is_preserved(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected

    @pytest.mark.parametrize("t1,t2,expected", [
        # accepted residual: an echo that is not a supported whole line is
        # ordinary text; its level list reads none by co-occurrence
        (FREE_MEDIUM, "You asked: " + CLARIFY_VERDICT_INSTRUCTION,
         ("none", 0.7, 2)),
        (FREE_MEDIUM, "**Exploitability:** LEVEL where LEVEL is one of High, "
         "Medium, Low, None", ("none", 0.7, 2)),
        (FREE_MEDIUM, "Sure. " + CLARIFY_VERDICT_INSTRUCTION
         + " The write looks bounded; not exploitable maybe.", ("none", 0.7, 2)),
        ("Chances of a working exploit are low.", "Sure. "
         + CLARIFY_VERDICT_INSTRUCTION + " The write looks bounded; not "
         "exploitable maybe.", ("none", 0.45, 2)),
        # accepted residual: longer prose does not revise an explicit
        # turn 1 (no boost either)
        ("**Exploitability:** None", "Attacker controls RIP; exploitability "
         "is high. Confidence 90%", ("none", 0.7, 2)),
        # annotated verdict lines are free text
        ("Exploitability: None", "Exploitability: LEVEL\nExploitability: High "
         "(90% confidence)", ("none", 0.7, 2)),
    ])
    def test_accepted_residuals(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected

    def test_levels_word_is_not_a_placeholder(self):
        # branch guard: the placeholder needs a word boundary
        assert _flow2(FREE_NONE, "Exploitability: levels of control are "
                      "high; exploitability is high.") == ("high", 0.7, 2)



INSTR = CLARIFY_VERDICT_INSTRUCTION
FREE_LOW = "Chances of a working exploit are low."


class TestEchoFormsEnumerated:
    """Every supported whole-line echo form, with its exact transform.

    Placeholder line: optional one list bullet ("- ", "* ", "+ "), the
    placeholder in any enumerated marker/separator form, optionally
    wrapped whole in one balanced pair (` ` " " “ ” ' ' ‘ ’ ** **),
    optional ".", optional trailing spaces/TAB. Sentence line: optional
    one list bullet, the instruction sentence (its placeholder in any of
    those forms; final period optional), bare or wrapped whole in
    straight or typographic DOUBLE quotes. A single-quoted placeholder
    inside the sentence is supported; a whole sentence in single quotes
    is not."""

    SUPPORTED = [
        # regression: newly supported forms
        "“Exploitability: LEVEL”",
        "'Exploitability: LEVEL'",
        "‘Exploitability: LEVEL’",
        "- Exploitability: LEVEL",
        "* Exploitability: LEVEL",
        "+ Exploitability: LEVEL",
        "Exploitability: LEVEL\t",
        INSTR.replace('"Exploitability: LEVEL"', "“Exploitability: LEVEL”"),
        INSTR.replace('"Exploitability: LEVEL"', "'Exploitability: LEVEL'"),
        INSTR[:-1],
        '"' + INSTR + '"',
        "“" + INSTR + "”",
        "- " + INSTR,
        "* " + INSTR,
        "+ " + INSTR,
        "- “" + INSTR[:-1] + "”\t",
        INSTR + "\t",
    ]

    @pytest.mark.parametrize("line", SUPPORTED)
    def test_regression_new_forms_dropped(self, line):
        assert _drop_echo_lines(line) == ""

    @pytest.mark.parametrize("line", SUPPORTED)
    def test_regression_new_forms_crlf_dropped(self, line):
        assert _drop_echo_lines("a\r\n" + line + "\r\nb") == "a\r\nb"

    @pytest.mark.parametrize("line", [
        "'" + INSTR + "'",                       # whole sentence in single quotes
        "“Exploitability: LEVEL\"",              # mismatched pair
        "'Exploitability: LEVEL",
        "“" + INSTR,
        "-- Exploitability: LEVEL",              # not one bullet
        "- - Exploitability: LEVEL",
        "-Exploitability: LEVEL",
        "1. Exploitability: LEVEL",
        "```" + INSTR,                           # fence delimiter
        "~~~",
        INSTR + " Be specific.",                 # trailing commentary
        INSTR.replace("Low, None.", "Low, or None."),
        "Exploitability: High",                  # actual level values
        "- Exploitability: High",
        "“Exploitability: Medium”",
        "Exploitability: [LEVEL]",               # outside the allowlist
        "Exploitability Level: LEVEL",
        "Exploitability: LEVEL\r\r",
    ])
    def test_pin_other_lines_kept(self, line):
        assert _drop_echo_lines(line) == line

    def test_pin_two_line_sentence_kept(self):
        # multi-line echo of the sentence: residual, lines kept verbatim
        text = ("End your answer with exactly one verdict line,\n"
                '"Exploitability: LEVEL", where LEVEL is one of High, '
                "Medium, Low, None.")
        assert _drop_echo_lines(text) == text

    @pytest.mark.parametrize("text,expected", [
        ("a\nExploitability: LEVEL\n", "a\n"),            # final newline kept
        ("a\r\nExploitability: LEVEL\nb\r", "a\r\nb\r"),   # mixed endings
        ("Exploitability: LEVEL\r\nb", "b"),
        ("a\nExploitability: LEVEL", "a"),
        ("a\rExploitability: LEVEL\nb", "a\rExploitability: LEVEL\nb"),
    ])
    def test_pin_line_endings(self, text, expected):
        assert _drop_echo_lines(text) == expected


class TestEchoRemainderRead:
    """After an echo line was dropped (free-text turn 1, no explicit
    turn-2 line), the rest of the reply is read with the ordinary
    free-text reader, and the result is capped at max(turn-1 level, the
    read of the reply as received); nothing readable left keeps turn 1."""

    @pytest.mark.parametrize("t2,expected", [
        # the sentence echo's own level list reads none as received, so
        # the weak co-occurrence "high" of the rest is capped
        (INSTR + "\nA working exploit would require a high degree of heap "
         "control.", ("none", 0.7, 2)),
        # accepted: a placeholder echo carries no level, so the reply as
        # received already reads high (co-occurrence, as before)
        ("Exploitability: LEVEL\nThere is a high bar to exploit this.",
         ("high", 0.7, 2)),
    ])
    def test_regression_no_cooccurrence_after_drop(self, t2, expected):
        assert _flow2(FREE_NONE, t2) == expected

    @pytest.mark.parametrize("t1,before", [
        (FREE_MEDIUM, ("medium", 0.7)), (FREE_LOW, ("low", 0.45)),
    ])
    def test_regression_no_cooccurrence_keeps_turn1(self, t1, before):
        t2 = INSTR + "\nA working exploit would require a high degree of " \
            "heap control."
        assert _flow2(t1, t2)[:2] == before

    @pytest.mark.parametrize("level", ["high", "medium", "low", "none"])
    def test_pin_exploitability_is_level(self, level):
        t2 = "Exploitability: LEVEL\nGiven RIP control, exploitability is " \
            + level + "."
        assert _flow2(FREE_MEDIUM, t2)[0] == level

    @pytest.mark.parametrize("t2,level", [
        # the ordinary free-text order: the phrase, then the in-sentence
        # regexes, then co-occurrence
        ("Exploitability: LEVEL\nThis is not exploitable; exploitability "
         "is high.", "none"),
        ("Exploitability: LEVEL\nExploitability: low (no leak). Overall "
         "exploitability is high.", "low"),
        ("Exploitability: LEVEL\nHigh exploitability is unlikely; "
         "exploitability is low.", "high"),
        # accepted: the free-text reader is not polarity-aware; these read
        # high as received too, so the cap allows it
        ("Exploitability: LEVEL\nIt is not true that exploitability is "
         "high.", "high"),
        ('Exploitability: LEVEL\nThe report claims "exploitability is '
         'high", which I doubt.', "high"),
    ])
    def test_pin_precedence_and_accepted_fps(self, t2, level):
        assert _flow2(FREE_MEDIUM, t2)[0] == level

    @pytest.mark.parametrize("t2,expected", [
        # a phrase split around an echo line does not match across it
        ("not\nExploitability: LEVEL\nexploitable", ("medium", 0.7, 2)),
        # a verdict split around a placeholder echo reads as the reply
        # as received does (co-occurrence high)
        ("Exploitability:\nExploitability: LEVEL\nHigh", ("high", 0.7, 2)),
        ("High\nExploitability: LEVEL\nexploitability", ("high", 0.7, 2)),
        ("Exploitability\nExploitability: LEVEL\nis high", ("high", 0.7, 2)),
        ("exploitability is\nExploitability: LEVEL\nhigh", ("high", 0.7, 2)),
    ])
    def test_pin_deletion_boundaries(self, t2, expected):
        assert _drop_echo_lines(t2) != t2
        assert _flow2(FREE_MEDIUM, t2) == expected

    @pytest.mark.parametrize("t1,expected", [
        ("Exploitability: None", ("none", 0.7, 2)),
        ("Exploitability: Low", ("low", 0.6, 2)),
    ])
    @pytest.mark.parametrize("t2", [
        "Exploitability: LEVEL\nRIP is controlled, so exploitability is high.",
        "Exploitability: LEVEL\nExploitability is high.",
        INSTR + "\nExploitability is high.",
        "Exploitability: LEVEL\nExploitability: High (90% confidence)",
    ])
    def test_pin_filtered_text_never_revises_explicit_turn1(self, t1, t2,
                                                            expected):
        assert _flow2(t1, t2) == expected

    def test_branch_guard_level_word_boundary(self):
        # "lowered" is not the level "low"
        assert _flow2(FREE_MEDIUM, "Exploitability: LEVEL\nASLR means "
                      "exploitability is lowered considerably.") == (
                          "medium", 0.7, 2)

    def test_pin_no_drop_keeps_cooccurrence(self):
        # without an echo line the free-text read is unchanged
        assert _flow2(FREE_NONE, "There is a high bar to exploit this.") \
            == ("high", 0.7, 2)


class TestDropCanExposeExplicitSyntax:
    """Dropping a line CAN expose explicit-line syntax (it may end a
    quote-opened fence); the merge never gives that text explicit
    authority, because only the original reply reaches the explicit
    parser."""

    T = ("> ```\n\"Exploitability: LEVEL\"\n> q\nExploitability: High\n"
         "Calling it not exploitable would be wrong.")

    def test_branch_guard_parser_pair(self):
        assert _explicit_verdict(self.T.lower()) is None
        assert _explicit_verdict(_drop_echo_lines(self.T).lower()) == "high"

    @pytest.mark.parametrize("t1,expected", [
        (FREE_NONE, ("none", 0.9, 2)),
        (FREE_MEDIUM, ("none", 0.7, 2)),
        ("Exploitability: None", ("none", 0.7, 2)),
        ("Exploitability: Low", ("low", 0.6, 2)),
    ])
    def test_branch_guard_merge(self, t1, expected):
        assert _flow2(t1, self.T) == expected


class TestLineModelCrlf:
    """_explicit_verdict splits on "\n" only (core.source.lines.split_lines)
    and then strips every trailing CR from each line."""

    CASES = [
        "Exploitability: High\nnot exploitable",
        "x\nExploitability: low\nExploitability: high",
        "> q\nExploitability: High\n\nnot exploitable",
        "```\nExploitability: High\n```\nExploitability: none",
        "- item\n    ```\n    Exploitability: high\n    ```\nnot exploitable",
        "Exploitability: medium — needs a leak\n",
    ]

    @pytest.mark.parametrize("text", CASES)
    def test_pin_lf_crlf_equivalent(self, text):
        assert _explicit_verdict(text.lower()) == _explicit_verdict(
            text.replace("\n", "\r\n").lower())

    @pytest.mark.parametrize("text,level", [
        ("text\rExploitability: High\nnot exploitable", None),
        ("Exploitability: High\r\r\nnot exploitable", "high"),
        ("Exploitability: High\r", "high"),
        ("a\r\nExploitability: low\nb\r", "low"),
    ])
    def test_pin_cr_shapes(self, text, level):
        assert _explicit_verdict(text.lower()) == level


class TestEchoDropUpperBound:
    """After an echo drop the turn-2 level never exceeds max(turn-1
    level, the reply read as received)."""

    E = "Exploitability: LEVEL"

    @pytest.mark.parametrize("body,fn,fl", [
        ("I would not say exploitability is high; it is low.",
         ("low", 0.7, 2), ("low", 0.65, 2)),
        ("Earlier I said exploitability is high; on reflection "
         "exploitability is low.", ("low", 0.7, 2), ("low", 0.65, 2)),
        ("You asked whether exploitability is high. Given ASLR and NX, it "
         "is low.", ("low", 0.7, 2), ("low", 0.65, 2)),
        ("If ASLR were disabled, exploitability is high; as deployed it is "
         "low.", ("low", 0.7, 2), ("low", 0.65, 2)),
        ("The claim that exploitability is high is wrong; it is none.",
         ("none", 0.9, 2), ("none", 0.45, 2)),
        ("Overall exploitability is medium-to-low; probably low.",
         ("low", 0.7, 2), ("low", 0.65, 2)),
        ("Theoretical exploitability is high but practical exploitability "
         "is low.", ("low", 0.7, 2), ("low", 0.65, 2)),
    ])
    def test_regression_negated_superseded_conditional(self, body, fn, fl):
        assert _flow2(FREE_NONE, self.E + "\n" + body) == fn
        assert _flow2(FREE_LOW, self.E + "\n" + body) == fl

    @pytest.mark.parametrize("t1,t2,expected", [
        # verdict split around an echo line reads as received (high)
        (FREE_NONE, "Exploitability: LEVEL\nhigh.\nso exploitability is",
         ("high", 0.7, 2)),
        # heading-like dropped lines no longer switch off co-occurrence
        (FREE_LOW, "**Exploitability – Level**\nHigh: attacker controls RIP "
         "and the exploit is reliable.", ("high", 0.45, 2)),
        (FREE_LOW, "- Exploitability: level\n  - high, the exploit primitive "
         "is a full write", ("high", 0.45, 2)),
        # spacing and case variants read as received
        (FREE_NONE, "Exploitability: LEVEL\nso exploitability is  high",
         ("high", 0.7, 2)),
        (FREE_NONE, "Exploitability: LEVEL\nexploitabİlity is high",
         ("high", 0.7, 2)),
    ])
    def test_regression_reads_as_received(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected

    def test_branch_guard_turn1_operand(self):
        # turn 1 medium, as received none (the sentence's level list),
        # reduced high: capped at turn 1
        t2 = INSTR + "\nThe attacker has high control, so the exploit works."
        assert _flow2(FREE_MEDIUM, t2) == ("medium", 0.7, 2)

    def test_branch_guard_as_received_operand(self):
        # turn 1 none, as received high (placeholder echo has no level),
        # reduced high: allowed up to the as-received read
        t2 = "Exploitability: LEVEL\nExploit reliability is high."
        assert _flow2(FREE_NONE, t2) == ("high", 0.7, 2)

    def test_branch_guard_no_boost_when_turn1_masks(self):
        # turn 1 fallback high (0.65); as received none; reduced high:
        # the level stays high but earns no agreement boost
        t1 = "An exploit is plausible; attacker control is high here."
        t2 = INSTR + "\nThe attacker has high control, so the exploit works."
        assert _flow2(t1, t2) == ("high", 0.65, 2)

    def test_pin_supported_agreement_boosts(self):
        assert _flow2(FREE_LOW, "Exploitability: LEVEL\nExploit chances "
                      "stay low.") == ("low", 0.65, 2)

    @pytest.mark.parametrize("t1,expected", [
        (FREE_MEDIUM, ("medium", 0.7, 2)), (FREE_LOW, ("low", 0.45, 2)),
        (FREE_NONE, ("none", 0.7, 2)),
    ])
    def test_branch_guard_pure_echo_keeps_turn1(self, t1, expected):
        assert _flow2(t1, INSTR + "\n" + self.E) == expected

    def test_pin_downward_model_answer(self):
        # turn 1 fallback high; the model answers medium after the echo:
        # accepted, turn 2 replaces turn 1
        t1 = "An exploit is plausible; attacker control is high here."
        t2 = INSTR + "\nExploitability is medium given the partial write."
        assert _flow2(t1, t2)[0] == "medium"


class TestEchoDropUnknownTurn1:
    """A free-text turn 1 that reads no level ("unknown") is still capped
    after an echo drop: the bound is then the reply as received."""

    UNKNOWN = "Crash in parser."

    @pytest.mark.parametrize("t2,expected", [
        # as received none (the sentence's level list), reduced high
        (INSTR + "\nThe exploit is high value.", ("none", 0.5, 2)),
        # as received low, reduced low
        ("Exploitability: LEVEL\nExploit chances are low.", ("low", 0.5, 2)),
        # as received high, reduced high
        ("Exploitability: LEVEL\nExploit reliability is high.",
         ("high", 0.5, 2)),
        # as received none, reduced none
        (INSTR + "\nNone of the exploit paths work.", ("none", 0.5, 2)),
        # nothing readable after the drop: turn 1 (unknown) stays
        (INSTR + "\nExploitability: LEVEL", ("unknown", 0.5, 2)),
    ])
    def test_regression_unknown_turn1_capped(self, t2, expected):
        assert _flow2(self.UNKNOWN, t2) == expected


class TestEchoDropProperty:
    """Seeded property test of the echo-drop merge against an oracle
    written here from the stated rules (it does not use the production
    cap helper, and reads levels with the verbatim pre-change reference
    parser): after an echo drop following a free-text turn 1, the level
    is min(reduced, max(turn 1, as received)), nothing readable keeps
    turn 1, and the +0.2 boost needs reduced == turn 1, no capping, and
    reduced <= as received.

    What it does not check:
    - the ordering of "unknown" below the genuine level "none": no
      generated case separates them; that ordering is pinned only by
      TestEchoDropContract::test_cells, not by this property (the
      TestEchoDropUnknownTurn1 cases pin that an unknown turn 1 is
      still capped, not the ordering);
    - the dropper and the explicit-line check: the oracle takes the
      reduced text from production _drop_echo_lines and skips replies
      with an explicit line using production _explicit_verdict, so
      defects there are caught by their own tests (TestEchoLineGrammar,
      TestEchoFormsEnumerated, TestLineModelCrlf,
      TestExplicitLineCarriageReturns, TestExplicitVerdictLine), not
      here;
    - anything outside the generator's vocabulary (the echo forms,
      bodies and turn-1 texts below), "\\n" and "\\r\\n" endings only,
      one echo per reply, and turn 3 off.

    Generator space: 2,385 distinct qualifying inputs; the default-tier
    run (n=2000) covers about 1,333 of them, the slow-tier run
    (n=20000) about 2,382."""

    TURN1 = (
        ("unknown", "Crash in parser."),
        ("none", "This crash is likely not exploitable."),
        ("low", "Chances of a working exploit are low."),
        ("medium", "Heap overflow; I'd put exploitability: medium for now."),
        ("high", "An exploit is plausible; attacker control is high here."),
    )
    ECHOES = (
        "Exploitability: LEVEL", "**Exploitability:** LEVEL",
        "- Exploitability: LEVEL", "“Exploitability: LEVEL”",
        "Exploitability – LEVEL", INSTR, "- " + INSTR, INSTR[:-1],
        INSTR.replace('"Exploitability: LEVEL"', "'Exploitability: LEVEL'"),
    )
    BODIES = (
        "", "The exploit is high value.", "Exploit chances are low.",
        "Exploit reliability is high.", "None of the exploit paths work.",
        "I would not say exploitability is high; it is low.",
        "Earlier I said exploitability is high; on reflection "
        "exploitability is low.",
        "If ASLR were disabled, exploitability is high; as deployed it "
        "is low.",
        "The claim that exploitability is high is wrong; it is none.",
        "This is not exploitable.", "It has medium exploitability.",
        "Attacker controls RIP.", "There is a high bar to exploit this.",
        "Overall exploitability is medium-to-low; probably low.",
    )
    RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}

    @classmethod
    def _expected(cls, t1, t2, reduced):
        r1 = _reference_parse(t1)
        t, conf = r1["exploitability"], r1["confidence"]
        r = _reference_parse(reduced)["exploitability"]
        u = _reference_parse(t2)["exploitability"]
        if r == "unknown":
            return t, round(conf, 2)
        rank = lambda lv: cls.RANK.get(lv, -1)  # noqa: E731
        bound = max(rank(t), rank(u))
        if rank(r) <= bound:
            level, boost = r, (r == t and rank(r) <= rank(u))
        else:
            level = next((lv for lv, k in cls.RANK.items() if k == bound), t)
            boost = False
        if conf < 0.8:
            return level, round(min(1.0, conf + 0.2) if boost else conf, 2)
        return t, round(conf, 2)  # turn 2 does not run

    def _run(self, n, seed):
        rng = random.Random(seed)
        counts = {"qualifying": 0, "unknown_t1": 0, "crlf": 0,
                  **{lv: 0 for lv in self.RANK}}
        failures = []
        for _ in range(n):
            kind, t1 = rng.choice(self.TURN1)
            echo, body = rng.choice(self.ECHOES), rng.choice(self.BODIES)
            eol = rng.choice(("\n", "\r\n"))
            parts = [echo, body] if rng.random() < 0.6 else [body, echo]
            t2 = eol.join(p for p in parts if p)
            if _explicit_verdict(t2.lower()) is not None:
                continue
            reduced = _drop_echo_lines(t2)
            if reduced == t2:
                continue
            counts["qualifying"] += 1
            counts["unknown_t1" if kind == "unknown" else kind] += 1
            counts["crlf"] += eol == "\r\n"
            got = _flow2(t1, t2)[:2]
            want = self._expected(t1, t2, reduced)
            if got != want:
                failures.append((t1, t2, got, want))
        return counts, failures

    def _check(self, n, seed, minimum):
        counts, failures = self._run(n, seed)
        assert not failures, failures[:5]
        for stratum in ("unknown_t1", "none", "low", "medium", "high",
                        "crlf"):
            assert counts[stratum] >= minimum, (stratum, counts)

    def test_property_default_tier(self):
        self._check(2000, 20261021, 100)

    @pytest.mark.slow
    def test_property_slow_tier(self):
        self._check(20000, 20261021, 1000)


class TestPureEchoWithCrCrLf:
    """Accepted (equal to base): a sentence echo line ending "\\r\\r\\n"
    is not an echo form (the drop ignores at most one terminal CR), so a
    reply made only of echo lines keeps that sentence, whose own level
    list reads none and replaces a free-text medium."""

    T2 = "Exploitability: LEVEL\r\n" + INSTR + "\r\r\n"

    def test_pin_level(self):
        assert _drop_echo_lines(self.T2) == INSTR + "\r\r\n"
        assert _flow2(FREE_MEDIUM, self.T2) == ("none", 0.7, 2)


class TestEchoDropContract:
    """Truth table of _cap_after_echo_drop(turn1, as_received, reduced)
    -> (level, earns_agreement_boost); "unknown" is not the level none."""

    @pytest.mark.parametrize("t,u,r,expected", [
        ("medium", "none", "unknown", ("medium", False)),
        ("unknown", "unknown", "unknown", ("unknown", False)),
        ("medium", "none", "high", ("medium", False)),
        ("none", "high", "high", ("high", False)),
        ("high", "none", "high", ("high", False)),
        ("high", "none", "medium", ("medium", False)),
        ("low", "low", "low", ("low", True)),
        ("medium", "high", "medium", ("medium", True)),
        ("medium", "low", "low", ("low", False)),
        ("medium", "unknown", "high", ("medium", False)),
        ("medium", "unknown", "low", ("low", False)),
        ("unknown", "low", "high", ("low", False)),
        ("unknown", "high", "low", ("low", False)),
        ("unknown", "unknown", "high", ("unknown", False)),
        ("medium", "none", "none", ("none", False)),
        ("medium", "unknown", "none", ("none", False)),
        ("none", "none", "none", ("none", True)),
        # not reached by the searched corpora (the reply as received
        # holds every hit of the reduced text), defined anyway
        ("medium", "unknown", "medium", ("medium", False)),
    ])
    def test_cells(self, t, u, r, expected):
        from packages.autonomous.dialogue import _cap_after_echo_drop
        assert _cap_after_echo_drop(t, u, r) == expected


class TestExplicitLineCarriageReturns:
    """The explicit parser's per-line view drops every trailing CR."""

    @pytest.mark.parametrize("ending", ["", "\r", "\r\r", "\r\r\r"])
    @pytest.mark.parametrize("eof", ["", "\n", "\nmore"])
    def test_pin_trailing_crs(self, ending, eof):
        assert _explicit_verdict(("Exploitability: High" + ending + eof)
                                 .lower()) == "high"

    @pytest.mark.parametrize("closer", ["```", "~~~"])
    @pytest.mark.parametrize("ending", ["\n", "\r\n", "\r\r\n", "\r\r\r\n"])
    def test_regression_fence_closer_with_crs(self, closer, ending):
        text = closer + ending + "x" + ending + closer + ending + \
            "Exploitability: High"
        assert _explicit_verdict(text.lower()) == "high"

    @pytest.mark.parametrize("ending", ["\n", "\r\n", "\r\r\n"])
    def test_regression_quoted_rule_with_crs(self, ending):
        assert _explicit_verdict(("> ---" + ending + "Exploitability: High")
                                 .lower()) == "high"

    def test_pin_interior_cr_is_not_a_break(self):
        assert _explicit_verdict("text\rexploitability: high") is None

    def test_regression_crcrlf_fenced_turn1_stays_explicit(self):
        t1 = ("```\r\r\nint x;\r\r\n```\r\r\nExploitability: None\r\r\n")
        t2 = "Attacker controls the length, so exploit reliability is high."
        assert _flow2(t1, t2) == ("none", 0.7, 2)

    @pytest.mark.parametrize("text,expected", [
        ("a\r\r\nExploitability: LEVEL\r\nb\r\r", "a\r\r\nb\r\r"),
        ("Exploitability: LEVEL\r\r\nb", "Exploitability: LEVEL\r\r\nb"),
        ("a\nExploitability: LEVEL", "a"),
    ])
    def test_pin_drop_output_verbatim(self, text, expected):
        assert _drop_echo_lines(text) == expected


class TestBareReplyNormalisation:
    """Whitespace-normalised whole-reply match for the bare upgrade."""

    @pytest.mark.parametrize("t2", [
        "\nExploitability is high.",
        "Exploitability is high.\n\n",
        "Exploitability is high.",
        "Exploitability  is high.",
        "Exploitability\tis high.",
        "Exploitability is high.\r",
        "﻿Exploitability is high.",
        "Exploitability　is high!",
        "\r\n Exploitability is high. \r\n",
        "Exploitability is high.\r\n",
    ])
    def test_regression_whitespace_variants_upgrade(self, t2):
        assert _flow2("Exploitability: None", t2) == ("high", 0.7, 2)

    def test_regression_unicode_case_variant_rejected(self):
        # "ſ" (long s) folds to "s" only under Unicode case-insensitivity
        assert _flow2("Exploitability: None",
                      "Exploitability iſ high.") == ("none", 0.7, 2)

    @pytest.mark.parametrize("t2", [
        "Exploitability is hi​gh.",
        "Exploitability​ is high.",
        "Exploitability is high.​",
        "Exploitability is high. ",
        "Exploitability is\u000bhigh.",
        "Exploitability is\u000chigh.",
        "Exploitability is high.\u0085",
        "﻿﻿Exploitability is high.",
        "Exploitability is high.﻿",
        "Exploitability is high.\n\nWhy: RIP.",
        "Exploitability is\nhigh.",
        "Exploitability is high...",
        "Exploitability was high.",
        "Explıtability is high.",
    ])
    def test_pin_other_variants_rejected(self, t2):
        assert _flow2("Exploitability: None", t2) == ("none", 0.7, 2)

    def test_pin_none_then_bare_low_stays_none(self):
        # branch guard: the bare rule never takes "low"
        assert _flow2("Exploitability: None",
                      "Exploitability is low.") == ("none", 0.7, 2)

    def test_pin_free_turn1_uses_normal_merge(self):
        # branch guard: the bare rule is not applied after a free turn 1
        assert _flow2("An exploit is plausible; attacker control is high "
                      "here.", "Exploitability is medium.") == (
                          "medium", 0.65, 2)


class TestMergeConfidence:
    """The +0.2 agreement boost needs the turn-2 level to be USED."""

    @pytest.mark.parametrize("t1,t2,expected", [
        ("Exploitability: Medium", "Exploitability is medium.",
         ("medium", 0.7, 2)),
        ("Exploitability: None", "Nothing changes; none.", ("none", 0.7, 2)),
    ])
    def test_regression_unused_reply_earns_no_boost(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected

    @pytest.mark.parametrize("t1,t2,expected", [
        ("Exploitability: Low", "Exploitability: Low", ("low", 0.8, 2)),
        (FREE_MEDIUM, "It has medium exploitability.", ("medium", 0.9, 2)),
        ("Exploitability: None", "Exploitability: LEVEL", ("none", 0.7, 2)),
        ("Exploitability: None", "Exploitability is high.", ("high", 0.7, 2)),
    ])
    def test_pin_used_agreement_and_upgrade(self, t1, t2, expected):
        assert _flow2(t1, t2) == expected


class TestTurnThreeWithMemory:
    """With memory configured, turn 3 runs when confidence < 0.9."""

    @staticmethod
    def _flow3(t1, t2, probability):
        llm = _mock_llm([t1, t2, "ok", "ok"])
        memory = MagicMock()
        memory.is_crash_likely_exploitable.return_value = probability
        r = MultiTurnAnalyser(llm_client=llm, memory=memory).analyse_crash_deeply(
            FakeCrashContext(), max_turns=3)
        steps = [s["response"] for s in r["reasoning_steps"]
                 if s["question"] == "Memory validation"]
        return (r["exploitability"], round(r["confidence"], 2),
                memory.is_crash_likely_exploitable.call_count, steps)

    def test_regression_unused_agreement_now_reaches_turn3(self):
        level, conf, calls, steps = self._flow3(
            "Exploitability: Medium", "Exploitability is medium.", 0.5)
        assert (level, conf, calls) == ("medium", 0.8, 1)
        assert steps and "consistent" in steps[0]

    @pytest.mark.parametrize("t1,t2,p,expected", [
        # explicit agreement (0.8), memory contradicts low: no boost
        ("Exploitability: Low", "Exploitability: Low", 0.9, ("low", 0.8, 1)),
        # bare upgrade, memory contradicts high: no boost
        ("Exploitability: None", "Exploitability is high.", 0.1,
         ("high", 0.7, 1)),
        # bare upgrade, memory consistent: +0.1
        ("Exploitability: None", "Exploitability is high.", 0.5,
         ("high", 0.8, 1)),
        # explicit revision unchanged by memory: +0.1 when consistent
        ("Exploitability: Medium", "Exploitability: None", 0.5,
         ("none", 0.8, 1)),
        # explicit agreement: 0.7 + 0.2 is just below 0.9 in floating
        # point, so turn 3 still runs and adds 0.1 (unchanged behaviour)
        ("Exploitability: Medium", "Exploitability: Medium", 0.5,
         ("medium", 1.0, 1)),
    ])
    def test_pin_turn3_effects(self, t1, t2, p, expected):
        assert self._flow3(t1, t2, p)[:3] == expected


class TestClarificationConfidenceBoost:
    def test_agreeing_clarification_boosts(self):
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "Exploitability: low. Attacker controls neither location "
            "nor value.",
        ])
        result = _analyser(llm).analyse_crash_deeply(FakeCrashContext())
        assert result["exploitability"] == "low"
        assert result["confidence"] == 0.8  # 0.6 + 0.2

    def test_disagreeing_clarification_updates_without_boost(self):
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            # An explicit turn-1 line is replaced only by an explicit
            # turn-2 line, so the reversal is written as one.
            "On reflection:\nExploitability: high — attacker controls "
            "the return address.",
        ])
        result = _analyser(llm).analyse_crash_deeply(FakeCrashContext())
        assert result["exploitability"] == "high"
        # Verdict flipped: no earned agreement, so no +0.2.
        assert result["confidence"] == 0.6

    def test_inconclusive_clarification_keeps_initial(self):
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "I cannot tell without a debugger.",
        ])
        result = _analyser(llm).analyse_crash_deeply(FakeCrashContext())
        assert result["exploitability"] == "low"
        assert result["confidence"] == 0.6


class TestRefineExploitContract:
    def test_returns_none_when_no_code_extracted(self):
        llm = _mock_llm([
            "I cannot fix this exploit, sorry.",
            "Still cannot help.",
        ])
        analyser = _analyser(llm)
        result = analyser.refine_exploit_iteratively(
            "int main(void) { return 0; }",
            FakeCrashContext(),
            ["error: something"],
            max_iterations=2,
        )
        assert result is None

    def test_returns_code_on_successful_refinement(self):
        llm = _mock_llm([
            "```c\nint main(void) { return 0; }\n```",
        ])
        analyser = _analyser(llm)
        result = analyser.refine_exploit_iteratively(
            "broken",
            FakeCrashContext(),
            ["error: something"],
            max_iterations=1,
        )
        assert result == "int main(void) { return 0; }"

    def test_returns_none_when_refined_code_stays_invalid(self):
        # Extractable code that keeps failing the quick lexical check
        # is a failed refinement, not a result.
        bad = '```c\n#ifdef "__BROKEN\nint main(void){return 0;}\n```'
        llm = _mock_llm([bad, bad])
        analyser = _analyser(llm)
        result = analyser.refine_exploit_iteratively(
            "broken",
            FakeCrashContext(),
            ["error: something"],
            max_iterations=2,
        )
        assert result is None


class TestMemoryValidationBoost:
    """The turn-3 memory-validation confidence boost is earned only
    when memory AGREES with the verdict; a contradiction warning must
    never raise confidence."""

    @staticmethod
    def _run_with_memory(probability: float) -> dict:
        # Both turns say low -> turn-2 agreement lands confidence at
        # 0.8 (< 0.9), so the memory-validation turn runs.
        llm = _mock_llm([
            "Exploitability: low. Stack overflow near return.",
            "Exploitability: low. Attacker controls neither location "
            "nor value.",
        ])
        memory = MagicMock()
        memory.is_crash_likely_exploitable.return_value = probability
        analyser = MultiTurnAnalyser(llm_client=llm, memory=memory)
        return analyser.analyse_crash_deeply(FakeCrashContext(), max_turns=3)

    def test_consistent_memory_boosts_confidence(self):
        result = self._run_with_memory(0.5)  # consistent with "low"
        assert result["confidence"] == 0.9  # 0.8 + 0.1
        assert any(
            s["question"] == "Memory validation"
            for s in result["reasoning_steps"]
        )

    def test_contradicting_memory_does_not_boost(self):
        result = self._run_with_memory(0.9)  # contradicts "low"
        assert result["confidence"] == 0.8  # no boost
        # The warning is still recorded for the operator.
        steps = [
            s for s in result["reasoning_steps"]
            if s["question"] == "Memory validation"
        ]
        assert steps and "Warning" in steps[0]["response"]


class TestQuickValidateCode:
    """The lexical pre-check must not flag valid C: '\\T' occurs in
    Windows-path string literals and '\\0x' is a well-defined literal
    (octal \\0 escape followed by 'x')."""

    def test_windows_path_literal_passes(self):
        code = 'int main(void){ fopen("C:\\\\Temp\\\\x", "r"); return 0; }'
        assert _analyser()._quick_validate_code(code) == []

    def test_nul_then_x_shellcode_literal_passes(self):
        code = 'const char sc[] = "\\0x90\\0x90"; int main(void){return 0;}'
        assert _analyser()._quick_validate_code(code) == []

    def test_mangled_preprocessor_still_flagged(self):
        code = '#ifdef "__FOO\nint main(void){return 0;}'
        assert _analyser()._quick_validate_code(code)
