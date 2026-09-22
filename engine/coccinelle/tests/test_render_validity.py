"""Render-validity oracle for the stock rule library.

Two mechanically-derived closure gates (the universe is globbed from
``rules/*.cocci``, never a hand-typed list):

1. **Seed parse** — every stock rule must be accepted by
   ``spatch --parse-cocci``. Parametric rules get a ``-D`` define for
   every ``virtual.<name>`` reference they carry.
2. **Rendered parse** — every ``// @vocab:``-marked rule, rendered
   with a representative non-empty vocabulary for EVERY mapped bucket,
   must still be accepted by ``spatch --parse-cocci``.

Gate 2 exists because an unparseable render is a silent total outage:
core/audit/sweep.py renders whenever the audit learned any vocabulary,
so a bad ``@vocab-tmpl`` turns the ENTIRE rule (seed lanes included)
into outcome="error" on precisely the runs the vocabulary machinery
is supposed to strengthen — and nothing else executes rendered forms
for most rules (missing_null_check shipped unparseable templates for
this exact reason).

Note the parse gate is necessary, not sufficient: an indented ``*``
context line parses clean but never matches. Match-level behaviour is
pinned per-rule in the fixture tests (see test_missing_null_check_rule
TestVocabRendered) and structurally in test_vocab_renderer.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from engine.coccinelle import vocab_renderer
from engine.coccinelle.vocab_renderer import render

_RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
_ALL_RULES = sorted(_RULES_DIR.glob("*.cocci"))
_VOCAB_RULES = [
    p for p in _ALL_RULES if "// @vocab:" in p.read_text(encoding="utf-8")
]

# ``identifier virtual.lock`` style references AND standalone
# ``virtual lock`` declarations both demand a -D define to parse.
# The declaration branch keeps its whitespace class newline-free
# ([^\S\n]) so consecutive ``virtual`` lines never fuse into one
# garbage define under MULTILINE.
_VIRTUAL_REF_RE = re.compile(
    r"\bvirtual\.(\w+)|^virtual[^\S\n]+([\w,]+(?:[^\S\n]+[\w,]+)*)[^\S\n]*$",
    re.MULTILINE,
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _virtual_defines(text: str) -> list[str]:
    names: set[str] = set()
    for m in _VIRTUAL_REF_RE.finditer(text):
        if m.group(1):
            names.add(m.group(1))
        else:
            names.update(n.strip() for n in m.group(2).split(",") if n.strip())
    args = []
    for n in sorted(names):
        args += ["-D", f"{n}=parse_probe_{n}"]
    return args


def _parse_cocci(rule: Path) -> subprocess.CompletedProcess:
    defines = _virtual_defines(rule.read_text(encoding="utf-8"))
    return subprocess.run(  # noqa: S603 — fixed local binary, repo input
        ["spatch", "--parse-cocci", *defines, str(rule)],
        capture_output=True, text=True, timeout=60,
    )


def _template_disjunctions(text: str) -> list[tuple[int, str, list[str]]]:
    """``(line_no, template, seed_entry_lines)`` for every
    ``@vocab-tmpl`` marker followed by a multi-line disjunction block.

    Reuses the renderer's own marker regex so this scanner and the
    renderer never disagree about what constitutes a template.
    """
    lines = text.splitlines()
    blocks: list[tuple[int, str, list[str]]] = []
    for i, line in enumerate(lines):
        m = vocab_renderer._TMPL_RE.match(line.rstrip())
        if not m or i + 1 >= len(lines) or lines[i + 1].strip() != "(":
            continue
        entries: list[str] = []
        for j in range(i + 2, len(lines)):
            stripped = lines[j].strip()
            if stripped == ")":
                break
            if stripped in ("", "|") or stripped.startswith("//"):
                continue
            entries.append(stripped)
        blocks.append((i + 1, m.group(1).rstrip(), entries))
    return blocks


class _RepresentativeVocab:
    """One valid identifier in every bucket the renderer maps.

    Derived from ``vocab_renderer._BUCKET_MAP`` so a newly mapped
    bucket is automatically exercised here without editing this file.
    """

    def __init__(self) -> None:
        for attr in set(vocab_renderer._BUCKET_MAP.values()):
            setattr(self, attr, frozenset({f"probe_{attr}"}))


def test_universe_is_nonempty():
    # Guards the globs themselves — a moved rules dir must not turn
    # both parametrized gates into vacuous zero-case passes.
    assert len(_ALL_RULES) >= 60
    assert len(_VOCAB_RULES) >= 5
    # The terminator gate below must see at least one statement-position
    # template block, or it degrades to a vacuous pass.
    blocks = [
        b
        for rule in _VOCAB_RULES
        for b in _template_disjunctions(rule.read_text(encoding="utf-8"))
    ]
    assert any(
        entries and all(e.endswith(";") for e in entries)
        for _, _, entries in blocks
    )


@pytest.mark.parametrize(
    "rule", _VOCAB_RULES, ids=lambda p: p.stem,
)
def test_template_terminator_matches_block_position(rule):
    """A template must keep its disjunction block's position class.

    The parse gate cannot catch this: a statement-position template
    that drops its trailing ``;`` still parses — spatch reads the
    spliced entry as an EXPRESSION disjunct, which additionally
    matches assignments in subexpression position (``if ((a =
    xnew(n)) == b)``, for-init clauses) that the statement-form seed
    entries do not. The learned lane then silently diverges from the
    seed lanes' match semantics, so the terminator class of every
    template is pinned to the class of the seed entries it extends.
    """
    text = rule.read_text(encoding="utf-8")
    for line_no, tmpl, entries in _template_disjunctions(text):
        assert entries, (
            f"{rule.name}:{line_no}: @vocab-tmpl block has no seed "
            f"entries to derive the template's position class from"
        )
        term_classes = {e.endswith(";") for e in entries}
        assert len(term_classes) == 1, (
            f"{rule.name}:{line_no}: disjunction mixes statement- and "
            f"expression-position seed entries — spliced entries "
            f"cannot match both classes"
        )
        if term_classes == {True}:
            assert tmpl.endswith(";"), (
                f"{rule.name}:{line_no}: statement-position template "
                f"{tmpl!r} lacks the trailing ';' its seed entries "
                f"carry — the rendered entry parses as an expression "
                f"disjunct and diverges from the seed lanes' match "
                f"semantics"
            )
        else:
            assert not tmpl.endswith(";"), (
                f"{rule.name}:{line_no}: expression-position template "
                f"{tmpl!r} carries a ';' its seed entries do not"
            )


@pytest.mark.parametrize(
    "rule", _ALL_RULES, ids=lambda p: p.stem,
)
def test_seed_rule_parses(rule):
    proc = _parse_cocci(rule)
    assert proc.returncode == 0, (
        f"{rule.name} failed spatch --parse-cocci:\n"
        f"{proc.stderr[-2000:]}"
    )


@pytest.mark.parametrize(
    "rule", _VOCAB_RULES, ids=lambda p: p.stem,
)
def test_rendered_rule_parses(rule):
    rendered = render(rule, _RepresentativeVocab())
    assert rendered is not None, (
        f"{rule.name} carries // @vocab: markers but rendered no "
        f"change with a non-empty vocabulary in every bucket"
    )
    try:
        proc = _parse_cocci(rendered)
        assert proc.returncode == 0, (
            f"vocab-rendered {rule.name} failed spatch --parse-cocci "
            f"— the rule is DARK on every vocabulary-bearing audit:\n"
            f"{proc.stderr[-2000:]}"
        )
    finally:
        rendered.unlink()
