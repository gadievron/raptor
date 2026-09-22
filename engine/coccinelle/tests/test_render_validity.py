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

import logging
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


def _vocab_buckets(text: str) -> list[str]:
    """Bucket names of every ``@vocab`` marker, in file order."""
    return [
        m.group(1)
        for m in (
            vocab_renderer._MARKER_RE.match(line.rstrip())
            for line in text.splitlines()
        )
        if m
    ]


def _render_capturing_warnings(
    rule: Path, vocab: object,
) -> tuple[Path | None, list[str]]:
    """Render ``rule`` and capture the renderer's warning channel.

    Returns ``(rendered_path_or_None, warning_messages)``. The
    renderer deliberately degrades on an unknown ``@vocab`` bucket
    (warn, splice nothing) so a sweep never goes dark at run time —
    which makes the warning channel the ONLY witness that a rule
    carries a dead splice slot. The oracle tests below promote those
    warnings to failures.
    """
    captured: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(record)

    log = logging.getLogger(vocab_renderer.__name__)
    handler = _Capture(level=logging.WARNING)
    old_level = log.level
    log.addHandler(handler)
    log.setLevel(logging.WARNING)
    try:
        rendered = vocab_renderer.render(rule, vocab)
    finally:
        log.removeHandler(handler)
        log.setLevel(old_level)
    return rendered, [r.getMessage() for r in captured]


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
def test_no_unknown_vocab_buckets(rule):
    """Every ``@vocab`` bucket a stock rule names must be mapped.

    At run time an unknown bucket only warns and splices nothing, so
    the marked slot is silently dead on every vocabulary-bearing
    audit. Here that warning is a failure, and a rule whose buckets
    are ALL unmapped fails with the rule and bucket names rather than
    tripping the incidental rendered-no-change assertion.
    """
    text = rule.read_text(encoding="utf-8")
    buckets = _vocab_buckets(text)
    unmapped = sorted(
        {b for b in buckets if b not in vocab_renderer._BUCKET_MAP}
    )
    rendered, warnings = _render_capturing_warnings(
        rule, _RepresentativeVocab(),
    )
    if rendered is not None:
        rendered.unlink()
    unknown = [w for w in warnings if "unknown @vocab bucket" in w]
    scope = (
        "EVERY @vocab marker in the rule is a dead splice slot"
        if unmapped and set(unmapped) == set(buckets)
        else "those splice slots are silently dead"
    )
    assert not unmapped and not unknown, (
        f"{rule.name} names @vocab bucket(s) with no "
        f"vocab_renderer._BUCKET_MAP entry: {', '.join(unmapped)} — "
        f"{scope} on every vocabulary-bearing audit; renderer "
        f"warnings: {unknown}"
    )


def test_unknown_bucket_detection_self_check(tmp_path):
    # The gate above proves the universe clean only if the warning
    # capture actually works — flag a synthetic unknown bucket here so
    # a broken capture channel cannot green the universe silently.
    rule = tmp_path / "synthetic.cocci"
    rule.write_text(
        "// @vocab: not_a_real_bucket\n"
        r"\(kfree\|kvfree\)(E);" + "\n",
        encoding="utf-8",
    )
    assert _vocab_buckets(rule.read_text(encoding="utf-8")) == [
        "not_a_real_bucket",
    ]
    rendered, warnings = _render_capturing_warnings(
        rule, _RepresentativeVocab(),
    )
    assert rendered is None
    unknown = [w for w in warnings if "unknown @vocab bucket" in w]
    assert unknown and "not_a_real_bucket" in unknown[0]


@pytest.mark.parametrize(
    "rule", _VOCAB_RULES, ids=lambda p: p.stem,
)
def test_rendered_rule_parses(rule):
    rendered = render(rule, _RepresentativeVocab())
    assert rendered is not None, (
        f"{rule.name} carries // @vocab: markers "
        f"({', '.join(_vocab_buckets(rule.read_text(encoding='utf-8')))}) "
        f"but rendered no change with a non-empty vocabulary in every "
        f"mapped bucket"
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
