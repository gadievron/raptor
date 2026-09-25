r"""Census gate: line-model sites stay CRLF-tolerant or adjudicated.

On a CRLF checkout of a TARGET repo, byte-decoded text carries a
trailing ``\r`` on every line.  Two construction families silently
degrade detection on such content:

* ``text.split("\n")`` — every element keeps its ``\r``, so
  exact-string guards and end-anchored per-line matches false-miss;
* ``re.MULTILINE`` patterns whose ``$`` is preceded by a token that
  cannot match ``\r`` — ``foo$`` never matches ``foo\r``.

The fail direction is degraded detection (findings missed, never
minted), so each site is adjudicated rather than blanket-rewritten:
the remedy per site is ``core.source.lines.split_lines`` (and the
site vanishes from arm S), a ``\r?``-tolerant ``$`` (and the site
vanishes from arm M), or an inline justification marker::

    lines = text.split("\n")  # line-model: <why this model is right>

The marker currency is shared with the splitlines census
(``test_splitlines_line_model_census``): the justification lives next
to the pairing it excuses and moves with it — deliberately no
allowlist file.  For arm S the marker sits on the call's first line;
for arm M anywhere within the ``re.*`` call's source span (compiled
patterns routinely span lines).

Named boundaries (not flagged, no marker needed):

* arm S skips receivers that mention ``stdout``/``stderr`` — host
  tool-stream iteration is single-model, matching the splitlines
  census's tool-output boundary;
* arm S sees TEXT splits only — ``bytes.split(b"\n")`` and the
  ``rsplit``/``partition`` family are deliberately out of scope: the
  byte-splitting sites are the byte-model-deliberate families the
  DO-NOT doctrine protects (hashes, keepends, scanner pairings), and
  widening to them would push this gate into policing the very
  models it must not touch;
* arm M analyses LITERAL pattern text only; a ``$`` inside an
  f-string interpolation or a variable pattern is invisible (blind
  spot, reviewers backstop), as is a pattern loaded from a data file.
  The MULTILINE signal is either the ``re.MULTILINE``/``re.M`` flag
  argument or an inline ``(?m)``/``(?im)``/``(?m:`` spelling in the
  literal pattern (a scoped group counts whole-pattern —
  conservative);
* arm M treats a ``$`` right after a group opening, an alternation
  pipe, or a walked-back run of optional tokens ending at one as
  tolerant (conservative — ``(?::|\s|$)`` shapes);
* ``^$`` (empty-line match) walks back past the zero-width ``^`` to
  pattern start and is treated tolerant — a known blind spot.

The DO-NOT families of the line-model doctrine are out of scope by
construction: this gate never inspects read modes (``newline=""``
scanner pairings), hashes, or keepends rewriters — it only sees the
two syntactic shapes above, and byte-model-deliberate sites among
them carry markers saying so.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from runtime_universe import repo_root, runtime_file_universe  # noqa: E402

_MARKER = "line-model:"
# Must carry an actual justification — a bare marker is a rubber
# stamp, not an adjudication record (same rule as the sibling census).
_MARKER_RE = re.compile(r"#[ \t]*" + re.escape(_MARKER) + r"[ \t]*\S")

_GUIDANCE_SPLIT = (
    'text.split("\\n") keeps a trailing \\r per element on CRLF '
    "content, so exact-match guards and end-anchored per-line "
    "matches false-miss. Route through core.source.lines.split_lines "
    f"or justify inline with '# {_MARKER} <why>' on the call's first "
    "line:\n"
)
_GUIDANCE_MULT = (
    "re.MULTILINE pattern with a \\r-intolerant $ false-misses on "
    "CRLF content. Use \\r?$ (or a tolerant preceding token), or "
    f"justify with '# {_MARKER} <why>' within the call's span:\n"
)

_STREAM_NAMES = frozenset({"stdout", "stderr"})


# ---------------------------------------------------------------------------
# Arm S — .split("\n")
# ---------------------------------------------------------------------------


def _is_stream_receiver(expr: ast.AST) -> bool:
    for sub in ast.walk(expr):
        if isinstance(sub, ast.Attribute) and sub.attr in _STREAM_NAMES:
            return True
        if isinstance(sub, ast.Name) and sub.id in _STREAM_NAMES:
            return True
    return False


def _split_nl_calls(tree: ast.AST) -> list[ast.Call]:
    out = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "split"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "\n"
        ):
            continue
        if _is_stream_receiver(node.func.value):
            continue
        out.append(node)
    return out


# ---------------------------------------------------------------------------
# Arm M — re.MULTILINE with an intolerant $
# ---------------------------------------------------------------------------

_RE_FUNCS = frozenset({
    "compile", "search", "match", "fullmatch", "sub", "subn",
    "findall", "finditer", "split",
})
_RE_MODULE_NAMES = frozenset({"re", "_re"})
#: Sentinel standing in for a non-constant pattern fragment
#: (f-string interpolation, concatenated name) — unknowable, so the
#: walk-back treats it as tolerant.
_UNKNOWN = "\x00"

_GROUP_OPEN_RE = re.compile(
    r"\((?:\?(?:[aiLmsux]*:|P<[^>]*>|P=\w+|<?[=!]|<\w+>))?",
)

#: Inline MULTILINE flag inside the pattern itself — ``(?m)``,
#: ``(?im)``, or a scoped ``(?m:``/``(?m-i:`` group.  A scoped group
#: is treated as whole-pattern MULTILINE (conservative: flagging is
#: cheap, the marker/`\r?$` adjudication resolves it).
_INLINE_M_RE = re.compile(r"\(\?[aiLsux]*m[aiLmsux]*(?:-[aiLmsux]+)?[):]")


@dataclass
class _Tok:
    kind: str  # lit | esc | cls | dot | open | close | alt | caret | dollar | unknown
    text: str
    quant: str = ""  # "", "*", "+", "?", or "{m,n}"
    open_idx: int = -1  # for close tokens: index of the matching open


def _tokenize(pat: str) -> list[_Tok]:
    toks: list[_Tok] = []
    stack: list[int] = []
    i = 0
    n = len(pat)
    while i < n:
        c = pat[i]
        if c == "\\":
            toks.append(_Tok("esc", pat[i:i + 2]))
            i += 2
            continue
        if c == "[":
            j = i + 1
            if j < n and pat[j] == "^":
                j += 1
            if j < n and pat[j] == "]":
                j += 1
            while j < n and pat[j] != "]":
                if pat[j] == "\\":
                    j += 1
                j += 1
            toks.append(_Tok("cls", pat[i:j + 1]))
            i = j + 1
            continue
        if c == "(":
            m = _GROUP_OPEN_RE.match(pat, i)
            text = m.group(0) if m else "("
            stack.append(len(toks))
            toks.append(_Tok("open", text))
            i += len(text)
            continue
        if c == ")":
            open_idx = stack.pop() if stack else -1
            toks.append(_Tok("close", ")", open_idx=open_idx))
            i += 1
            continue
        if c in "*+?" and toks and toks[-1].kind not in ("open", "alt"):
            if not toks[-1].quant:
                toks[-1].quant = c
            i += 1
            continue
        if c == "{":
            j = pat.find("}", i)
            body = pat[i + 1:j] if j != -1 else ""
            if j != -1 and re.fullmatch(r"\d*(?:,\d*)?", body) and toks:
                if not toks[-1].quant:
                    toks[-1].quant = pat[i:j + 1]
                i = j + 1
                continue
            toks.append(_Tok("lit", c))
            i += 1
            continue
        kind = {
            ".": "dot", "|": "alt", "^": "caret", "$": "dollar",
            _UNKNOWN: "unknown",
        }.get(c, "lit")
        toks.append(_Tok(kind, c))
        i += 1
    return toks


def _min_zero(quant: str) -> bool:
    if quant in ("*", "?"):
        return True
    return quant.startswith("{") and quant[1:].split(",", 1)[0] in ("", "0")


_CR_CLASS_HINT_RE = re.compile(r"\\[srWD]|\r")


def _can_match_cr(tok: _Tok, pat_toks: list[_Tok]) -> bool:
    if tok.kind in ("dot", "unknown"):
        return True
    if tok.kind == "esc":
        return tok.text in (r"\s", r"\W", r"\D", r"\r")
    if tok.kind == "cls":
        body = tok.text[1:-1]
        negated = body.startswith("^")
        if negated:
            # [^...] matches \r unless the set includes it (via \r or
            # the whole \s class); [^\S...] deliberately DOES match \r.
            rest = body[1:].replace(r"\S", "")
            return not _CR_CLASS_HINT_RE.search(rest)
        return bool(_CR_CLASS_HINT_RE.search(body))
    if tok.kind == "close":
        # Coarse group verdict: any \r-capable hint inside the span.
        lo = tok.open_idx if tok.open_idx >= 0 else 0
        idx = pat_toks.index(tok)
        return any(
            t.kind in ("dot", "unknown")
            or (t.kind == "esc" and t.text in (r"\s", r"\W", r"\D", r"\r"))
            or (t.kind == "cls" and _can_match_cr(t, pat_toks))
            for t in pat_toks[lo + 1:idx]
        )
    return False


def _dollar_is_tolerant(toks: list[_Tok], di: int) -> bool:
    k = di - 1
    while k >= 0:
        t = toks[k]
        if t.kind in ("open", "alt"):
            return True  # conservative: position after an absorber arm
        if t.kind == "caret":
            k -= 1  # zero-width; keep walking
            continue
        if _can_match_cr(t, toks):
            return True
        if _min_zero(t.quant):
            if t.kind == "close" and t.open_idx >= 0:
                k = t.open_idx - 1  # skip the whole optional group
            else:
                k -= 1
            continue
        return False
    return True  # walked to pattern start


def pattern_intolerant_dollar(pat: str) -> bool:
    """True when *pat* has an unescaped ``$`` that a trailing ``\\r``
    would defeat under ``re.MULTILINE``."""
    toks = _tokenize(pat)
    return any(
        t.kind == "dollar" and not _dollar_is_tolerant(toks, i)
        for i, t in enumerate(toks)
    )


def _literal_pattern(node: ast.AST) -> str | None:
    """Best-effort literal text of a pattern expression.

    Non-constant fragments become the _UNKNOWN sentinel; a pattern
    with no constant fragment at all returns None (invisible)."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            else:
                parts.append(_UNKNOWN)
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal_pattern(node.left)
        right = _literal_pattern(node.right)
        if left is None and right is None:
            return None
        return (left or _UNKNOWN) + (right or _UNKNOWN)
    return None


def _has_multiline_flag(call: ast.Call) -> bool:
    for expr in list(call.args[1:]) + [kw.value for kw in call.keywords]:
        for sub in ast.walk(expr):
            if (
                isinstance(sub, ast.Attribute)
                and sub.attr in ("MULTILINE", "M")
                and isinstance(sub.value, ast.Name)
                and sub.value.id in _RE_MODULE_NAMES
            ):
                return True
    return False


def _multiline_re_calls(tree: ast.AST) -> list[tuple[ast.Call, str]]:
    out = []
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _RE_FUNCS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in _RE_MODULE_NAMES
            and node.args
        ):
            continue
        pat = _literal_pattern(node.args[0])
        if pat is None:
            continue
        if not _has_multiline_flag(node) and not _INLINE_M_RE.search(pat):
            continue
        out.append((node, pat))
    return out


# ---------------------------------------------------------------------------
# The census
# ---------------------------------------------------------------------------


def census_offenders(rel: str, source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    lines = source.split("\n")

    def marked(lineno: int) -> bool:
        return bool(_MARKER_RE.search(lines[lineno - 1]))

    offenders = []
    for call in _split_nl_calls(tree):
        if not marked(call.lineno):
            offenders.append(
                (call.lineno, f'{rel}:{call.lineno}: .split("\\n") '
                 "without a line-model adjudication"),
            )
    for call, pat in _multiline_re_calls(tree):
        if not pattern_intolerant_dollar(pat):
            continue
        end = call.end_lineno or call.lineno
        if not any(marked(ln) for ln in range(call.lineno, end + 1)):
            offenders.append(
                (call.lineno, f"{rel}:{call.lineno}: re.MULTILINE "
                 "pattern with a \\r-intolerant $"),
            )
    return [msg for _, msg in sorted(set(offenders))]


def test_no_unadjudicated_crlf_line_model_sites() -> None:
    repo = repo_root()
    offenders: list[str] = []
    for path in runtime_file_universe(repo, include_dev_scripts=True):
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Cheap prefilter only — ".M" also catches the bare re.M
        # flag spelling, at worst costing a parse.
        if "split" not in source and ".M" not in source:
            continue
        rel = path.relative_to(repo).as_posix()
        offenders.extend(census_offenders(rel, source))
    assert not offenders, (
        _GUIDANCE_SPLIT + _GUIDANCE_MULT + "\n".join(offenders)
    )


class TestArmSMechanics:
    def test_bare_split_flagged(self):
        assert census_offenders("x.py", 'lines = text.split("\\n")\n')

    def test_marker_with_justification_passes(self):
        src = ('lines = text.split("\\n")  '
               "# line-model: universal-newline read upstream\n")
        assert census_offenders("x.py", src) == []

    def test_bare_marker_is_a_rubber_stamp(self):
        src = 'lines = text.split("\\n")  # line-model:\n'
        assert census_offenders("x.py", src)

    def test_split_lines_adoption_passes(self):
        src = ("from core.source.lines import split_lines\n"
               "lines = split_lines(text)\n")
        assert census_offenders("x.py", src) == []

    def test_stdout_receiver_boundary_not_flagged(self):
        src = ('for ln in proc.stdout.strip().split("\\n"):\n'
               "    handle(ln)\n"
               'errs = (result.stderr or "").split("\\n")\n')
        assert census_offenders("x.py", src) == []

    def test_other_separator_not_flagged(self):
        assert census_offenders("x.py", 'parts = text.split(",")\n') == []

    def test_maxsplit_form_flagged(self):
        assert census_offenders("x.py", 'head = text.split("\\n", 1)\n')

    def test_unparseable_source_skipped(self):
        assert census_offenders("x.py", "def broken(:\n") == []


class TestArmMMechanics:
    @staticmethod
    def _mult(pat: str) -> str:
        return f"import re\nx = re.compile(r'{pat}', re.MULTILINE)\n"

    def test_bare_dollar_flagged(self):
        assert census_offenders("x.py", self._mult(r"^foo$"))

    def test_cr_optional_dollar_passes(self):
        assert census_offenders("x.py", self._mult(r"^foo\r?$")) == []

    def test_whitespace_absorber_passes(self):
        assert census_offenders("x.py", self._mult(r"^foo\s*$")) == []

    def test_dot_absorber_passes(self):
        assert census_offenders("x.py", self._mult(r"//.*$")) == []

    def test_negated_class_absorber_passes(self):
        assert census_offenders("x.py", self._mult(r"-r\s+([^\n]+)$")) == []

    def test_nonspace_capture_dollar_flagged(self):
        assert census_offenders("x.py", self._mult(r"^(\S+)$"))

    def test_word_class_dollar_flagged(self):
        assert census_offenders("x.py", self._mult(r"=\s*(\w+)$"))

    def test_optional_group_walkback_passes(self):
        # (?:;\s*)?$ — the optional group can end in \r via \s*.
        assert census_offenders(
            "x.py", self._mult(r"^\s*return\s+0\s*(?:;\s*)?$"),
        ) == []

    def test_optional_noncr_group_walks_past(self):
        # (;)?$ can't absorb \r, but the \s* before it can.
        assert census_offenders("x.py", self._mult(r"foo\s*(;)?$")) == []

    def test_optional_noncr_group_then_lit_flagged(self):
        assert census_offenders("x.py", self._mult(r"foo(;)?$"))

    def test_alternation_arm_dollar_passes(self):
        assert census_offenders(
            "x.py", self._mult(r"when\s+(\S.*?)(?::|\s|$)"),
        ) == []

    def test_escaped_dollar_passes(self):
        assert census_offenders("x.py", self._mult(r"cost\$\d+")) == []

    def test_dollar_in_class_passes(self):
        assert census_offenders("x.py", self._mult(r"[$]\w+")) == []

    def test_no_multiline_flag_ignored(self):
        src = "import re\nx = re.compile(r'^foo$')\n"
        assert census_offenders("x.py", src) == []

    def test_multiline_alias_module_flagged(self):
        src = ("import re as _re\n"
               "x = _re.compile(r'^foo$', _re.MULTILINE)\n")
        assert census_offenders("x.py", src)

    def test_marker_within_call_span_passes(self):
        src = ("import re\n"
               "x = re.compile(\n"
               "    r'^foo$',\n"
               "    re.MULTILINE,  # line-model: LF-only artifact\n"
               ")\n")
        assert census_offenders("x.py", src) == []

    def test_fstring_unknown_tail_passes(self):
        # A $ right after an interpolated fragment is unknowable.
        src = ("import re\n"
               "x = re.compile(rf'^{name}$', re.MULTILINE)\n")
        assert census_offenders("x.py", src) == []

    def test_concatenated_literal_flagged(self):
        src = ("import re\n"
               "x = re.compile(r'^foo' + r'bar$', re.MULTILINE)\n")
        assert census_offenders("x.py", src)

    def test_combined_flags_detected(self):
        src = ("import re\n"
               "x = re.compile(r'^a$', re.IGNORECASE | re.MULTILINE)\n")
        assert census_offenders("x.py", src)

    def test_flags_keyword_detected(self):
        src = ("import re\n"
               "x = re.sub(r'a$', '', text, flags=re.MULTILINE)\n")
        assert census_offenders("x.py", src)

    def test_inline_m_flag_detected(self):
        src = "import re\nx = re.compile(r'(?m)^foo$')\n"
        assert census_offenders("x.py", src)

    def test_inline_combined_flags_detected(self):
        src = "import re\nx = re.compile(r'(?im)^foo$')\n"
        assert census_offenders("x.py", src)

    def test_inline_scoped_m_group_detected(self):
        src = "import re\nx = re.search(r'(?m:^foo$)', text)\n"
        assert census_offenders("x.py", src)

    def test_inline_i_only_not_multiline(self):
        src = "import re\nx = re.compile(r'(?i)^foo$')\n"
        assert census_offenders("x.py", src) == []

    def test_inline_m_tolerant_dollar_passes(self):
        src = "import re\nx = re.compile(r'(?m)^foo\\s*$')\n"
        assert census_offenders("x.py", src) == []

    def test_named_group_not_mistaken_for_flags(self):
        src = "import re\nx = re.compile(r'(?P<m>x)y$')\n"
        assert census_offenders("x.py", src) == []
