"""Shape-detection: which angr primitive (if any) would apply to a target.

Called BEFORE spending ~5-30s on a full symex run — a cheap
gate that tells the router / LLM "yes, PC-control shape, fire the
overflow primitive" vs "no, this is a heap UAF, don't bother".

Cost: single-digit milliseconds when a source file is available
(source-pattern grep only). Sub-second when only a binary is
available (loads via cache, scans for marker-target symbols; no CFG
walk yet — that's a planned enhancement for pure-binary detection).

Returns a :class:`ShapeDetection` structured result. Consumers
branch on the boolean flags AND on ``suggested_primitives`` (a
list of primitive names to try in order of expected value).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Source-pattern regexes for overflow detection. Naive "any read(0, ...)"
# gives false positives on heap targets whose menu reads are size-bounded
# (a bounded ``read(0, scratch, 16)`` on ``scratch[32]`` —
# safe). Match specifically read(fd, buf, N) with the size arg so we can
# compare N against the buffer's declared size.
_READ_SIZED_RE = re.compile(
    r"\bread\s*\(\s*(?:0|stdin_fd|\w+)\s*,\s*"
    r"(?P<buf>&?\w+(?:\.\w+)?(?:\[\w+\])?)\s*,\s*"
    r"(?P<size>\d+|sizeof\s*[^,)]+)"
)
# gets() is always unbounded; strcpy() into a fixed buffer likewise —
# treat these as unconditionally unsafe when present.
_UNSAFE_CALL_RE = re.compile(
    r"\b(?:gets\s*\(|strcpy\s*\(|scanf\s*\(\s*\"%s)"
)
_CHAR_BUF_RE = re.compile(
    r"\bchar\s+(?P<var>\w+)\s*\[\s*(?P<size>\d+)\s*\]"
)
_FORMAT_STRING_SINK_RE = re.compile(
    r"\b(?:printf|snprintf|fprintf|sprintf|vprintf)\s*\("
)
# User-controlled fmt: a printf-family call whose FORMAT argument
# (position from core.function_taxonomy.FORMAT_STRING_FMT_ARG_INDEX —
# the first arg is the format only for printf/vprintf; fprintf's is
# second, snprintf's third) is a variable rather than a string
# literal. Positional matching kills the "fprintf(stderr, \"...\")
# flags as user-controlled" false-positive class.
_FMT_CALL_RE = re.compile(r"\b([a-z_]\w*)\s*\(")


def _split_call_args(src: str, open_paren: int) -> list[str]:
    """Top-level comma split of a call's argument text. Tracks paren
    depth and double-quoted strings; good enough for detector-grade
    source scanning (not a C parser)."""
    depth, in_str, arg, args = 0, False, [], []
    i = open_paren + 1
    while i < len(src):
        c = src[i]
        if in_str:
            arg.append(c)
            if c == "\\":
                i += 2
                arg.append(src[i - 1] if i - 1 < len(src) else "")
                continue
            if c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            arg.append(c)
        elif c == "(":
            depth += 1
            arg.append(c)
        elif c == ")":
            if depth == 0:
                args.append("".join(arg).strip())
                return args
            depth -= 1
            arg.append(c)
        elif c == "," and depth == 0:
            args.append("".join(arg).strip())
            arg = []
        else:
            arg.append(c)
        i += 1
    return args


def _find_user_controlled_fmt(src: str) -> str | None:
    """First printf-family call whose format-position argument is a
    plain identifier (not a string literal); None when all format
    arguments are literals."""
    from core.function_taxonomy import FORMAT_STRING_FMT_ARG_INDEX
    for m in _FMT_CALL_RE.finditer(src):
        fn = m.group(1)
        pos = FORMAT_STRING_FMT_ARG_INDEX.get(fn)
        if pos is None:
            continue
        args = _split_call_args(src, m.end() - 1)
        if len(args) < pos:
            continue
        fmt_arg = args[pos - 1]
        if fmt_arg.startswith('"'):
            continue
        if re.fullmatch(r"[a-zA-Z_]\w*", fmt_arg):
            return f"{fn}({', '.join(args[:pos])}...)"[:60]
    return None
_C_LINE_COMMENT_RE = re.compile(r"//[^\n]*")
_C_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", flags=re.DOTALL)

# Symbol names the corpus uses for "attacker's goal" functions.
# Kept broad so the detector doesn't miss variants; the router's
# subsequent symex fire will either produce a working input or
# fail cleanly.
_WIN_SYMBOL_NAMES: frozenset[str] = frozenset({
    "win", "winfunc", "flag", "give_flag", "print_flag",
    "admin", "backdoor", "shell", "system_wrapper",
})


@dataclass(frozen=True)
class ShapeDetection:
    """Which symex primitive(s) would apply to a target.

    ``suggested_primitives`` is ordered by expected value — a
    consumer that wants to try ONE primitive should take the head.
    A consumer that wants to fall through the list should iterate.
    """

    pc_control_shape: bool
    """True when we detected an unbounded read + a marker-target symbol.
    Firing ``find_overflow_reaching_input`` is warranted."""

    fmtstr_shape: bool
    """True when a printf-family call reads its format string from
    a non-literal argument. Placeholder for the not-yet-built
    ``find_format_string_positions`` primitive."""

    intsize_shape: bool
    """True when integer arithmetic appears near allocation or
    loop bounds. Placeholder for the not-yet-built
    ``find_intsize_trigger_input`` primitive."""

    suggested_primitives: tuple[str, ...]
    """Names of the primitives that would apply, in try-order.
    Populated only for shapes whose primitive exists today; a shape
    detected without a matching primitive is surfaced via the
    boolean but not in this list."""

    evidence: dict = field(default_factory=dict)
    """Free-form: which line the source pattern matched, which
    symbol names were found, etc. Useful for the LLM to explain
    itself when firing (or NOT firing) a primitive.

    UNTRUSTED CONTENT: symbol names and source excerpts come from
    the target. Envelope before prompt use."""


def detect_shape(
    binary_path: Path,
    *,
    source_path: Optional[Path] = None,
) -> ShapeDetection:
    """Detect which angr primitive would apply.

    Args:
        binary_path: ELF to inspect. Loaded via the substrate's
            Project cache — sub-millisecond on cache-hit,
            50-200ms cold.
        source_path: optional C source path. When provided, enables
            richer detection (unbounded-read + user-fmt patterns).
            When None, detection falls back to symbol-scan only.

    Returns:
        :class:`ShapeDetection` populated with boolean shape flags
        + ``suggested_primitives`` (only listing primitives that
        exist today — pc_control_shape → ``find_overflow_reaching_input``
        currently). Future primitives (fmtstr, intsize) will extend
        this list as they land.
    """
    from core.symbolic._project import load_binary

    binary_path = Path(binary_path)
    evidence: dict = {}
    win_symbols: list[str] = []
    pc_control_shape = False
    fmtstr_shape = False
    intsize_shape = False

    # Binary-side scan: which marker-target symbols exist?
    if binary_path.is_file():
        try:
            info = load_binary(binary_path)
        except (FileNotFoundError, ValueError):
            info = None
        if info is not None:
            win_symbols = [
                name for name in info.symbols
                if name.lower() in _WIN_SYMBOL_NAMES
            ]
            if win_symbols:
                evidence["win_symbols"] = win_symbols
                evidence["is_pie"] = info.is_pie

    # Source-side scan: real overflow (read size > buf size, or gets /
    # strcpy / scanf-%s) combined with a marker-target symbol → pc_control_shape.
    # User-controlled format string → fmtstr_shape.
    if source_path is not None and source_path.is_file():
        try:
            raw = source_path.read_text(errors="replace")
        except OSError:
            raw = ""
        if raw:
            src = _strip_c_comments(raw)
            char_bufs = {
                m.group("var"): int(m.group("size"))
                for m in _CHAR_BUF_RE.finditer(src)
            }
            has_real_overflow = _has_real_overflow(src, char_bufs)
            user_fmt = _find_user_controlled_fmt(src)
            has_fmt_sink = _FORMAT_STRING_SINK_RE.search(src)
            if has_real_overflow and char_bufs:
                evidence["overflow_evidence"] = has_real_overflow
                evidence["char_bufs"] = [
                    {"var": v, "size": s} for v, s in list(char_bufs.items())[:5]
                ]
                if win_symbols:
                    pc_control_shape = True
            if user_fmt and has_fmt_sink:
                evidence["user_controlled_fmt"] = user_fmt
                fmtstr_shape = True

    # Suggested primitives — only include those that actually exist
    # today. Future primitives (find_format_string_positions,
    # find_intsize_trigger_input) will extend this list as they land.
    suggested: list[str] = []
    if pc_control_shape:
        suggested.append("core.symbolic.find_overflow_reaching_input")

    return ShapeDetection(
        pc_control_shape=pc_control_shape,
        fmtstr_shape=fmtstr_shape,
        intsize_shape=intsize_shape,
        suggested_primitives=tuple(suggested),
        evidence=evidence,
    )


def _strip_c_comments(src: str) -> str:
    src = _C_BLOCK_COMMENT_RE.sub(" ", src)
    src = _C_LINE_COMMENT_RE.sub(" ", src)
    return src


def _has_real_overflow(
    src: str, char_bufs: dict[str, int],
) -> Optional[str]:
    """Return a descriptive string when the source shows a REAL
    overflow (read size > buf size, or gets/strcpy/scanf-%s).

    ``read(0, buf, 512)`` on ``char buf[64]`` → real overflow.
    ``read(0, buf, 16)`` on ``char buf[32]`` → NOT overflow.
    ``read(0, buf, sizeof buf - 1)`` → NOT overflow (bounded).

    Returns None when no overflow is detectable.
    """
    unsafe = _UNSAFE_CALL_RE.search(src)
    if unsafe:
        return f"unbounded call: {unsafe.group(0)}"

    for m in _READ_SIZED_RE.finditer(src):
        buf = m.group("buf").lstrip("&").split(".")[0].split("[")[0]
        size = m.group("size").strip()
        # Ignore reads bounded by sizeof — always safe.
        if "sizeof" in size:
            continue
        try:
            n = int(size)
        except ValueError:
            continue
        buf_size = char_bufs.get(buf)
        if buf_size is not None and n > buf_size:
            return f"read({buf}, {n}) > sizeof({buf})={buf_size}"
    return None
