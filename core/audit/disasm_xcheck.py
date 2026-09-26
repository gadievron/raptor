"""disasm_xcheck — verdict-time disassembly cross-check for binary items.

Target class: decompilation artifacts that mint false verdicts. A
decompiler can silently drop a call argument, misrender register
liveness, or narrow an operand — and a review grounded in that
pseudo-C then asserts a mechanism ("no count argument is passed",
"r8d is never set before the call", "only 4 bytes are validated")
that the machine code contradicts. When a binary item's
suspicious/finding-tier hypothesis cites such an ARGUMENT / REGISTER /
IMMEDIATE-WIDTH claim, this channel extracts a bounded instruction
window around the relevant call site(s) from the analysed binary and
runs mechanical predicates against the decoded instructions.

Outcomes (tool output is the verdict):

* ``refuted`` — the instructions contradict the decompilation-derived
  claim at EVERY examined call site, with REFUTE-GRADE evidence only
  (see the grade rules below). Consumed by the refutation-gate seam
  (:mod:`core.audit.refutation`), which demotes with the disassembly
  excerpt as receipt.
* ``corroborated`` — the instructions are consistent with the claim.
  The verdict STANDS unchanged; a receipt is attached. Never a
  promotion, never new evidence-tool stamps.
* ``inconclusive`` — window unresolvable, architecture unsupported,
  binding ambiguous, writes present but below refute grade, or
  predicates do not decide. No verdict change; the honest record is
  journaled.
* ``skipped`` — did not look (per-run invocation cap, objdump
  absent). Distinct from inconclusive in tier telemetry.

REFUTE-GRADE EVIDENCE (strictly stronger than corroboration-blocking):
a write only refutes a "register/argument missing" claim when

1. the destination is a 32/64-bit register (32-bit writes zero-extend
   on x86-64; an 8/16-bit alias write leaves the upper bits stale and
   therefore NEVER refutes — it still blocks corroboration), and
2. the write is unconditional (``cmov*``/``set*`` are excluded from
   refute grade — conditional materialization proves nothing about
   the not-taken path — but still block corroboration), and
3. the write provably reaches the call within the decoded window:
   either BRANCH-FREE-CONNECTED (no control-transfer instruction
   between write and call AND no in-window branch target strictly
   between them — a jump landing between the two means the call is
   reachable without the write) or ENTRY-DOMINATING (the write sits
   in the function's straight-line entry region, before the first
   control-transfer instruction of a window that starts at the
   function entry: no in-window path can reach any later instruction
   without passing it). Control flow entering the window from OUTSIDE
   (non-local jumps into mid-function) is invisible to a
   window-bounded decoder; the refuter grade stays ``heuristic``
   partly for this reason.

ADDRESS SPACES: checklist / re-database addresses live in the RE
tool's image space (Ghidra rebases PIE ELFs to its default image
base), while objdump decodes ELF vaddrs. Every resolved address —
window start, callee targets, sibling xref sites — is corrected by
the LOAD BIAS: the re-database's minimum segment start (when the
database is available) or the Ghidra default-image-base convention
(a ``FUN_``/``SUB_``-named item whose embedded address equals the
item address, on an ET_DYN ELF) against the ELF's minimum PT_LOAD
vaddr. Without a computable bias the raw address stands (bias 0), and
an implausible corrected window resolves to an honest inconclusive —
never a silently wrong decode.

Prior-art boundary (do not twin): :mod:`core.audit.binary_check_vectors`
and :mod:`core.audit.block_sibling_analysis` extract properties from
PERSISTED artifacts for sibling property-vectors — no disassembler
runs there. THIS module is the different thing those files' docstrings
reserve: a verdict-time pass that MAY run the disassembler, sandboxed
exactly like the binary-oracle's binutils invocations
(``core.sandbox.run``, network blocked, list argv, safe env). It
extends the shared vocabulary rather than duplicating it: evidence
tiers come from the one canonical :class:`core.evidence.EvidenceTier`
enum (``decoded_instruction``), and check identifiers follow the
``<channel>:<class>`` rule-id convention.

Honesty: every predicate here is SYNTACTIC over a bounded decoded
window. Refutation requires refute-grade contradiction at EVERY
examined call site; corroboration requires a complete (untruncated)
window and is blocked by ANY write to the family, however weak. The
trigger taxonomy is a bounded keyword+structure match on the claim
text — never free LLM classification.
"""

from __future__ import annotations

import logging
import re
import struct
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.evidence import EvidenceTier
from core.security.log_sanitisation import escape_nonprintable

from .run_memo import BoundedMemo

logger = logging.getLogger(__name__)

# Rule-id namespace (one per trigger class, the channel:class rule).
RULE_DROPPED_ARGUMENT = "disasm_xcheck:dropped-argument"
RULE_REGISTER_LIVENESS = "disasm_xcheck:register-liveness"
RULE_IMMEDIATE_WIDTH = "disasm_xcheck:immediate-width"
RULE_SIBLING_ARGUMENT = "disasm_xcheck:sibling-argument"

TRIGGER_DROPPED_ARGUMENT = "dropped_argument"
TRIGGER_REGISTER_LIVENESS = "register_liveness"
TRIGGER_IMMEDIATE_WIDTH = "immediate_width"
TRIGGER_SIBLING_ARGUMENT = "sibling_argument"

_RULE_BY_TRIGGER = {
    TRIGGER_DROPPED_ARGUMENT: RULE_DROPPED_ARGUMENT,
    TRIGGER_REGISTER_LIVENESS: RULE_REGISTER_LIVENESS,
    TRIGGER_IMMEDIATE_WIDTH: RULE_IMMEDIATE_WIDTH,
    TRIGGER_SIBLING_ARGUMENT: RULE_SIBLING_ARGUMENT,
}

# Enumerated non-verdict reasons (each a distinct tested string).
REASON_BINARY_UNRESOLVED = "binary-unresolved"
REASON_ADDRESS_UNRESOLVED = "address-unresolved"
REASON_ARCH_UNSUPPORTED = "arch-unsupported"
REASON_WINDOW_EMPTY = "window-empty"
REASON_NO_CALL_SITE = "no-call-site"
REASON_CALLSITE_UNRESOLVED = "callsite-unresolved"
REASON_MIXED_CALL_SITES = "mixed-call-sites"
REASON_WINDOW_INCOMPLETE = "window-incomplete"
REASON_TOOL_UNAVAILABLE = "objdump-unavailable"
REASON_INVOCATION_CAP = "invocation-cap"
REASON_DISASM_FAILED = "disasm-failed"
REASON_NO_COMPARE = "no-compare-in-window"
REASON_WIDER_COMPARE = "wider-compare-present"
REASON_WRITE_NOT_REFUTE_GRADE = "write-present-not-refute-grade"
REASON_SIBLING_SUBSTRATE = "sibling-substrate-unavailable"
REASON_SIBLING_SAMPLE_TRUNCATED = "sibling-sample-truncated"
REASON_GUESSED_BIAS = "bias-convention-unverified"

# ── bounds ──────────────────────────────────────────────────────────
# Every limit is two-directional by design; see the regression tests.

#: Claim text scanned for triggers. Longer reads more of a genuinely
#: verbose hypothesis but hands LLM/hostile-decomp-shaped prose a
#: bigger regex budget; shorter can miss a register named late.
MAX_HYPOTHESIS_CHARS = 4_000

#: Instruction-window span disassembled per item. Larger covers huge
#: functions but hands a forged st_size a bigger objdump/parse
#: budget; smaller truncates real functions (truncation blocks
#: corroboration, so over-small silently degrades the channel).
MAX_WINDOW_BYTES = 65_536

#: Window when the item carries no size at all — enough for the call
#: sites of a typical function without betting on a forged span.
DEFAULT_WINDOW_BYTES = 2_048

#: objdump output lines parsed per window. Above this the window is
#: marked truncated: refutation and corroboration are both refused
#: on a partial decode (an unseen region can hide either answer).
MAX_OUTPUT_LINES = 20_000

#: Pre-call lookback per call site, in instructions. Longer finds
#: writes hoisted far above the call but weakens the "at the call
#: site" claim binding; shorter misses legitimately scheduled writes.
#: A lookback that ends at the cap (not at function start or the
#: previous call) cannot corroborate.
LOOKBACK_INSTRUCTIONS = 32

#: Call sites examined per window. A flooded decoy function must not
#: turn one item into hundreds of predicate walks; truncation blocks
#: refutation and corroboration alike (→ inconclusive, and the
#: receipt notes the partial site set).
MAX_CALL_SITES = 16

#: Sibling call sites decoded for the sibling-differential lane. The
#: differential is only refute-sound over the FULL attributable
#: population (a sampled subset can be flooded with low-address decoy
#: callers that displace the real siblings), so a population above
#: this cap BLOCKS refutation the way call-site truncation does.
#: Larger covers hot callees' real caller populations at subprocess
#: cost (still bounded by the per-run spawn budget); smaller turns
#: more real targets into truncation-blocked inconclusives.
MAX_SIBLING_SITES = 24

#: Minimum clean sibling profiles for a differential verdict — one
#: sibling is an anecdote, not a majority premise.
MIN_SIBLING_SITES = 2

#: Receipt excerpt ceiling (escaped characters). Bounded with an
#: explicit elision marker — target-derived bytes render per the
#: ``core.security.log_sanitisation`` contract.
MAX_EXCERPT_CHARS = 2_000

#: Per-invocation objdump wall ceiling (seconds).
PER_ITEM_TIMEOUT_S = 20

#: Disassembler spawns per run (cache misses only). A run whose
#: binary items all trigger must stay bounded in subprocess cost;
#: raising it buys coverage on huge engagements at wall-clock cost.
#: Sibling-differential windows draw from the same budget.
PER_RUN_INVOCATION_CAP = 48

#: Ghidra's default image base for relocatable (ET_DYN) ELF imports —
#: the per-source_tool address-space convention used when no segment
#: table is available to measure the load bias directly.
GHIDRA_DEFAULT_IMAGE_BASE = 0x100000

#: Refute-grade writes must fill at least this many destination bytes
#: (32-bit writes zero-extend the full 64-bit register on x86-64;
#: 8/16-bit alias writes leave stale upper bits and never refute).
STRONG_WRITE_MIN_BYTES = 4

# ── x86-64 register vocabulary ──────────────────────────────────────
# Hypothesis-side spellings deliberately EXCLUDE the bare legacy
# 8/16-bit names (``ax``, ``si``, ``cl``, ...) — in prose they collide
# with English fragments and would bind the wrong family — and the
# rsp/rbp families entirely (never SysV argument registers; "the esp
# argument"-shaped prose must not mint a liveness claim). Disasm-side
# operand matching includes every alias — objdump output is
# unambiguous.

_HYP_REG_CANON: dict[str, str] = {}
_DISASM_FAMILY_MEMBERS: dict[str, frozenset[str]] = {}
_REG_WIDTH_BYTES: dict[str, int] = {}


def _register_family(
    family: str, members64: list[tuple[str, int]],
    hyp_ok: list[str],
) -> None:
    names = frozenset(n for n, _w in members64)
    _DISASM_FAMILY_MEMBERS[family] = names
    for name, width in members64:
        _REG_WIDTH_BYTES[name] = width
    for name in hyp_ok:
        _HYP_REG_CANON[name] = family


for _base, _low8 in (("ax", "al"), ("bx", "bl"), ("cx", "cl"),
                     ("dx", "dl")):
    _register_family(
        f"r{_base}",
        [(f"r{_base}", 8), (f"e{_base}", 4), (_base, 2),
         (_low8, 1), (_low8[0] + "h", 1)],
        [f"r{_base}", f"e{_base}"],
    )
for _base in ("si", "di"):
    _register_family(
        f"r{_base}",
        [(f"r{_base}", 8), (f"e{_base}", 4), (_base, 2),
         (f"{_base}l", 1)],
        [f"r{_base}", f"e{_base}", f"{_base}l"],
    )
for _base in ("bp", "sp"):
    # Disasm-side members only: rbp/rsp are frame/stack registers,
    # never SysV arguments — excluded from hypothesis-side binding.
    _register_family(
        f"r{_base}",
        [(f"r{_base}", 8), (f"e{_base}", 4), (_base, 2),
         (f"{_base}l", 1)],
        [],
    )
for _n in range(8, 16):
    _register_family(
        f"r{_n}",
        [(f"r{_n}", 8), (f"r{_n}d", 4), (f"r{_n}w", 2), (f"r{_n}b", 1)],
        [f"r{_n}", f"r{_n}d", f"r{_n}w", f"r{_n}b"],
    )

#: SysV AMD64 integer argument registers, position order.
SYSV_ARG_REGISTERS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

_ORDINAL_WORDS = {
    "first": 1, "second": 2, "third": 3,
    "fourth": 4, "fifth": 5, "sixth": 6,
}

# ── trigger taxonomy (keyword + structure, bounded) ────────────────

_HYP_REG_RE = re.compile(
    r"\b(" + "|".join(sorted(_HYP_REG_CANON, key=len, reverse=True))
    + r")\b",
    re.IGNORECASE,
)
_ARG_NOUN_RE = re.compile(
    r"\b(?:argument|parameter|arg)s?\b", re.IGNORECASE,
)
_DROP_RE = re.compile(
    r"\b(?:missing|dropped|omitted|absent|discarded|lost|truncated"
    r"|never\s{1,4}(?:passed|set|loaded|materiali[sz]ed|supplied)"
    r"|not\s{1,4}(?:passed|set|loaded|supplied|materiali[sz]ed"
    r"|initiali[sz]ed)"
    r"|no\s{1,4}longer\s{1,4}passed)\b",
    re.IGNORECASE,
)
_NO_ARG_RE = re.compile(
    r"\bno\s{1,4}(?:count|length|size|len|byte[- ]count)"
    r"\s{1,4}(?:argument|parameter|arg)\b",
    re.IGNORECASE,
)
_LIVENESS_RE = re.compile(
    r"\b(?:never|not|isn't|is\s{1,4}not|un)[\s-]{0,4}"
    r"(?:written|set|loaded|assigned|initiali[sz]ed|live|defined)\b",
    re.IGNORECASE,
)
_ORDINAL_RE = re.compile(
    r"\b(first|second|third|fourth|fifth|sixth)\s{1,4}"
    r"(?:argument|parameter|arg)\b"
    r"|\b(?:argument|parameter|arg)\s{0,2}#?\s{0,2}([1-6])\b",
    re.IGNORECASE,
)
_WIDTH_RE = re.compile(
    r"\bonly\s{1,4}(?:the\s{1,4})?(?:first\s{1,4}|low(?:er)?\s{1,4})?"
    r"(\d{1,4})\s{1,4}(bytes?|bits?)\b",
    re.IGNORECASE,
)
_VALIDATE_VERB_RE = re.compile(
    r"\b(?:validat|check|compar|examin|verif|test)\w{0,10}\b",
    re.IGNORECASE,
)
_CALLEE_RE = re.compile(
    r"\b(?:call(?:s|ed|ing)?\s{1,4}(?:to\s{1,4})?"
    r"|(?:passed|supplied)\s{1,4}(?:in)?to\s{1,4}"
    r"|(?:validated|checked|verified|handled|processed|sanitized"
    r"|parsed|invoked)\s{1,4}by\s{1,4})[`\"']?"
    r"([A-Za-z_][A-Za-z0-9_@]{2,63})",
    re.IGNORECASE,
)
_FUNCALL_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]{2,63})\s{0,2}\(",
)
#: Tool-minted function names (Ghidra/r2 conventions) are unambiguous
#: symbols wherever they appear in prose — always callee candidates.
_TOOL_NAME_RE = re.compile(
    r"\b((?:FUN|SUB|fcn)[._][0-9a-fA-F]{4,16})\b",
)
#: FUN_/SUB_-shaped item names embed the RE tool's address — the
#: name-derived leg of the load-bias convention.
_FUN_NAME_ADDR_RE = re.compile(
    r"\A(?:FUN|SUB)_([0-9a-fA-F]{4,16})\Z",
)

#: Prose words the callee shapes capture that are never symbols.
_CALLEE_STOPWORDS = frozenset({
    "if", "while", "for", "switch", "return", "sizeof", "count",
    "that", "this", "which", "one", "the", "and", "but", "with",
    "element", "entry", "value", "index", "array", "call", "calls",
})


@dataclass(frozen=True)
class DisasmTrigger:
    """One bound trigger: class + the structure the predicates need."""

    kind: str
    register: str | None = None  # canonical 64-bit family name
    callees: tuple[str, ...] = ()
    claimed_width: int | None = None  # bytes


def _bind_register(text: str) -> str | None:
    """Disciplined register binding — refuse rather than guess.

    The claim text quotes attacker-influenced material (decompilation
    identifiers, string literals the model echoes), so first-match
    binding is steerable: a quoted "rdi validated ok" would bind rdi
    for a claim about rdx. Nearest-to-keyword binding was considered
    and rejected — quoted text can sit nearer the keyword than the
    reviewer's own register mention. Rules:

    * multiple DISTINCT explicit families mentioned → refuse (None);
    * multiple distinct ordinal positions → refuse;
    * explicit family and ordinal-mapped family disagree → refuse;
    * rsp/rbp spellings never bind (excluded from the vocabulary).
    """
    explicit = {
        _HYP_REG_CANON[m.group(1).lower()]
        for m in _HYP_REG_RE.finditer(text)
    }
    ordinals = set()
    for m in _ORDINAL_RE.finditer(text):
        if m.group(1):
            pos = _ORDINAL_WORDS[m.group(1).lower()]
        else:
            pos = int(m.group(2))
        ordinals.add(SYSV_ARG_REGISTERS[pos - 1])
    if len(explicit) > 1 or len(ordinals) > 1:
        return None
    if explicit and ordinals and explicit != ordinals:
        return None
    if explicit:
        return next(iter(explicit))
    if ordinals:
        return next(iter(ordinals))
    return None


def _bind_callees(text: str, self_name: str = "") -> tuple[str, ...]:
    """Candidate callee names from the claim text, bounded."""
    seen: list[str] = []
    for regex in (_CALLEE_RE, _TOOL_NAME_RE, _FUNCALL_RE):
        for m in regex.finditer(text):
            name = m.group(1)
            low = name.lower()
            if low in _CALLEE_STOPWORDS or low in _HYP_REG_CANON:
                continue
            if self_name and name == self_name:
                continue
            if name not in seen:
                seen.append(name)
            if len(seen) >= 6:
                return tuple(seen)
    return tuple(seen)


def classify_trigger(
    hypothesis: str, *, function_name: str = "",
) -> DisasmTrigger | None:
    """Bounded keyword+structure match — the documented taxonomy.

    Returns ``None`` for every claim outside the four trigger
    classes; the channel is then never invoked (no subprocess, no
    journal row). NOT free LLM classification: the match is a fixed
    regex conjunction over a truncated copy of the claim text.
    """
    text = str(hypothesis or "")[:MAX_HYPOTHESIS_CHARS]
    if not text:
        return None
    register = _bind_register(text)
    callees = _bind_callees(text, self_name=function_name)

    # Class 1: dropped/missing argument with a bound register — the
    # canonical decompiler artifact: the pseudo-C omits a count/length
    # argument that the instructions show materialized in its SysV
    # register, live into the callee.
    no_arg = bool(_NO_ARG_RE.search(text))
    dropped = no_arg or (
        bool(_ARG_NOUN_RE.search(text)) and bool(_DROP_RE.search(text))
    )
    if register is not None and dropped:
        return DisasmTrigger(
            kind=TRIGGER_DROPPED_ARGUMENT,
            register=register,
            callees=callees,
        )

    # Class 2: register-unbound count/length/size-argument claim with
    # a nameable callee ("no count argument, unlike sibling calls
    # that pass one") — adjudicated by the sibling-differential lane
    # against the callee's OTHER call sites.
    if register is None and no_arg and callees:
        return DisasmTrigger(
            kind=TRIGGER_SIBLING_ARGUMENT,
            callees=callees,
        )

    # Class 3: register-liveness ("r8d is never set before the call").
    if register is not None and _LIVENESS_RE.search(text):
        return DisasmTrigger(
            kind=TRIGGER_REGISTER_LIVENESS,
            register=register,
            callees=callees,
        )

    # Class 4: immediate/operand width ("only 4 bytes are validated").
    # Corroborate/inconclusive-only — see _check_immediate_width.
    wm = _WIDTH_RE.search(text)
    if wm and _VALIDATE_VERB_RE.search(text):
        value = int(wm.group(1))
        unit = wm.group(2).lower()
        width = (value + 7) // 8 if unit.startswith("bit") else value
        if 1 <= width <= 8:
            return DisasmTrigger(
                kind=TRIGGER_IMMEDIATE_WIDTH,
                register=register,
                callees=callees,
                claimed_width=width,
            )
    return None


# ── result record ───────────────────────────────────────────────────


@dataclass
class DisasmXCheckResult:
    """One cross-check adjudication with its receipt."""

    outcome: str  # refuted | corroborated | inconclusive | skipped | error
    trigger: str
    reason: str
    rule_id: str
    register: str = ""
    call_sites: list[dict[str, Any]] = field(default_factory=list)
    excerpt: str = ""  # bounded + escaped disassembly receipt
    engine: str = "disasm"
    tier: str = EvidenceTier.DECODED_INSTRUCTION.value
    binary: str = ""
    window: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome,
            "trigger": self.trigger,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "register": self.register,
            "call_sites": list(self.call_sites),
            "excerpt": self.excerpt,
            "engine": self.engine,
            "tier": self.tier,
            "binary": self.binary,
            "window": dict(self.window),
        }

    def receipt_summary(self) -> dict[str, Any]:
        """Compact receipt for outcome attachment (export chain)."""
        return {
            "outcome": self.outcome,
            "trigger": self.trigger,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "engine": self.engine,
            "tier": self.tier,
            "excerpt": self.excerpt,
        }


def _result(
    outcome: str, trigger: DisasmTrigger, reason: str, **kw: Any,
) -> DisasmXCheckResult:
    return DisasmXCheckResult(
        outcome=outcome,
        trigger=trigger.kind,
        reason=reason,
        rule_id=_RULE_BY_TRIGGER[trigger.kind],
        register=trigger.register or "",
        **kw,
    )


def _bound_excerpt(text: str) -> str:
    """One bounding chokepoint for every receipt excerpt: escape
    (newline-preserving), cap at :data:`MAX_EXCERPT_CHARS`, trim a
    cut-in-half trailing escape token, append the elision marker."""
    escaped = escape_nonprintable(text, preserve_newlines=True)
    if len(escaped) <= MAX_EXCERPT_CHARS:
        return escaped
    cut = escaped[:MAX_EXCERPT_CHARS]
    # A slice can bisect a ``\xHH``/``\uHHHH`` escape the escaper just
    # minted; a trailing partial token would render as misleading
    # bytes in the receipt.
    cut = re.sub(
        r"\\(?:x[0-9a-fA-F]?|u[0-9a-fA-F]{0,3}|U[0-9a-fA-F]{0,7})?\Z",
        "", cut,
    )
    return cut + "\n...[excerpt elided]"


# ── window extraction (sandboxed objdump) ───────────────────────────


@dataclass(frozen=True)
class _Insn:
    address: int
    mnemonic: str
    operands: str


@dataclass(frozen=True)
class _Window:
    insns: tuple[_Insn, ...]
    file_format: str
    truncated: bool
    tool_ok: bool


#: (path, mtime_ns, lo, hi) → parsed window. Content-stamped key per
#: the run_memo discipline; the memo never bypasses the sandbox.
_WINDOW_MEMO: "BoundedMemo[_Window]" = BoundedMemo(64)

#: x86 instruction-prefix tokens objdump renders as the FIRST word of
#: the mnemonic column (``rep ret``, ``bnd jmp``, ``lock cmpxchg``,
#: ``cs nop`` padding). Folded away at the parse seam so the REAL
#: mnemonic drives control-flow classification — an unfolded ``repz``
#: read ``rep ret`` as a fall-through and let a write "reach" a call
#: that only external entries reach. ISA facts, not a vocabulary.
_PREFIX_TOKENS = frozenset({
    "rep", "repz", "repe", "repnz", "repne", "lock", "bnd",
    "notrack", "data16", "addr32", "xacquire", "xrelease",
    "cs", "ds", "es", "fs", "gs", "ss",
})

#: Trap/terminator mnemonics: execution never falls through them in
#: reality (``ud2`` after a noreturn call is ubiquitous in modern
#: compiler output). Classified as control flow AND as terminators in
#: the entry-reachability walk.
_TRAP_MNEMONICS = frozenset({"ud2", "ud1", "ud0", "hlt", "int3"})

_FORMAT_RE = re.compile(r"file format\s{1,8}(\S{1,64})")
# Applied per line via .match() — never MULTILINE over whole output.
# Every quantifier is bounded (byte pairs: x86 instructions max 15
# bytes; objdump pads short instructions' byte columns, hence the
# generous per-separator bound) so a hostile-ELF-shaped output line
# cannot buy superlinear backtracking; an over-long line simply fails
# to parse and the window is treated as incomplete.
_INSN_LINE_RE = re.compile(
    r"[ \t]{0,8}([0-9a-f]{1,16}):[ \t]{1,8}"
    r"(?:[0-9a-f]{2}[ \t]{1,32}){1,16}"
    r"([a-z][a-z0-9.]{0,15})?(?:[ \t]{1,8}(.{0,200}))?$",
)

# Per-run spawn budget, keyed by run identity (the RESOLVED out_dir —
# distinct spellings of one directory share one budget). Bounded so a
# long-lived process serving many runs cannot grow the registry.
_SPAWN_LOCK = threading.Lock()
_SPAWN_COUNTS: "OrderedDict[str, int]" = OrderedDict()
_SPAWN_RUNS_KEPT = 8


def _spawn_budget_take(run_key: str) -> bool:
    """Reserve one disassembler spawn; False when the cap is spent."""
    with _SPAWN_LOCK:
        count = _SPAWN_COUNTS.get(run_key, 0)
        if count >= PER_RUN_INVOCATION_CAP:
            return False
        _SPAWN_COUNTS[run_key] = count + 1
        _SPAWN_COUNTS.move_to_end(run_key)
        while len(_SPAWN_COUNTS) > _SPAWN_RUNS_KEPT:
            _SPAWN_COUNTS.popitem(last=False)
    return True


def _reset_for_tests() -> None:
    """Clear per-run spawn budgets and the window memo (tests only)."""
    global _WINDOW_MEMO  # noqa: PLW0603 — test-only reset seam
    with _SPAWN_LOCK:
        _SPAWN_COUNTS.clear()
    _WINDOW_MEMO = BoundedMemo(64)


def _run_objdump(binary: Path, lo: int, hi: int) -> tuple[str, bool]:
    """Sandboxed ``objdump -d`` over one address window.

    Same posture as the binary-oracle's binutils runs: the tool is
    RAPTOR-picked but the parsed bytes come from the analysed binary,
    and binutils' ELF parsers have a CVE history — full sandbox
    (network blocked, list argv, safe env), never a shell string.
    """
    from core.sandbox import run as _sandbox_run

    argv = [
        "objdump", "-d", "-M", "intel", "-w",
        f"--start-address={lo:#x}",
        f"--stop-address={hi:#x}",
        str(binary),
    ]
    try:
        proc = _sandbox_run(
            argv, block_network=True,
            target=str(binary.resolve().parent),
            capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=PER_ITEM_TIMEOUT_S,
        )
    except Exception as exc:  # noqa: BLE001 — best-effort channel
        logger.debug("disasm_xcheck objdump failed: %s", exc)
        return "", False
    if proc.returncode != 0:
        logger.debug(
            "disasm_xcheck objdump rc=%s on %s",
            proc.returncode,
            escape_nonprintable(str(binary)),
        )
        return "", False
    return proc.stdout or "", True


def _parse_window(text: str, lo: int, hi: int) -> _Window:
    fmt = ""
    insns: list[_Insn] = []
    truncated = False
    for i, line in enumerate(text.splitlines()):
        if i >= MAX_OUTPUT_LINES:
            truncated = True
            break
        if not fmt:
            fm = _FORMAT_RE.search(line[:200])
            if fm:
                fmt = fm.group(1)
                continue
        m = _INSN_LINE_RE.match(line)
        if not m or not m.group(2):
            continue
        try:
            addr = int(m.group(1), 16)
        except ValueError:
            continue
        if not (lo <= addr < hi):
            continue
        mnemonic = m.group(2)
        operands = (m.group(3) or "").strip()
        # Prefix folding: the column's first token can be an x86
        # prefix; shift until the real mnemonic surfaces (bounded —
        # real encodings carry at most a few prefixes).
        folds = 0
        while mnemonic in _PREFIX_TOKENS and operands and folds < 4:
            head, _, rest = operands.partition(" ")
            mnemonic, operands = head, rest.strip()
            folds += 1
        insns.append(_Insn(
            address=addr,
            mnemonic=mnemonic,
            operands=operands,
        ))
    return _Window(
        insns=tuple(insns), file_format=fmt,
        truncated=truncated, tool_ok=True,
    )


class _SpawnBudgetExhausted(Exception):
    """Raised inside the memo compute so a cap-hit caches NOTHING —
    a later run with fresh budget must be able to disassemble this
    same window."""


def _extract_window(
    binary: Path, lo: int, hi: int, run_key: str,
) -> _Window | str:
    """Parsed window, or a skip/inconclusive reason string."""
    import shutil

    if shutil.which("objdump") is None:
        return REASON_TOOL_UNAVAILABLE
    try:
        stat = binary.stat()
        key = (str(binary.resolve()), stat.st_mtime_ns, lo, hi)
    except OSError:
        return REASON_BINARY_UNRESOLVED

    def _compute() -> _Window:
        if not _spawn_budget_take(run_key):
            raise _SpawnBudgetExhausted
        text, ok = _run_objdump(binary, lo, hi)
        if not ok:
            # Cached: a window objdump cannot decode stays undecodable
            # for this (path, mtime) — re-spawning per item would just
            # re-pay the failure.
            return _Window(
                insns=(), file_format="", truncated=False,
                tool_ok=False,
            )
        return _parse_window(text, lo, hi)

    try:
        window, _cached = _WINDOW_MEMO.get_or_compute(key, _compute)
    except _SpawnBudgetExhausted:
        return REASON_INVOCATION_CAP
    if not window.tool_ok:
        return REASON_DISASM_FAILED
    return window


# ── ELF load info + address-space bias ──────────────────────────────


def _elf_load_info(binary: Path) -> tuple[int, bool] | None:
    """``(min PT_LOAD vaddr, is_ET_DYN)`` from the ELF64 header.

    Bounded pure-Python fixed-size reads — the bytes are hostile, so
    no library parser and no unbounded loops. ``None`` on anything
    that is not a well-formed little-endian ELF64.
    """
    from core.source import open_regular

    fh = open_regular(binary, "rb")
    if fh is None:
        return None
    try:
        with fh:
            hdr = fh.read(64)
            if (len(hdr) < 64 or hdr[:4] != b"\x7fELF"
                    or hdr[4] != 2 or hdr[5] != 1):
                return None
            e_type = struct.unpack_from("<H", hdr, 16)[0]
            e_phoff = struct.unpack_from("<Q", hdr, 32)[0]
            e_phentsize = struct.unpack_from("<H", hdr, 54)[0]
            e_phnum = struct.unpack_from("<H", hdr, 56)[0]
            if not (0 < e_phnum <= 64) or e_phentsize < 56 \
                    or e_phoff > (1 << 30):
                return None
            fh.seek(e_phoff)
            table = fh.read(e_phentsize * e_phnum)
    except OSError:
        return None
    loads: list[int] = []
    for i in range(e_phnum):
        off = i * e_phentsize
        if off + 56 > len(table):
            break
        p_type = struct.unpack_from("<I", table, off)[0]
        if p_type == 1:  # PT_LOAD
            loads.append(struct.unpack_from("<Q", table, off + 16)[0])
    if not loads:
        return None
    return min(loads), e_type == 3


#: Bias provenance values. ``segments`` is MEASURED (the re-database's
#: own block table against the ELF's program headers); ``name`` is the
#: GUESSED per-source_tool convention. Per the suppression-authority
#: doctrine (guessed configuration downgrades authority — the
#: binary-oracle ``earns_suppression`` precedent), a nonzero
#: name-convention bias CAPS the run's outcome at
#: corroborate/inconclusive: only a measured bias may back a
#: refutation.
BIAS_SOURCE_SEGMENTS = "segments"
BIAS_SOURCE_NAME = "name-convention"
BIAS_SOURCE_NONE = "none"


def _resolve_bias(
    db: Any | None, binary: Path, function_name: str,
    address: int | None,
) -> tuple[int, int, str]:
    """``(tool_bias, item_bias, source)`` for every resolved address.

    ``tool_bias`` maps RE-DATABASE addresses (callee targets, xref
    sites, function starts — always tool-space) to ELF vaddrs. Two
    legs, measured-first: (1) the re-database's segment table — the
    minimum start of its LOADED blocks is the RE tool's image base,
    compared against the ELF's minimum PT_LOAD vaddr; (2) the
    per-source_tool convention — a ``FUN_``/``SUB_``-named item whose
    embedded hex equals the item address proves tool-minted
    (tool-space) addressing, and Ghidra rebases ET_DYN ELFs to its
    default image base. Without ELF load info no correction is
    attempted (0): guessing a base against an unparsable header would
    be exactly the wrong-window class this function exists to close.

    ``item_bias`` maps the ITEM's given address: normally equal to
    ``tool_bias``, but tool-minted names embed the TOOL-SPACE address,
    so a ``FUN_``/``SUB_`` item whose embedded address sits exactly one
    tool_bias ABOVE the given address was already corrected by the
    caller — correcting again would decode one bias below the function
    (the double-correction wrong-window class) — and item_bias is 0.
    """
    info = _elf_load_info(binary)
    if info is None:
        return 0, 0, BIAS_SOURCE_NONE
    elf_base, is_dyn = info

    source = BIAS_SOURCE_NONE
    tool_base: int | None = None
    segments = getattr(db, "segments", None) if db is not None else None
    if segments:
        # LOADED blocks only: Ghidra also records non-loaded metadata
        # blocks (.shstrtab, _elfSectionHeaders, .gnu_debuglink) at
        # address 0 with permissions "---" — folding those in would
        # read the image base as 0 and disable the correction.
        starts = [
            s.start for s in segments
            if isinstance(getattr(s, "start", None), int)
            and s.start >= 0
            and any(
                c in (getattr(s, "permissions", "") or "")
                for c in "rwx"
            )
        ]
        if starts:
            tool_base = min(starts)
            source = BIAS_SOURCE_SEGMENTS
    embedded = -1
    m = _FUN_NAME_ADDR_RE.match(function_name or "")
    if m:
        try:
            embedded = int(m.group(1), 16)
        except ValueError:
            embedded = -1
    if tool_base is None and address is not None \
            and is_dyn and embedded == address:
        tool_base = GHIDRA_DEFAULT_IMAGE_BASE
        source = BIAS_SOURCE_NAME
    if tool_base is None:
        return 0, 0, BIAS_SOURCE_NONE
    tool_bias = tool_base - elf_base
    item_bias = tool_bias
    if (
        address is not None
        and embedded >= 0
        and embedded != address
        and embedded - address == tool_bias
    ):
        item_bias = 0
    return tool_bias, item_bias, source


# ── address / callee resolution ─────────────────────────────────────


def _checklist_item(
    checklist: dict[str, Any] | None, file_path: str, function_name: str,
) -> dict[str, Any] | None:
    for file_entry in (checklist or {}).get("files", []):
        if file_entry.get("path") != file_path:
            continue
        items = file_entry.get("items", file_entry.get("functions", []))
        for item in items or []:
            if item.get("name") == function_name:
                return item
    return None


def _load_redb_for(
    out_dir: Path | None, target_path: Path,
) -> Any | None:
    try:
        from .binary_context import find_redb, load_redb

        redb_path = find_redb(out_dir, target_path)
        if redb_path is None:
            return None
        return load_redb(redb_path)
    except Exception:  # noqa: BLE001 — resolution is best-effort
        logger.debug("disasm_xcheck redb load failed", exc_info=True)
        return None


def _resolve_window_bounds(
    *,
    checklist: dict[str, Any] | None,
    file_path: str,
    function_name: str,
    db: Any | None,
) -> tuple[int, int] | None:
    """(tool-space address, size) for the reviewed function, or None."""
    item = _checklist_item(checklist, file_path, function_name)
    address = None
    size = None
    if item is not None:
        address = item.get("address")
        size = item.get("size")
        meta = item.get("metadata") or {}
        if address is None:
            address = meta.get("address")
        if size is None:
            size = meta.get("size")
    lookup_name = function_name
    if address is None and "@0x" in function_name:
        base, _, addr_s = function_name.rpartition("@")
        try:
            address = int(addr_s, 16)
            lookup_name = base
        except ValueError:
            address = None
    if db is not None and (address is None or not size):
        func = None
        if isinstance(address, int):
            func = db.function_by_address(address)
        if func is None:
            func = next(
                (f for f in db.functions if f.name == lookup_name),
                None,
            )
        if func is not None:
            if address is None:
                address = func.address
            if not size:
                size = func.size
    if not isinstance(address, int) or address < 0:
        return None
    if not isinstance(size, int) or size <= 0:
        size = DEFAULT_WINDOW_BYTES
    return address, min(size, MAX_WINDOW_BYTES)


def _resolve_callee_addresses(
    db: Any | None, callees: tuple[str, ...], bias: int,
) -> dict[str, int]:
    """Callee name → ELF-vaddr (bias-corrected) via the re-database."""
    if db is None or not callees:
        return {}
    wanted = set(callees)
    out: dict[str, int] = {}
    try:
        for f in db.functions:
            if f.name in wanted and isinstance(f.address, int):
                corrected = f.address - bias
                if corrected >= 0:
                    out[f.name] = corrected
    except Exception:  # noqa: BLE001 — hostile-derived database shapes
        logger.debug("disasm_xcheck callee resolve failed", exc_info=True)
    return out


# ── instruction predicates ──────────────────────────────────────────

_WRITE_MNEMONICS = frozenset({
    "mov", "movabs", "movzx", "movsx", "movsxd", "lea",
    "xor", "or", "and", "add", "sub", "adc", "sbb", "imul",
    "inc", "dec", "neg", "not", "shl", "shr", "sar", "sal",
    "rol", "ror", "pop", "bswap", "xchg", "movd", "movq",
    "cvttsd2si", "cvttss2si",
})
_CMP_MNEMONICS = frozenset({"cmp", "test"})
_CALL_SYMBOL_RE = re.compile(r"<([^>+@]{1,128})")
_CALL_ADDR_RE = re.compile(r"\A(?:0x)?([0-9a-f]{1,16})\b")

WRITE_KIND_STRONG = "strong"
WRITE_KIND_WEAK = "weak"


def _is_control_flow(mnemonic: str) -> bool:
    m = mnemonic.lower()
    return (
        m == "call"
        or m.startswith("j")      # jmp + every jcc + jrcxz
        or m.startswith("ret")
        or m.startswith("loop")
        or m in _TRAP_MNEMONICS   # execution never falls through
    )


def _branch_targets(insns: tuple[_Insn, ...]) -> frozenset[int]:
    """In-window jump/branch target addresses (decoded operands)."""
    out: set[int] = set()
    for insn in insns:
        m0 = insn.mnemonic.lower()
        if not (m0.startswith("j") or m0.startswith("loop")):
            continue
        m = _CALL_ADDR_RE.match(insn.operands.strip().lower())
        if m:
            try:
                out.add(int(m.group(1), 16))
            except ValueError:
                continue
    return frozenset(out)


def _first_operand(operands: str) -> str:
    return operands.split(",", 1)[0].strip().lower()


def _write_kind(insn: _Insn, members: frozenset[str]) -> str | None:
    """``strong``/``weak``/None write classification for one family.

    ``strong`` = unconditional mnemonic with a 32/64-bit destination
    (refute-grade CANDIDATE — reachability rules still apply).
    ``weak`` = conditional (cmov*/set*) or sub-width destination:
    blocks corroboration, never refutes (stale upper bits / untaken
    path). A mnemonic missing from the allowlist yields None in both
    lanes — fail-safe toward inconclusive, never toward refutation.
    """
    mnem = insn.mnemonic.lower()
    conditional = mnem.startswith(("cmov", "set"))
    if not conditional and mnem not in _WRITE_MNEMONICS:
        return None
    if mnem == "xchg":
        parts = [p.strip().lower() for p in insn.operands.split(",")]
        hits = [p for p in parts if p in members]
        if not hits:
            return None
        width = max(_REG_WIDTH_BYTES.get(p, 0) for p in hits)
    else:
        dest = _first_operand(insn.operands)
        if dest not in members:
            return None
        width = _REG_WIDTH_BYTES.get(dest, 0)
    if conditional or width < STRONG_WRITE_MIN_BYTES:
        return WRITE_KIND_WEAK
    return WRITE_KIND_STRONG


def _call_sites_in(insns: tuple[_Insn, ...]) -> list[int]:
    return [
        i for i, insn in enumerate(insns)
        if insn.mnemonic.lower() == "call"
    ]


def _call_matches(
    insn: _Insn,
    callee_names: tuple[str, ...],
    callee_addrs: dict[str, int],
) -> bool:
    ops = insn.operands
    sm = _CALL_SYMBOL_RE.search(ops)
    if sm and sm.group(1) in callee_names:
        return True
    am = _CALL_ADDR_RE.match(ops.strip().lower())
    if am and callee_addrs:
        try:
            target = int(am.group(1), 16)
        except ValueError:
            return False
        return target in callee_addrs.values()
    return False


def _entry_cf_index(insns: tuple[_Insn, ...]) -> int:
    for k, insn in enumerate(insns):
        if _is_control_flow(insn.mnemonic):
            return k
    return len(insns)


def _branch_target_index(
    insn: _Insn, idx_by_addr: dict[int, int],
) -> int | None:
    m = _CALL_ADDR_RE.match(insn.operands.strip().lower())
    if not m:
        return None
    try:
        return idx_by_addr.get(int(m.group(1), 16))
    except ValueError:
        return None


def _entry_reachable(insns: tuple[_Insn, ...]) -> frozenset[int]:
    """Instruction indices reachable from the window's first
    instruction via in-window control flow.

    Successors: ``ret*`` and the trap terminators
    (:data:`_TRAP_MNEMONICS`) have none; unconditional ``jmp`` has
    only its in-window target (an indirect/out-of-window jmp ends the
    path); conditional branches/``loop*`` have fall-through plus
    target; ``call`` falls through (callees return); everything else
    falls through. Bounded: each index enters the worklist once.

    This closes the entry-domination reachability vacuum: an entry
    region that ends in ``ret`` or jumps PAST the call leaves the
    call reachable only from OUTSIDE the entry path, so a write there
    dominates nothing that matters. Control flow entering the window
    from outside stays the documented residual.
    """
    if not insns:
        return frozenset()
    idx_by_addr = {insn.address: i for i, insn in enumerate(insns)}
    seen: set[int] = set()
    work = [0]
    while work:
        i = work.pop()
        if i in seen or i < 0 or i >= len(insns):
            continue
        seen.add(i)
        mnem = insns[i].mnemonic.lower()
        if mnem.startswith("ret") or mnem in _TRAP_MNEMONICS:
            continue
        if mnem == "jmp":
            target = _branch_target_index(insns[i], idx_by_addr)
            if target is not None:
                work.append(target)
            continue
        work.append(i + 1)
        if mnem.startswith("j") or mnem.startswith("loop"):
            target = _branch_target_index(insns[i], idx_by_addr)
            if target is not None:
                work.append(target)
    return frozenset(seen)


@dataclass
class _SiteAnalysis:
    """One call site's register analysis for one family."""

    index: int
    address: int
    strong: bool = False
    strong_kind: str = ""      # branch-free | entry-dominating
    write_address: int | None = None
    weak_write: bool = False   # ANY write present (blocks corroborate)
    unwritten_complete: bool = False

    def site_dict(self, binding: str) -> dict[str, Any]:
        return {
            "call_address": f"{self.address:#x}",
            "register_written": self.strong,
            "write_grade": (
                self.strong_kind if self.strong
                else ("weak" if self.weak_write else "none")
            ),
            "write_address": (
                f"{self.write_address:#x}"
                if self.write_address is not None else None
            ),
            "segment_complete": self.unwritten_complete or self.strong,
            "binding": binding,
        }


def _analyze_site(
    insns: tuple[_Insn, ...],
    call_index: int,
    members: frozenset[str],
    targets: frozenset[int],
    entry_reach: frozenset[int] | None,
) -> _SiteAnalysis:
    """Classify the family's pre-call writes for one call site.

    Refute grade (``strong``) requires the write to provably reach
    the call within the window: branch-free-connected (no
    control-transfer instruction between write and call, no in-window
    branch target strictly between them) or entry-dominating (in the
    straight-line entry region of a window that starts at the
    function entry — every in-window path passes it; see module
    docstring for the external-entry limitation).

    ``entry_reach`` is :func:`_entry_reachable` for windows whose
    first instruction IS the function entry, else ``None``. When
    present, a call NOT reachable from the entry (the entry region
    returns or jumps past it) refuses refute grade entirely — the
    only paths to such a call enter from outside the decoded window,
    so no in-window write can claim to dominate it.
    """
    call_addr = insns[call_index].address
    out = _SiteAnalysis(index=call_index, address=call_addr)
    call_unreachable_from_entry = (
        entry_reach is not None and call_index not in entry_reach
    )

    steps = 0
    j = call_index - 1
    cf_between = False
    boundary = False
    while j >= 0 and steps < LOOKBACK_INSTRUCTIONS:
        insn = insns[j]
        mnem = insn.mnemonic.lower()
        if mnem == "call":
            boundary = True
            break
        kind = _write_kind(insn, members)
        if kind is not None:
            out.weak_write = True
            if (
                kind == WRITE_KIND_STRONG
                and not out.strong
                and not cf_between
                and not call_unreachable_from_entry
                and not any(
                    insn.address < t <= call_addr for t in targets
                )
            ):
                out.strong = True
                out.strong_kind = "branch-free"
                out.write_address = insn.address
        if _is_control_flow(mnem):
            cf_between = True
        j -= 1
        steps += 1
    if j < 0:
        boundary = True

    if (
        not out.strong
        and entry_reach is not None
        and not call_unreachable_from_entry
    ):
        # Entry-dominating: a strong write before the FIRST
        # control-transfer instruction of the function. No in-window
        # jump can originate before it (the entry region is
        # straight-line by construction), so every in-window path to
        # the call passes the write — PROVIDED the call is reachable
        # from the entry at all (``call_unreachable_from_entry``
        # gates both strong legs: an entry region that returns or
        # jumps past the call dominates nothing that matters). An
        # intervening ``call`` between the write and the examined
        # call disqualifies: SysV argument registers are
        # caller-saved, so a callee in between may clobber the
        # materialized value (the tail-call/helper decoy shape).
        first_cf = _entry_cf_index(insns)
        has_intervening_call = any(
            insns[m].mnemonic.lower() == "call"
            for m in range(call_index)
        )
        if not has_intervening_call:
            for k in range(min(first_cf, call_index)):
                if _write_kind(insns[k], members) == WRITE_KIND_STRONG:
                    out.strong = True
                    out.strong_kind = "entry-dominating"
                    out.write_address = insns[k].address
                    out.weak_write = True
                    break

    out.unwritten_complete = (
        not out.weak_write and not out.strong and boundary
    )
    return out


def _excerpt_for(
    insns: tuple[_Insn, ...], site_indices: list[int],
) -> str:
    """Bounded, escaped receipt excerpt around the examined sites."""
    lines: list[str] = []
    for idx in site_indices[:4]:
        start = max(0, idx - 12)
        lines.append(f"; call-site window [{insns[idx].address:#x}]")
        for insn in insns[start:idx + 1]:
            lines.append(
                f"  {insn.address:#x}: {insn.mnemonic} {insn.operands}"
            )
    return _bound_excerpt("\n".join(lines))


# ── lane: register-not-set (dropped_argument / register_liveness) ───


def _check_register_not_set(
    trigger: DisasmTrigger,
    window: _Window,
    callee_addrs: dict[str, int],
    lo: int,
    base: dict[str, Any],
) -> DisasmXCheckResult:
    family = trigger.register or ""
    members = _DISASM_FAMILY_MEMBERS.get(family, frozenset())
    all_calls = _call_sites_in(window.insns)
    if not all_calls:
        return _result(
            "inconclusive", trigger, REASON_NO_CALL_SITE, **base,
        )
    if trigger.callees:
        matched = [
            i for i in all_calls
            if _call_matches(window.insns[i], trigger.callees,
                             callee_addrs)
        ]
        if not matched:
            # A bound callee that matches NO decoded call site must
            # never silently rebind to every call in the window (a
            # tail-called or misresolved callee would hand the
            # verdict to an unrelated call's registers).
            return _result(
                "inconclusive", trigger, REASON_CALLSITE_UNRESOLVED,
                excerpt=_excerpt_for(window.insns, all_calls),
                **base,
            )
        examined = matched
        binding = "callee-bound"
    else:
        examined = all_calls
        binding = "all-call-sites"
    sites_truncated = len(examined) > MAX_CALL_SITES
    examined = examined[:MAX_CALL_SITES]
    if sites_truncated:
        base = {
            **base,
            "window": {**base.get("window", {}),
                       "call_sites_truncated": True},
        }

    targets = _branch_targets(window.insns)
    head_at_start = bool(window.insns) and window.insns[0].address == lo
    entry_reach = _entry_reachable(window.insns) if head_at_start else None
    analyses = [
        _analyze_site(window.insns, i, members, targets, entry_reach)
        for i in examined
    ]
    site_dicts = [a.site_dict(binding) for a in analyses]
    excerpt = _excerpt_for(window.insns, examined)
    base = {**base, "call_sites": site_dicts, "excerpt": excerpt}

    strong = [a for a in analyses if a.strong]
    if (
        strong
        and len(strong) == len(analyses)
        and not sites_truncated
        and not window.truncated
    ):
        kinds = "+".join(sorted({a.strong_kind for a in strong}))
        return _result(
            "refuted", trigger,
            f"{family} materialized by a refute-grade write before "
            f"every examined call site ({binding}, "
            f"{len(analyses)} site(s), {kinds})",
            **base,
        )
    if any(a.weak_write and not a.strong for a in analyses):
        # Writes exist but below refute grade (conditional, sub-width,
        # or not provably reaching the call): corroboration is blocked
        # AND refutation is refused — the honest record.
        return _result(
            "inconclusive", trigger, REASON_WRITE_NOT_REFUTE_GRADE,
            **base,
        )
    if strong:
        return _result(
            "inconclusive", trigger, REASON_MIXED_CALL_SITES, **base,
        )
    complete = all(a.unwritten_complete for a in analyses)
    if complete and not window.truncated and not sites_truncated:
        return _result(
            "corroborated", trigger,
            f"no write to {family} in any complete pre-call segment "
            f"({len(analyses)} site(s))",
            **base,
        )
    return _result(
        "inconclusive", trigger, REASON_WINDOW_INCOMPLETE, **base,
    )


# ── lane: immediate width (corroborate / inconclusive ONLY) ─────────


def _is_zero_test_idiom(insn: _Insn) -> bool:
    """``test X,X`` on one register — a null/zero check, not a bounds
    check; it must never count as width evidence (a 64-bit zero test
    beside a 32-bit bounds compare is the classic truncated-length
    TRUE-finding shape)."""
    if insn.mnemonic.lower() != "test":
        return False
    parts = [p.strip().lower() for p in insn.operands.split(",")]
    return (
        len(parts) == 2
        and parts[0] == parts[1]
        and parts[0] in _REG_WIDTH_BYTES
    )


def _operand_width_bytes(operands: str) -> int:
    low = operands.lower()
    width = 0
    if "qword ptr" in low:
        width = 8
    elif "dword ptr" in low:
        width = 4
    elif "word ptr" in low and "dword" not in low and "qword" not in low:
        width = 2
    elif "byte ptr" in low:
        width = 1
    for part in low.split(","):
        token = part.strip().split()[0] if part.strip() else ""
        width = max(width, _REG_WIDTH_BYTES.get(token, 0))
    return width


def _check_immediate_width(
    trigger: DisasmTrigger,
    window: _Window,
    base: dict[str, Any],
) -> DisasmXCheckResult:
    """Width claims corroborate or stay inconclusive — NEVER refute.

    Rationale (deliberate downgrade): telling a bounds-check compare
    apart from a pointer/null/flag compare on the same register
    family is not mechanically decidable from a linear window — a
    64-bit zero test beside a 32-bit bounds check is precisely the
    truncated-length-check TRUE-finding shape, and a refutation lane
    here would demote real findings. Wider-compare evidence therefore
    only WITHHOLDS corroboration.
    """
    claimed = trigger.claimed_width or 0
    family = trigger.register or ""
    members = _DISASM_FAMILY_MEMBERS.get(family, frozenset())
    compares = [
        insn for insn in window.insns
        if insn.mnemonic.lower() in _CMP_MNEMONICS
        and not _is_zero_test_idiom(insn)
    ]
    if family:
        compares = [
            insn for insn in compares
            if any(
                tok.strip().split()[0] in members
                for tok in insn.operands.lower().split(",")
                if tok.strip()
            )
        ]
    cmp_lines = "\n".join(
        f"  {c.address:#x}: {c.mnemonic} {c.operands}"
        for c in compares[:8]
    )
    base = {**base, "excerpt": _bound_excerpt(cmp_lines)}
    if not compares:
        return _result(
            "inconclusive", trigger, REASON_NO_COMPARE, **base,
        )
    widths = [_operand_width_bytes(c.operands) for c in compares]
    max_width = max(widths) if widths else 0
    if max_width > claimed:
        return _result(
            "inconclusive", trigger, REASON_WIDER_COMPARE, **base,
        )
    if not window.truncated and 0 < max_width <= claimed:
        return _result(
            "corroborated", trigger,
            f"all decoded compares are <= {claimed} byte(s) "
            f"(max {max_width})",
            **base,
        )
    return _result(
        "inconclusive", trigger, REASON_WINDOW_INCOMPLETE, **base,
    )


# ── lane: sibling-differential argument profile ─────────────────────


def _site_arg_profile(
    insns: tuple[_Insn, ...],
    call_index: int,
    targets: frozenset[int],
    entry_reach: frozenset[int] | None,
    *,
    strong_only: bool,
) -> tuple[set[str], dict[str, _SiteAnalysis]]:
    """SysV argument registers written before one call.

    ``strong_only`` selects the lane's asymmetric detectors: the
    CLAIMED site counts refute-grade writes only (under-approximate —
    a register we are not sure is materialized must not defeat the
    claim), while SIBLING sites count ANY write (over-approximate —
    more registers in the sibling intersection make refutation
    strictly harder, the safe direction for a detector miss).
    """
    profile: set[str] = set()
    analyses: dict[str, _SiteAnalysis] = {}
    for family in SYSV_ARG_REGISTERS:
        a = _analyze_site(
            insns, call_index, _DISASM_FAMILY_MEMBERS[family],
            targets, entry_reach,
        )
        analyses[family] = a
        if a.strong or (not strong_only and a.weak_write):
            profile.add(family)
    return profile, analyses


def _check_sibling_argument(
    trigger: DisasmTrigger,
    window: _Window,
    db: Any | None,
    binary: Path,
    bias: int,
    lo: int,
    claimed_span: tuple[int, int],
    run_key: str,
    base: dict[str, Any],
) -> DisasmXCheckResult:
    """Adjudicate "no count/length/size argument, unlike sibling
    calls" without a register binding: compare THIS call site's
    argument-register profile against the callee's OTHER call sites.

    Refuted when no SysV register that every sibling site
    materializes is missing from this site's refute-grade profile —
    the "unlike siblings" premise is contradicted. Refutation is
    only sound over the FULL attributable sibling population: a
    sampled subset is decoy-steerable (low-address callers passing
    fewer arguments displace the real siblings and shrink the shared
    set toward the near-universal arg registers), so a population
    above :data:`MAX_SIBLING_SITES` or any attributable site that
    fails to sample cleanly BLOCKS refutation, and a shared set with
    no signal beyond arg1/arg2 (``{rdi}``/``{rsi}``/``{rdi, rsi}`` —
    materialized at essentially every call site) refuses to
    adjudicate. Xref sites with no containing function in the
    re-database are excluded from the population and counted in the
    receipt (``unattributed_sites``) — they are not sibling FUNCTION
    call sites this lane can reason about. Corroborated when the
    sibling-shared register(s) are provably unwritten here (complete
    segments). Anything else records inconclusive.
    """
    if db is None:
        return _result(
            "inconclusive", trigger, REASON_SIBLING_SUBSTRATE, **base,
        )
    callee_addrs = _resolve_callee_addresses(db, trigger.callees, bias)
    if not callee_addrs:
        return _result(
            "inconclusive", trigger, REASON_SIBLING_SUBSTRATE, **base,
        )
    all_calls = _call_sites_in(window.insns)
    matched = [
        i for i in all_calls
        if _call_matches(window.insns[i], trigger.callees, callee_addrs)
    ]
    if not matched:
        return _result(
            "inconclusive", trigger, REASON_CALLSITE_UNRESOLVED,
            excerpt=_excerpt_for(window.insns, all_calls),
            **base,
        )
    # A claimed window with more matched sites than the cap is only
    # PARTIALLY examined — the unexamined site could be the one that
    # genuinely misses the register, so refutation is refused exactly
    # like the register lane's call-site truncation.
    claimed_sites_truncated = len(matched) > MAX_CALL_SITES
    matched = matched[:MAX_CALL_SITES]

    # Sibling call sites of the same callee(s), from the re-database
    # xrefs — tool-space, corrected by the same bias.
    tool_lo, tool_hi = claimed_span
    sibling_addrs: list[int] = []
    try:
        callee_tool_addrs = {a + bias for a in callee_addrs.values()}
        for xref in db.xrefs:
            if getattr(xref, "kind", "") != "call":
                continue
            if getattr(xref, "to_addr", None) not in callee_tool_addrs:
                continue
            from_addr = getattr(xref, "from_addr", None)
            if not isinstance(from_addr, int):
                continue
            if tool_lo <= from_addr < tool_hi:
                continue  # the claimed function's own site
            sibling_addrs.append(from_addr)
    except Exception:  # noqa: BLE001 — hostile-derived database shapes
        logger.debug("disasm_xcheck xref walk failed", exc_info=True)
    sibling_addrs = sorted(set(sibling_addrs))

    targets = _branch_targets(window.insns)
    head_at_start = bool(window.insns) and window.insns[0].address == lo
    entry_reach = _entry_reachable(window.insns) if head_at_start else None

    # Attribute every xref site to its containing function first: the
    # POPULATION (not just the sample) decides whether refutation is
    # even on the table.
    attributable: list[tuple[int, Any]] = []
    unattributed = 0
    for from_addr in sibling_addrs:
        container = db.function_containing_address(from_addr)
        if container is None or not isinstance(container.address, int):
            unattributed += 1
            continue
        attributable.append((from_addr, container))
    population = len(attributable)
    sample_truncated = population > MAX_SIBLING_SITES

    sibling_profiles: list[set[str]] = []
    siblings_meta: list[dict[str, Any]] = []
    sampling_incomplete = False
    for from_addr, container in attributable[:MAX_SIBLING_SITES]:
        s_lo = container.address - bias
        s_call = from_addr - bias
        if (
            s_lo < 0
            or s_call < s_lo
            or s_call - s_lo > MAX_WINDOW_BYTES
        ):
            sampling_incomplete = True
            continue
        s_hi = s_call + 16
        s_window = _extract_window(binary, s_lo, s_hi, run_key)
        if isinstance(s_window, str) or s_window.truncated:
            sampling_incomplete = True
            continue
        s_calls = [
            i for i in _call_sites_in(s_window.insns)
            if s_window.insns[i].address == s_call
        ]
        if not s_calls:
            sampling_incomplete = True
            continue
        s_targets = _branch_targets(s_window.insns)
        s_head = bool(s_window.insns) \
            and s_window.insns[0].address == s_lo
        s_reach = _entry_reachable(s_window.insns) if s_head else None
        profile, _ = _site_arg_profile(
            s_window.insns, s_calls[0], s_targets, s_reach,
            strong_only=False,
        )
        sibling_profiles.append(profile)
        siblings_meta.append({
            "call_address": f"{s_call:#x}",
            "profile": sorted(profile),
        })

    base = {
        **base,
        "window": {
            **base.get("window", {}),
            "sibling_population": population,
            "sibling_unattributed": unattributed,
            "sibling_sample_truncated": sample_truncated,
            "sibling_sampling_incomplete": sampling_incomplete,
            "claimed_sites_truncated": claimed_sites_truncated,
        },
    }
    if len(sibling_profiles) < MIN_SIBLING_SITES:
        return _result(
            "inconclusive", trigger, REASON_SIBLING_SUBSTRATE,
            excerpt=_excerpt_for(window.insns, matched),
            **base,
        )
    shared = set.intersection(*sibling_profiles)
    if not shared or shared <= {"rdi", "rsi"}:
        # Siblings agree on no argument register at all — or only on
        # arg1/arg2, which are materialized at essentially every call
        # site and therefore carry no count-argument signal. A
        # degenerate intersection is exactly what a decoy-steered or
        # weak sample produces; refuting against it would make the
        # lane refute-happy, so the claim's "siblings pass one"
        # premise has nothing safe to bind against.
        return _result(
            "inconclusive", trigger, REASON_SIBLING_SUBSTRATE,
            excerpt=_excerpt_for(window.insns, matched),
            **base,
        )
    # Refutation needs the WHOLE attributable population sampled
    # cleanly — a shrunken or partial sample is decoy-steerable —
    # AND every matched claimed-window site examined.
    refute_sample_ok = not sample_truncated and not sampling_incomplete \
        and not claimed_sites_truncated \
        and len(sibling_profiles) == population

    site_dicts: list[dict[str, Any]] = []
    missing_per_site: list[set[str]] = []
    complete_missing = True
    for i in matched:
        profile, analyses = _site_arg_profile(
            window.insns, i, targets, entry_reach, strong_only=True,
        )
        missing = shared - profile
        missing_per_site.append(missing)
        for fam in missing:
            a = analyses[fam]
            if not a.unwritten_complete:
                complete_missing = False
        site_dicts.append({
            "call_address": f"{window.insns[i].address:#x}",
            "strong_profile": sorted(profile),
            "sibling_shared": sorted(shared),
            "missing": sorted(missing),
            "binding": "callee-bound",
        })
    base = {
        **base,
        "call_sites": site_dicts,
        "excerpt": _excerpt_for(window.insns, matched),
        "window": {
            **base.get("window", {}),
            "sibling_sites": siblings_meta,
        },
    }

    if all(not m for m in missing_per_site):
        if refute_sample_ok and not window.truncated:
            return _result(
                "refuted", trigger,
                "every argument register the sibling call sites "
                f"materialize ({', '.join(sorted(shared))}; all "
                f"{len(sibling_profiles)} attributable sibling(s)) "
                "is also materialized by a refute-grade write before "
                "this call",
                **base,
            )
        return _result(
            "inconclusive", trigger,
            REASON_SIBLING_SAMPLE_TRUNCATED
            if not refute_sample_ok else REASON_WINDOW_INCOMPLETE,
            **base,
        )
    if (
        all(m for m in missing_per_site)
        and complete_missing
        and not window.truncated
    ):
        union_missing = sorted(set.union(*missing_per_site))
        return _result(
            "corroborated", trigger,
            f"sibling call sites materialize {', '.join(union_missing)} "
            "but this site provably does not (complete segments)",
            **base,
        )
    return _result(
        "inconclusive", trigger, REASON_WINDOW_INCOMPLETE, **base,
    )


# ── entry point ─────────────────────────────────────────────────────


def run_disasm_xcheck(
    target_path: Path | str | None,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    checklist: dict[str, Any] | None = None,
    out_dir: Path | None = None,
    trigger: DisasmTrigger | None = None,
    db: Any | None = None,
) -> DisasmXCheckResult:
    """Adjudicate one triggered binary-item claim against the decoded
    instruction window. Never raises for expected shapes; every
    non-verdict path returns an honest reason record. ``db`` may be
    passed directly (tests, callers holding one) or is located via
    :func:`core.audit.binary_context.find_redb`."""
    if trigger is None:
        trigger = classify_trigger(
            hypothesis, function_name=function_name,
        )
    if trigger is None:
        # Callers normally pre-classify; a None here is a skip, not
        # an error — the taxonomy is the documented boundary.
        return DisasmXCheckResult(
            outcome="skipped",
            trigger="none",
            reason="no-trigger",
            rule_id="disasm_xcheck:none",
        )

    binary = Path(target_path) if target_path else None
    if binary is None or not binary.is_file():
        return _result(
            "inconclusive", trigger, REASON_BINARY_UNRESOLVED,
        )

    if db is None:
        db = _load_redb_for(out_dir, binary)
    bounds = _resolve_window_bounds(
        checklist=checklist,
        file_path=file_path,
        function_name=function_name,
        db=db,
    )
    if bounds is None:
        return _result(
            "inconclusive", trigger, REASON_ADDRESS_UNRESOLVED,
            binary=binary.name,
        )
    item_lo, size = bounds
    tool_bias, item_bias, bias_source = _resolve_bias(
        db, binary, function_name, item_lo,
    )
    lo = item_lo - item_bias
    hi = lo + size
    if lo < 0:
        return _result(
            "inconclusive", trigger, REASON_ADDRESS_UNRESOLVED,
            binary=binary.name,
            window={"item_address": f"{item_lo:#x}",
                    "bias": f"{item_bias:#x}"},
        )

    run_key = str(Path(out_dir).resolve()) if out_dir else ""
    window = _extract_window(binary, lo, hi, run_key)
    if isinstance(window, str):
        outcome = (
            "skipped"
            if window in (REASON_TOOL_UNAVAILABLE, REASON_INVOCATION_CAP)
            else "inconclusive"
        )
        return _result(
            outcome, trigger, window, binary=binary.name,
            window={"start": f"{lo:#x}", "end": f"{hi:#x}"},
        )
    if window.file_format and not window.file_format.startswith(
            "elf64-x86-64"):
        return _result(
            "inconclusive", trigger, REASON_ARCH_UNSUPPORTED,
            binary=binary.name,
            window={"start": f"{lo:#x}", "end": f"{hi:#x}",
                    "file_format": window.file_format},
        )
    if not window.insns:
        return _result(
            "inconclusive", trigger, REASON_WINDOW_EMPTY,
            binary=binary.name,
            window={"start": f"{lo:#x}", "end": f"{hi:#x}",
                    "bias": f"{item_bias:#x}"},
        )

    base: dict[str, Any] = {
        "binary": binary.name,
        "window": {
            "start": f"{lo:#x}",
            "end": f"{hi:#x}",
            "bias": f"{item_bias:#x}",
            "tool_bias": f"{tool_bias:#x}",
            "bias_source": bias_source,
            "instructions": len(window.insns),
            "truncated": window.truncated,
            "file_format": window.file_format,
        },
    }
    if trigger.kind in (
        TRIGGER_DROPPED_ARGUMENT, TRIGGER_REGISTER_LIVENESS,
    ):
        callee_addrs = _resolve_callee_addresses(
            db, trigger.callees, tool_bias,
        )
        result = _check_register_not_set(
            trigger, window, callee_addrs, lo, base,
        )
    elif trigger.kind == TRIGGER_SIBLING_ARGUMENT:
        # The claimed function's tool-space span (for excluding its
        # own xref sites) derives from the CORRECTED window plus the
        # DB bias — correct even when the item address arrived
        # pre-corrected.
        result = _check_sibling_argument(
            trigger, window, db, binary, tool_bias, lo,
            (lo + tool_bias, lo + tool_bias + size), run_key, base,
        )
    else:
        result = _check_immediate_width(trigger, window, base)

    if (
        result.outcome == "refuted"
        and bias_source == BIAS_SOURCE_NAME
        and (tool_bias != 0 or item_bias != 0)
    ):
        # Suppression-authority doctrine: the name-convention bias is
        # a GUESSED tool default (the binary-oracle earns_suppression
        # precedent for guessed configuration) — a window placed by a
        # guess may be a lookalike, so it can corroborate and enrich
        # but never back a demotion. Only a measured (segments) bias
        # refutes.
        result.outcome = "inconclusive"
        result.window = {
            **result.window,
            "refute_capped": "guessed-bias",
            "capped_reason": result.reason,
        }
        result.reason = REASON_GUESSED_BIAS
    return result


__all__ = [
    "DisasmTrigger",
    "DisasmXCheckResult",
    "GHIDRA_DEFAULT_IMAGE_BASE",
    "LOOKBACK_INSTRUCTIONS",
    "MAX_CALL_SITES",
    "MAX_EXCERPT_CHARS",
    "MAX_HYPOTHESIS_CHARS",
    "MAX_OUTPUT_LINES",
    "MAX_SIBLING_SITES",
    "MAX_WINDOW_BYTES",
    "MIN_SIBLING_SITES",
    "PER_ITEM_TIMEOUT_S",
    "PER_RUN_INVOCATION_CAP",
    "RULE_DROPPED_ARGUMENT",
    "RULE_IMMEDIATE_WIDTH",
    "RULE_REGISTER_LIVENESS",
    "RULE_SIBLING_ARGUMENT",
    "STRONG_WRITE_MIN_BYTES",
    "SYSV_ARG_REGISTERS",
    "TRIGGER_DROPPED_ARGUMENT",
    "TRIGGER_IMMEDIATE_WIDTH",
    "TRIGGER_REGISTER_LIVENESS",
    "TRIGGER_SIBLING_ARGUMENT",
    "classify_trigger",
    "run_disasm_xcheck",
]
