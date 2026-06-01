"""Binary-oracle reachability evidence — Inc 1 (classifier + 3-way classify).

Joins the source inventory with a matching debug binary via DWARF + nm to
produce one verdict per source function:

    symbol_present   the function is present in the binary's symbol table.
    inlined          DWARF shows the function was absorbed into callers
                     (DW_TAG_inlined_subroutine instance exists), no
                     standalone symbol.
    absent           neither — DCE'd by the compiler/linker.
    folded           two distinct source functions share one binary address
                     (ICF / outlining); both classify here, never as ``absent``.

Used asymmetrically by the reachability classifier (Inc 2):

  * ``absent ∧ ¬inlined`` ⇒ dead in THIS build (STRONG HEURISTIC; build-
    config-specific, so surface-only until corpus precision earns
    enforcement; never overrides a SOUND witness).
  * ``inlined`` or ``symbol_present`` ⇒ no demote.
  * Binary call edges the source graph missed ⇒ promote callee to reachable
    (Inc 2; not built here).

v1 scope (per design): Linux ELF, DWARF required, native targets (C/C++/
Rust/Go). Stripped binary → ``skipped`` with reason; macOS Mach-O / PE
deferred.

Implementation: shells out to system tools (``readelf``, ``nm``,
``objdump --dwarf=info``) — no Python DWARF library dependency. The text
parsing is binutils-version-resilient enough for the fixture matrix; the
classifier is the consumer-facing contract, not the parsing details.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import (
    Dict, Iterable, Iterator, List, Literal, Optional, Set, Tuple,
)

logger = logging.getLogger(__name__)


Classification = Literal["symbol_present", "inlined", "absent", "folded"]


@dataclass(frozen=True)
class BinaryOracleWitness:
    """Per-source-function evidence from a debug binary join.

    Carries provenance (``build_id`` + ``binary_path``) so consumers can spot
    scope mismatch (e.g. a witness from a different build was reused) and so
    multi-binary results can be attributed correctly. ``edges_added`` is
    reserved for Inc 2 (the call-edge promote direction) and stays empty
    here.

    ``tier`` encodes the evidence quality:

      ``"full"`` — DWARF + nm. All four verdicts (symbol_present,
                   inlined, absent, folded) emittable. Corpus-earned;
                   absent verdicts may license downstream suppression.

      ``"symbol_only"`` — stripped binary (no DWARF), nm-only. Cannot
                   distinguish ``inlined`` (no DW_TAG_inlined_subroutine
                   info) from ``absent`` (no nm symbol). Conservative:
                   absent verdicts in this tier do NOT earn suppression
                   — a stripped-out function could be inlined into a
                   surviving caller without us knowing. Emits
                   ``symbol_present`` and ``absent`` only.
    """
    classification: Classification
    build_id: str
    binary_path: str
    address: Optional[int] = None
    edges_added: List[Tuple[str, str]] = field(default_factory=list)
    tier: str = "full"


# ---------------------------------------------------------------------------
# System-tool wrappers (small, defensive, swap-out points if pyelftools ever
# gets added as a dep).
# ---------------------------------------------------------------------------

def _run(argv: List[str], timeout: int = 60) -> str:
    """Capture stdout from a system tool; return ``''`` on any failure
    rather than raise — the classifier is best-effort and surface-only.

    Uses ``core.sandbox.run_trusted`` (matches the existing pattern for
    ELF/binutils tools in ``exploit_feasibility``/``binary_analysis``):
    applies ``RaptorConfig.get_safe_env()`` + resource rlimits to keep
    the tool's ambient state hostile-input-resistant. Read-only tools
    (readelf, nm, objdump, c++filt) are RAPTOR-picked even when the
    binary path is operator-supplied.
    """
    # Lazy import — keep the classifier independently importable in
    # unit tests that stub the sandbox module.
    from core.sandbox import run_trusted
    try:
        proc = run_trusted(argv, capture_output=True, text=True,
                           check=False, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as e:
        logger.debug("binary_oracle: %s failed: %s", argv[0], e)
        return ""
    if proc.returncode != 0:
        logger.debug("binary_oracle: %s rc=%s stderr=%s",
                     argv[0], proc.returncode, proc.stderr[:200])
    return proc.stdout or ""


def _stream(argv: List[str], timeout: int) -> Iterator[str]:
    """Stream stdout line-by-line from a system tool. Used when the
    output may be large (e.g. ``objdump --dwarf=info`` on a multi-MB
    binary produces 1-3 GB of text); ``_run`` would buffer it all into
    memory and OOM. Yields each line stripped of its trailing newline.

    Manual ``get_safe_env`` application — ``run_trusted`` is one-shot
    (capture_output=True) and would defeat the memory-bounded streaming
    we need here. Same env hygiene as ``_run`` (no namespace/Landlock —
    that's the ``run_trusted`` protection level: env + rlimits only).

    On any failure (tool missing, non-zero rc with no output, timeout)
    yields nothing — same swallow-and-degrade contract as ``_run``.
    """
    from core.config import RaptorConfig
    deadline = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1, env=RaptorConfig.get_safe_env(),
        )
    except OSError as e:
        logger.debug("binary_oracle: %s failed to start: %s", argv[0], e)
        return
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if time.monotonic() > deadline:
                logger.warning(
                    "binary_oracle: %s exceeded %ss timeout; killing",
                    argv[0], timeout,
                )
                proc.kill()
                break
            yield line.rstrip("\n")
    finally:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def read_build_id(binary_path: Path) -> Optional[str]:
    """Return the ELF ``.note.gnu.build-id`` (40-hex SHA1), or ``None``."""
    out = _run(["readelf", "-n", str(binary_path)])
    m = re.search(r"Build ID:\s*([0-9a-fA-F]+)", out)
    return m.group(1).lower() if m else None


# GCC IPA-clone suffixes. ``-O2`` routinely rewrites symbol names with
# these tails when interprocedural optimisations specialise a function for
# its callers. Operators analysing any GCC-built binary will hit this — a
# source ``foo`` may only appear in nm as ``foo.constprop.0``, with no
# original ``foo`` symbol. Strip the suffix when building the bare-name
# index so source-name lookup still finds the function.
#   .constprop.N  — -fipa-cp constant-propagation clone
#   .isra.N       — -fipa-sra scalar-replacement clone
#   .part.N       — -fpartial-inlining hot/cold split
#   .cold / .cold.N
#   .local.N      — local visibility specialisation
#   .lto_priv.N   — -flto privatised local clone (common in LTO builds)
#   .clone.N      — generic GCC clone (target attribute, tail-merge clone)
#   ._omp_fn.N    — OpenMP outlined function
#   .resolver     — ifunc resolver indirection
#   .cfi          — -fcf-protection CFI thunk
#   .llvm.NN…     — clang/LLVM target attribute / ThinLTO variant suffix
#                    (numeric tail can be long, allow .\w+)
_IPA_CLONE_SUFFIX_RE = re.compile(
    r"\.(?:constprop|isra|part|cold|local|lto_priv|clone|_omp_fn"
    r"|resolver|cfi)(?:\.\d+)?$"
    r"|\.llvm\.\w+$"
)


def _strip_ipa_suffix(name: str) -> str:
    """Repeatedly strip GCC IPA-clone suffixes; e.g.
    ``gz_skip.constprop.0`` → ``gz_skip``, ``foo.isra.0.constprop.1`` →
    ``foo``. Returns ``name`` unchanged if no suffix matches."""
    while True:
        stripped = _IPA_CLONE_SUFFIX_RE.sub("", name)
        if stripped == name:
            return name
        name = stripped


def _nm_symbols(binary_path: Path) -> Dict[str, int]:
    """Name → address for every text symbol (local + global) defined in the
    binary. Missing tools / non-ELF input return ``{}``.

    Uses ``nm --demangle`` so C++ source function names (which DWARF
    ``DW_AT_name`` emits unmangled) match the symbol table entries (which
    nm emits MANGLED by default — e.g. ``_ZNK6Widget11live_methodEv``).
    Without ``-C``, every C++ method would classify as ``absent`` because
    the unmangled lookup never finds the mangled symbol (adversarial-review
    scenario B). Also indexes by *bare* name so source ``live_method``
    matches demangled ``Widget::live_method() const``, and so source
    ``gz_skip`` matches the GCC-cloned ``gz_skip.constprop.0``."""
    out = _run(["nm", "--demangle", str(binary_path)])
    if not out:
        out = _run(["nm", str(binary_path)])   # fall back if -C unavailable
    syms: Dict[str, int] = {}
    for line in out.splitlines():
        # ``<addr> <type> <demangled name (may contain spaces)>``
        # — split into at most 3 parts so a demangled name with spaces
        # survives intact for both the full-signature and bare-name lookup.
        parts = line.split(None, 2)
        if len(parts) >= 3 and len(parts[1]) == 1 and parts[1] in "tTwW":
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            full = parts[2].strip()
            syms[full] = addr
            # Three name forms get indexed so source-name lookup hits no
            # matter which form the caller has:
            #   full       "snappy::Uncompress(snappy::Source*, snappy::Sink*)"
            #   qualified  "snappy::Uncompress"   ← what gcov -m emits
            #   bare       "Uncompress"           ← legacy bare-name lookup
            # Without ``qualified``, C++ measurement against ``gcov -m``
            # demangled output couldn't match nm — surfaced in snappy Inc 3c.
            qualified = full.split("(", 1)[0] if "(" in full else full
            qualified = _strip_ipa_suffix(qualified)
            if qualified and qualified != full:
                syms.setdefault(qualified, addr)
            bare = (qualified.rsplit("::", 1)[-1]
                    if "::" in qualified else qualified)
            if bare and bare not in (full, qualified):
                syms.setdefault(bare, addr)
    return syms


@dataclass
class _SubprogramDIE:
    name: str = ""                            # DW_AT_name (local)
    namespace_path: str = ""                  # "snappy::Bits" from enclosing scope
    low_pc: Optional[int] = None
    has_inline_marker: bool = False           # DW_AT_inline=inlined
    abstract_origin: Optional[int] = None     # DIE offset (for inline instances)
    specification: Optional[int] = None       # DIE offset (definition → declaration)
    linkage_name: str = ""                    # DW_AT_linkage_name (mangled symbol)

    @property
    def qualified_name(self) -> str:
        """Fully-qualified C++ name (``snappy::Bits::Log2Floor``) or the
        bare name for C. Empty if ``name`` is unset (declaration-only
        DIE that hasn't had its specification resolved yet)."""
        if not self.name:
            return ""
        if not self.namespace_path:
            return self.name
        return f"{self.namespace_path}::{self.name}"


# ---------------------------------------------------------------------------
# C++ demangled-name parsing — shared between the classifier and corpus
# drivers (snappy.py reuses these via import).
# ---------------------------------------------------------------------------

_METHOD_TRAILING_QUALS = (
    " const volatile", " const", " volatile",
    " noexcept", " &&", " &",
)


def _find_arglist_open(name: str) -> int:
    """Index of the ``(`` opening the function's argument list, or -1.
    Walks right-to-left tracking ``<>`` / ``()`` / ``[]`` depth so the
    ``(`` inside ``(anonymous namespace)`` or template args isn't
    mistaken for the arglist opener. Also recognises ``operator()`` as
    a name-token: a balance-zero ``(`` immediately following the
    literal ``operator`` is the call-operator's own paren, not an
    arglist — returns -1 (no arglist) when it's the only candidate so
    callers preserve ``operator()`` intact (snappy lambda FP fix)."""
    if not name.endswith(")"):
        return -1
    angle = 0
    bracket = 0   # [] depth, for ``operator[]``
    depth = 0
    for i in range(len(name) - 1, -1, -1):
        ch = name[i]
        if ch == ">":
            angle += 1
        elif ch == "<" and angle > 0:
            angle -= 1
        elif angle == 0:
            if ch == "]":
                bracket += 1
            elif ch == "[" and bracket > 0:
                bracket -= 1
            elif bracket == 0:
                if ch == ")":
                    depth += 1
                elif ch == "(":
                    depth -= 1
                    if depth == 0:
                        if name[:i].rstrip().endswith("operator"):
                            # The ``(`` belongs to ``operator()`` — not
                            # the function's arglist. There's no arglist
                            # after the operator name; keep the whole
                            # ``operator()`` intact in the qualified name.
                            return -1
                        return i
    return -1


# Lambda type tags in demangled output: c++filt emits the captured
# argument types inside ``{lambda(...)#N}`` but ``gcov -m`` emits the
# bare placeholder ``{lambda()#N}``. Normalise to the gcov form so the
# two name sources can match.
_LAMBDA_ARGS_RE = re.compile(r"\{lambda\([^)]*\)(#\d+)\}")


def _normalise_lambda_args(name: str) -> str:
    return _LAMBDA_ARGS_RE.sub(r"{lambda()\1}", name)


# Rust crate-id hash embedded in demangled names: c++filt's Rust v0
# decoder emits ``regex[7e9e1dd283b8ce7a]::Match``. The hash is distinct
# per build (regenerated on each compile) but carries no information for
# source-name matching. Strip it so qualified names compare cleanly
# across rebuilds and align with ``nm --demangle`` output (which omits
# the hash). Originally lived in the regex driver; promoted here so every
# Rust binary + every future Rust corpus driver benefits automatically.
#
# Constrained to Rust-shape contexts (hex with optional ``h`` prefix —
# the rustc convention — and the bracket sits at end-of-name or at a
# ``::`` boundary). Without this constraint the regex also stripped
# bracketed hex in C++ template arg lists (e.g. a hypothetical
# ``foo[deadbeef]::bar``); the constraint anchors to Rust shape.
_RUST_CRATE_HASH_RE = re.compile(
    r"\[h?[0-9a-f]{8,}\](?=::|$)"
)


def _strip_rust_crate_hash(name: str) -> str:
    return _RUST_CRATE_HASH_RE.sub("", name)


# Rust impl-block demangler syntax: ``<regex::regex::bytes::Match>::start``
# is ``impl Match { fn start... }``. DWARF tracks the same hierarchy via
# DW_TAG_namespace + DW_TAG_structure_type and produces the qualified
# name ``regex::regex::bytes::Match::start`` (no angle brackets). Strip
# the brackets so the lookup forms align — without this, accessor
# methods on Rust types misclassify as ``absent`` because the demangler
# and the DWARF namespace tracker disagree on syntax (Inc 3g regex
# corpus finding).
#
# Supports nested generics and qualified projections (the common shapes
# in real-world Rust binaries with heavy generic / trait code — tokio,
# hyper, etc.):
#   <crate::Type<T>>::method        — generic instantiation
#   <&str>::len                      — primitive ref
#   <[u8; 4]>::iter                  — array type
#   <dyn Trait>::method              — dyn trait
#   <<Foo as Trait>::Bar>::method    — qualified projection
#
# The bracketed type is balanced — count ``<`` / ``>`` to find the
# matching close. C++ templates with leading ``<>`` (e.g.
# ``<vector<int>>::method`` from a hypothetical C++ namespace prefix
# spelling — vanishingly rare) also benefit from the same handling.

def _strip_impl_block_brackets(name: str) -> str:
    """Strip the outermost ``<...>`` from a Rust impl-block-qualified
    name. Returns ``name`` unchanged if the input doesn't start with
    ``<`` or the bracket isn't followed by ``::``."""
    if not name.startswith("<"):
        return name
    depth = 0
    close_idx = -1
    for i, ch in enumerate(name):
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
            if depth == 0:
                close_idx = i
                break
    if close_idx < 1:
        return name
    # Must be followed by ``::`` for this to be an impl-block prefix.
    if not name[close_idx + 1:].startswith("::"):
        return name
    inner = name[1:close_idx]
    rest = name[close_idx + 3:]
    # Recurse on inner — Rust qualified projection
    # ``<<Foo as Trait>::Bar>::method`` strips to ``Foo as Trait::Bar::method``
    # in the outer pass; the inner ``<Foo as Trait>::Bar`` is itself a
    # well-formed impl-block prefix.
    inner = _strip_impl_block_brackets(inner)
    return f"{inner}::{rest}"


# Legacy back-compat — some callers may import the constant directly.
_IMPL_BLOCK_RE = re.compile(r"^<([\w:]+)>::(.+)$")


def _qualified_from_demangled(name: str) -> str:
    """Strip argument list + trailing method qualifiers + any leading
    return type from a demangled C++ or Rust name. Returns the
    qualified-no-args form. Operator names, template args with embedded
    spaces, anonymous namespaces, trailing ``const`` / ``noexcept``
    qualifiers, lambda arg-type normalisation, Rust impl-block
    bracket-strip and Rust crate-hash strip all handled."""
    name = _strip_impl_block_brackets(
        _strip_rust_crate_hash(
            _normalise_lambda_args(name.strip())))
    changed = True
    while changed:
        changed = False
        for q in _METHOD_TRAILING_QUALS:
            if name.endswith(q):
                name = name[:-len(q)].rstrip()
                changed = True
                break
    paren_open = _find_arglist_open(name)
    head = name if paren_open < 0 else name[:paren_open].strip()
    depth = 0
    last_space_at_top = -1
    for i, ch in enumerate(head):
        if ch in "<([":
            depth += 1
        elif ch in ">)]" and depth > 0:
            depth -= 1
        elif ch == " " and depth == 0:
            last_space_at_top = i
    if last_space_at_top < 0:
        return head
    return head[last_space_at_top + 1:]


def _demangle_linkage_names(linkage_names: Iterable[str]) -> Dict[str, str]:
    """Batch-demangle DWARF ``DW_AT_linkage_name`` values via ``c++filt``.
    Returns mangled → demangled. Empty dict if c++filt is missing or
    if ``linkage_names`` is empty.

    The classifier uses this to also index subprograms under their
    canonical demangled spelling, because the spelling DWARF emits in
    ``DW_AT_name`` may differ from what ``gcov -m`` / ``nm --demangle``
    produce (e.g. DWARF ``<long unsigned int>`` vs gcov
    ``<unsigned long>`` — surfaced by snappy's ``DecompressBranchless``
    template instantiations in Inc 3c)."""
    seen = sorted({n for n in linkage_names if n})
    if not seen or not shutil.which("c++filt"):
        return {}
    from core.sandbox import run_trusted
    try:
        proc = run_trusted(
            ["c++filt"], input="\n".join(seen),
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    lines = proc.stdout.splitlines()
    if len(lines) != len(seen):
        return {}
    return dict(zip(seen, lines))


# DIE tags that introduce a C++ name-scope; subprogram DIEs nested under
# any of these get their ``namespace_path`` prefixed by the parent's name.
_SCOPE_TAGS = frozenset({
    "DW_TAG_namespace",
    "DW_TAG_class_type",
    "DW_TAG_structure_type",
    "DW_TAG_union_type",
})


def _parse_dwarf(binary_path: Path) -> Tuple[Dict[int, _SubprogramDIE], List[int]]:
    """Parse ``objdump --dwarf=info`` into:

      * ``subs``: DIE-offset → ``_SubprogramDIE`` for every DW_TAG_subprogram.
      * ``inline_instance_origins``: list of DIE offsets each
        DW_TAG_inlined_subroutine instance's ``DW_AT_abstract_origin`` points
        at (resolved against ``subs`` by the caller to get the inlined fn's
        name).

    Best-effort text parse; tolerates binutils version drift in formatting
    by anchoring on the DIE-offset header (``<depth><offset>:`` shape).
    """
    # objdump --dwarf=info on a multi-MB binary with full DWARF emits
    # 1-3 GB of text. ``_run`` would buffer all of it into Python memory
    # before parsing — OOM on real C++ targets (libLLVM, Chromium).
    # Stream line-by-line via ``_stream`` so peak memory stays bounded
    # to ``subs`` + ``inlines`` (a few MB at most). Default 600s timeout
    # is generous for the largest binaries we expect to see in /agentic.
    subs: Dict[int, _SubprogramDIE] = {}
    inlines: List[int] = []

    # DIE header: ``<depth><offset>: Abbrev Number: NN (DW_TAG_...)``
    die_re = re.compile(
        r"^\s*<(\d+)><([0-9a-fA-F]+)>:\s+Abbrev Number:\s*\d+\s*\((\w+)\)")
    # An attribute line looks like ``<<offset>>   DW_AT_<name>  : <value>``.
    attr_re = re.compile(r"DW_AT_(\w+)\s*:?\s*(.*?)\s*$")
    # Format: ``(indirect string, offset: 0xNNN): the_actual_name``. We
    # must skip past the parenthesised qualifier AND its trailing colon to
    # reach the real name. A loose ``[^:]+`` matched only up to the FIRST
    # colon (inside the paren) — capturing the offset by mistake.
    # gcc emits ``(indirect string, offset: 0xNNN): the_actual_name``;
    # clang emits ``(indexed string: 0xN): the_actual_name``. Both are
    # parenthesised qualifiers followed by ``):`` then the real name — match
    # either so the parser doesn't silently miss every name in clang DWARF
    # (adversarial-review finding A: clang-built fixtures classified the
    # inlined_only case wrong because the parser couldn't read the name).
    # Capture EVERYTHING after the ``):`` qualifier to end-of-line — a
    # tighter ``(\S+)`` truncated C++ template names containing internal
    # whitespace (``DecompressBranchless<long unsigned int>`` clipped to
    # ``DecompressBranchless<long``), which then mis-classified as absent
    # because the qualified-name lookup couldn't find them (snappy Inc 3c
    # followup).
    name_indirect_re = re.compile(
        r"\(in(?:direct|dexed) string[^)]*\):\s*(.+?)\s*$")
    # DW_AT_abstract_origin emits an offset that may be ``<0xNN>`` or bare hex.
    aorig_re = re.compile(r"<0x([0-9a-fA-F]+)>")
    # DW_AT_low_pc is an address.
    addr_re = re.compile(r"0x([0-9a-fA-F]+)")

    cur_offset: Optional[int] = None
    cur_die: Optional[_SubprogramDIE] = None
    cur_is_inline_instance = False
    # Namespace-tracking state for C++ qualified-name resolution
    # (Inc 3c on snappy). ``depth_to_name`` maps DIE-depth → enclosing
    # scope name. When entering a DW_TAG_namespace/class at depth D we
    # record its name there; deeper subprogram DIEs read the stack to
    # build ``snappy::Bits`` style prefixes. We separately track the
    # pending scope DIE so we can defer assigning its name until
    # DW_AT_name is parsed (the header arrives before the attributes).
    depth_to_name: Dict[int, str] = {}
    cur_scope_depth: Optional[int] = None
    cur_scope_name: str = ""

    def _commit_scope():
        # Persist the pending scope's name into the depth map (anonymous
        # namespace falls back to the C++ convention). Then clear it.
        nonlocal cur_scope_depth, cur_scope_name
        if cur_scope_depth is not None:
            depth_to_name[cur_scope_depth] = (
                cur_scope_name or "(anonymous namespace)")
        cur_scope_depth = None
        cur_scope_name = ""

    def _flush():
        nonlocal cur_die, cur_offset, cur_is_inline_instance
        _commit_scope()
        if cur_die is not None and cur_offset is not None:
            # Store even nameless DIEs — they may carry a DW_AT_specification
            # we resolve to a name in the post-pass. Drop only if BOTH the
            # name and specification are absent (nothing recoverable).
            if cur_die.name or cur_die.specification is not None:
                subs[cur_offset] = cur_die
        cur_die = None
        cur_offset = None
        cur_is_inline_instance = False

    def _current_namespace_path(die_depth: int) -> str:
        # Concatenate scopes at depths strictly less than this DIE's depth.
        # Stale entries from sibling branches are pruned lazily on depth-
        # decrease (see header handler below).
        parts = [depth_to_name[d] for d in sorted(depth_to_name)
                 if d < die_depth]
        return "::".join(parts)

    for line in _stream(
            ["objdump", "--dwarf=info", str(binary_path)], timeout=600):
        m = die_re.match(line)
        if m:
            _flush()
            die_depth = int(m.group(1))
            # Pop stale namespace entries from sibling subtrees we've left.
            for d in [d for d in depth_to_name if d >= die_depth]:
                depth_to_name.pop(d, None)
            tag = m.group(3)
            if tag == "DW_TAG_subprogram":
                cur_offset = int(m.group(2), 16)
                cur_die = _SubprogramDIE(
                    namespace_path=_current_namespace_path(die_depth))
            elif tag == "DW_TAG_inlined_subroutine":
                cur_is_inline_instance = True
            elif tag in _SCOPE_TAGS:
                cur_scope_depth = die_depth
                cur_scope_name = ""
            continue

        if cur_die is not None:
            ma = attr_re.search(line)
            if not ma:
                continue
            attr, value = ma.group(1), ma.group(2)
            if attr == "name":
                # Either inline ``: foo`` or ``(indirect string, ...): foo``.
                ind = name_indirect_re.search(value)
                cur_die.name = (ind.group(1) if ind else value).strip()
            elif attr == "linkage_name":
                ind = name_indirect_re.search(value)
                linkage = (ind.group(1) if ind else value).strip()
                cur_die.linkage_name = linkage
                # Legacy fallback: if DW_AT_name was missing, the mangled
                # linkage name was previously used as the local name.
                # Keep that path so existing behaviour is unchanged when
                # no demangler is available.
                if not cur_die.name:
                    cur_die.name = linkage
            elif attr == "low_pc":
                ma2 = addr_re.search(value)
                if ma2:
                    cur_die.low_pc = int(ma2.group(1), 16)
            elif attr == "inline":
                # DW_AT_inline integer code, prefixing a human description:
                #   0  — not inlined
                #   1  — DW_INL_inlined (auto, actually inlined)
                #   2  — DW_INL_declared_not_inlined (had ``inline`` keyword
                #        but the compiler chose NOT to inline)
                #   3  — DW_INL_declared_inlined (declared inline AND inlined)
                # Only 1 and 3 mean "an inlined instance exists somewhere".
                # The prior substring match ``"inlined" in value`` matched
                # the human-readable text of code 2 too ("declared as inline
                # but not inlined") — asymmetrically safe (elevates absent →
                # inlined rather than dropping findings) but pollutes the
                # inlined-vs-absent split. Parse the integer code instead.
                v = value.lstrip()
                if v.startswith(("1", "3")) and not v.startswith(("10", "30")):
                    cur_die.has_inline_marker = True
            elif attr == "specification":
                # Definition pointing back to its declaration DIE; resolved
                # in the post-pass to inherit name + namespace_path.
                mo = aorig_re.search(value)
                if mo:
                    cur_die.specification = int(mo.group(1), 16)

        elif cur_scope_depth is not None:
            ma = attr_re.search(line)
            if ma and ma.group(1) == "name":
                ind = name_indirect_re.search(ma.group(2))
                cur_scope_name = (
                    ind.group(1) if ind else ma.group(2)).strip()

        elif cur_is_inline_instance:
            ma = attr_re.search(line)
            if ma and ma.group(1) == "abstract_origin":
                mo = aorig_re.search(ma.group(2))
                if mo:
                    inlines.append(int(mo.group(1), 16))

    _flush()

    # Resolve DW_AT_specification: definition DIEs inherit name +
    # namespace_path + linkage_name from their declaration sibling
    # (the C++ idiom — inlined templates emit a top-level definition
    # pointing back at the in-class declaration; without this, every
    # C++ inline method classifies as ``absent`` because the
    # DW_AT_inline=inlined definition has no name of its own).
    # ``linkage_name`` inheritance is what lets c++filt canonical-name
    # aliasing reach DIEs whose DWARF ``DW_AT_name`` uses a different
    # type-spelling than ``gcov -m`` / ``nm --demangle`` produce
    # (``long unsigned int`` vs ``unsigned long`` in snappy Inc 3c
    # followup).
    for die in subs.values():
        if die.specification is None:
            continue
        spec = subs.get(die.specification)
        if spec is None:
            continue
        if not die.name and spec.name:
            die.name = spec.name
        if not die.namespace_path and spec.namespace_path:
            die.namespace_path = spec.namespace_path
        if not die.linkage_name and spec.linkage_name:
            die.linkage_name = spec.linkage_name

    return subs, inlines


# ---------------------------------------------------------------------------
# Symbol-only tier (stripped-binary fallback)
# ---------------------------------------------------------------------------

def _dynamic_nm_symbols(binary_path: Path) -> Dict[str, int]:
    """``nm -D`` — dynamic symbol table. Fully-stripped binaries have
    NO plain-nm symbols (the ``.symtab`` section is removed), but
    ``.dynsym`` survives (the dynamic linker needs it). For a shared
    library, this exposes the entire public API. Same demangle +
    bare-name + qualified-no-args indexing as ``_nm_symbols``."""
    out = _run(["nm", "-D", "--demangle", str(binary_path)])
    if not out:
        out = _run(["nm", "-D", str(binary_path)])
    syms: Dict[str, int] = {}
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) >= 3 and len(parts[1]) == 1 and parts[1] in "tTwW":
            try:
                addr = int(parts[0], 16)
            except ValueError:
                continue
            full = parts[2].strip()
            syms[full] = addr
            qualified = full.split("(", 1)[0] if "(" in full else full
            qualified = _strip_ipa_suffix(qualified)
            if qualified and qualified != full:
                syms.setdefault(qualified, addr)
            bare = (qualified.rsplit("::", 1)[-1]
                    if "::" in qualified else qualified)
            if bare and bare not in (full, qualified):
                syms.setdefault(bare, addr)
    return syms


def _classify_symbol_only(
    source_function_names: Iterable[str],
    binary_path: Path,
    build_id: str,
    nm_syms: Dict[str, int],
) -> Dict[str, "BinaryOracleWitness"]:
    """Classify against an nm-only symbol table (no DWARF). For
    fully-stripped binaries, plain ``nm`` returns nothing — we union
    with ``nm -D`` (dynamic symbol table, survives stripping) so the
    operator at least gets reachability evidence for exported library
    API functions.

    Emits ``symbol_present`` when the name is in either symbol table,
    ``absent`` otherwise. Each witness is tagged ``tier="symbol_only"``
    so downstream consumers know not to license suppression on it (a
    function absent from nm in a stripped binary could still be
    inlined into a surviving caller — DWARF would have caught it;
    we can't)."""
    # Union of static + dynamic symbol tables.
    sym_table = dict(_dynamic_nm_symbols(binary_path))
    sym_table.update(nm_syms)  # plain nm wins on collisions
    bp = str(binary_path)
    out: Dict[str, BinaryOracleWitness] = {}
    for name in source_function_names:
        cls: Classification = (
            "symbol_present" if name in sym_table else "absent")
        out[name] = BinaryOracleWitness(
            classification=cls,
            build_id=build_id,
            binary_path=bp,
            address=sym_table.get(name),
            tier="symbol_only",
        )
    return out


# ---------------------------------------------------------------------------
# Classifier entry point
# ---------------------------------------------------------------------------

def classify_binary_evidence(
    source_function_names: Iterable[str],
    binary_path: Path,
) -> Dict[str, BinaryOracleWitness]:
    """Classify each ``source_function_names`` entry against ``binary_path``.

    Returns a name → ``BinaryOracleWitness`` mapping for every input name.
    Names not resolvable either way get ``absent`` (the DCE case).

    The binary MUST have DWARF. A stripped binary (no DWARF subprograms
    found) returns an empty mapping; the operator-visible skip is the
    caller's responsibility (the witness is consumed at the reachability
    layer in Inc 2, which logs the skip).
    """
    binary_path = Path(binary_path)
    if not binary_path.is_file():
        return {}

    if not shutil.which("nm") or not shutil.which("objdump"):
        logger.warning("binary_oracle: nm / objdump unavailable; classifier "
                       "cannot run")
        return {}

    build_id = read_build_id(binary_path) or ""
    nm_syms = _nm_symbols(binary_path)
    subs, inline_origins = _parse_dwarf(binary_path)

    if not subs:
        # Stripped (or DWARF-less) binary — fall back to symbol-only
        # tier. We can still answer ``symbol_present`` vs ``absent``
        # from the nm symbol table alone; we cannot distinguish
        # ``inlined`` (would need DW_TAG_inlined_subroutine instances)
        # or ``folded`` (would need DW_AT_low_pc collisions across
        # source names). Verdicts in this tier are conservative —
        # the inventory's ``earns_suppression`` flag downgrades to
        # False if ANY contributing binary is stripped (a function
        # ``absent`` here might really be inlined into a surviving
        # caller; suppressing on that risks false negatives).
        logger.info("binary_oracle: no DWARF subprograms in %s; "
                    "falling back to symbol-only tier",
                    binary_path)
        return _classify_symbol_only(
            source_function_names, binary_path, build_id, nm_syms,
        )

    # Reverse-index DWARF subprograms by both qualified and bare names.
    # Qualified is the primary key (matches the form ``gcov -m`` and
    # ``nm --demangle`` emit for C++); bare-name is kept as a fallback
    # so callers that don't know the namespace still find C functions.
    # ALSO index under the demangled ``DW_AT_linkage_name`` form — this
    # gives canonical spelling that matches gcov even when DWARF's
    # ``DW_AT_name`` uses a different type-spelling (e.g. ``long
    # unsigned int`` vs ``unsigned long``; Inc 3c snappy fix).
    by_qualified: Dict[str, List[_SubprogramDIE]] = {}
    by_bare: Dict[str, List[_SubprogramDIE]] = {}
    demangled_map = _demangle_linkage_names(
        d.linkage_name for d in subs.values() if d.linkage_name)
    for die in subs.values():
        q = die.qualified_name
        if q:
            by_qualified.setdefault(q, []).append(die)
        if die.name and die.name != q:
            by_bare.setdefault(die.name, []).append(die)
        if die.linkage_name:
            demangled = demangled_map.get(die.linkage_name)
            if demangled:
                canonical = _qualified_from_demangled(demangled)
                if canonical and canonical != q:
                    by_qualified.setdefault(canonical, []).append(die)

    # Names actually inlined somewhere. Two sources:
    #   (a) DW_TAG_inlined_subroutine instances whose abstract_origin
    #       points back at a DW_TAG_subprogram — function was inlined
    #       into a caller that survived. Normal case.
    #   (b) DW_TAG_subprogram with DW_AT_inline=inlined — compiler
    #       marked the function as always-inlined; the absence of a
    #       concrete instance means the body was empty or fully folded
    #       into its caller (e.g. zlib's ``tr_static_init``). Without
    #       this, such functions misclassify as ``absent``.
    # In both cases we index by the qualified name so C++ measurement
    # against gcov -m / nm --demangle output hits — Inc 3c on snappy
    # showed every ``snappy::Bits::Log2Floor`` style call misclassifying
    # as absent without namespace qualification.
    inlined_names: Set[str] = set()
    for off in inline_origins:
        die = subs.get(off)
        if die and die.qualified_name:
            inlined_names.add(die.qualified_name)
        if die and die.linkage_name:
            demangled = demangled_map.get(die.linkage_name)
            if demangled:
                canonical = _qualified_from_demangled(demangled)
                if canonical:
                    inlined_names.add(canonical)
    for die in subs.values():
        if die.has_inline_marker:
            if die.qualified_name:
                inlined_names.add(die.qualified_name)
            if die.linkage_name:
                demangled = demangled_map.get(die.linkage_name)
                if demangled:
                    canonical = _qualified_from_demangled(demangled)
                    if canonical:
                        inlined_names.add(canonical)

    # Fold detection: two distinct source names mapping to the same address.
    by_addr: Dict[int, Set[str]] = {}
    for q, dies in by_qualified.items():
        for die in dies:
            if die.low_pc is not None:
                by_addr.setdefault(die.low_pc, set()).add(q)
    folded_names = {n for names in by_addr.values() if len(names) > 1
                    for n in names}

    out: Dict[str, BinaryOracleWitness] = {}
    bp = str(binary_path)
    for name in source_function_names:
        # Qualified lookup is the primary path; bare-name falls back so
        # plain-C callers (no namespace to provide) still hit.
        dies = by_qualified.get(name) or by_bare.get(name, [])
        addr = next((d.low_pc for d in dies if d.low_pc is not None), None)
        in_nm = name in nm_syms

        if name in folded_names:
            cls: Classification = "folded"
        elif in_nm or addr is not None:
            # ``addr is not None`` = at least one DWARF subprogram DIE has
            # a concrete ``DW_AT_low_pc``. Internal-linkage helpers
            # (anonymous-namespace, ``static``) emit code but no nm
            # symbol; without surfacing DWARF location they misclassify
            # as ``absent`` (snappy Inc 3c FPs on ``DecompressBranchless
            # <char*>``, both ``DecompressAllTags`` template variants).
            cls = "symbol_present"
        elif name in inlined_names:
            cls = "inlined"
        else:
            cls = "absent"

        out[name] = BinaryOracleWitness(
            classification=cls,
            build_id=build_id,
            binary_path=bp,
            address=addr if addr is not None else nm_syms.get(name),
            tier="full",
        )
    return out


# ---------------------------------------------------------------------------
# Inventory enrichment — Inc 2 (surface-only)
# ---------------------------------------------------------------------------

# Native-compiled languages where DWARF + the symbol table give a meaningful
# answer. Others (Python / JS / Java / C#) skip — binary_oracle isn't the
# right oracle for them.
_NATIVE_LANGUAGES = frozenset({"c", "cpp", "c++", "rust", "go"})


# Priority for combining per-binary verdicts: alive-in-any wins. The
# combined classification is the strongest evidence across all analysed
# binaries — symbol_present beats folded beats inlined beats absent.
# A function is ``absent`` ONLY when EVERY analysed binary lacks it
# (no symbol, no inlined-subroutine instance) — this is what makes
# multi-binary suppression sound for hybrid targets (--target-kind=
# hybrid: library + application, both shipped). Picking the wrong
# single binary stops being a footgun.
_CLASS_PRIORITY: Dict[str, int] = {
    "symbol_present": 4,
    "folded":         3,
    "inlined":        2,
    "absent":         1,
}


def _combine_verdicts(
    entries: Iterable[Tuple[str, str]],
) -> Classification:
    """Combine per-binary classifications into one. Each entry is a
    ``(classification, tier)`` pair where tier is ``"full"`` (DWARF +
    nm; high confidence) or ``"symbol_only"`` (stripped fallback;
    weaker — symbols can be re-exports / weak aliases / .symver
    indirections without source evidence).

    Tier weighting: when ANY full-tier entry exists, only full-tier
    entries are considered. This stops a symbol_only "symbol_present"
    (from a stripped binary's nm output that picked up an unrelated
    weak alias) from masking a full-tier "absent" verdict — the
    full-DWARF evidence is authoritative when it disagrees with the
    symbol-only evidence. Among same-tier entries the highest-priority
    classification wins (alive-in-any). Empty input ⇒ ``absent``."""
    pairs = list(entries)
    if not pairs:
        return "absent"
    # Unknown-classification warn (adversarial review Agent D P2). The
    # priority dict's ``.get(v, 0)`` silently treats unknown values as
    # worse than ``absent`` (priority 1). If a new classification ever
    # lands without a priority entry, every binary's verdict would
    # silently demote to "worse than absent" — log loudly instead of
    # silently swallowing.
    for c, _ in pairs:
        if c not in _CLASS_PRIORITY:
            logger.warning(
                "binary_oracle: unknown classification %r — no priority "
                "entry; falling back to lowest priority. Add it to "
                "_CLASS_PRIORITY.", c,
            )
    full = [c for c, t in pairs if t == "full"]
    pool = full if full else [c for c, _ in pairs]
    return max(pool, key=lambda v: _CLASS_PRIORITY.get(v, 0))


def enrich_inventory_with_binary_oracle(
    inventory: Dict,
    binaries,
) -> Dict[str, int]:
    """Annotate each native-language inventory item with its binary-oracle
    classification, plus a top-level summary on the inventory itself.

    ``binaries`` may be a single ``Path`` / ``str`` (legacy single-binary
    call) or a sequence (multi-binary; the common case for
    ``--target-kind=hybrid`` deployments where library + application are
    BOTH part of the shipping surface). Each binary is classified
    independently and the per-source-function results are combined:

      - **alive in any binary** ⇒ combined verdict is the strongest
        (symbol_present > folded > inlined)
      - **absent from every binary** ⇒ combined verdict is ``absent``
        — and ONLY then can the downstream chokepoint hard-suppress

    Storage shape on each item::

      metadata.binary_oracle = {
        "classification": "absent",   # combined verdict — what consumers read
        "binaries": [
          {"path": "...", "build_id": "...", "classification": "absent",
           "address": null},
          ...                          # one entry per analysed binary
        ],
      }

    Top-level inventory summary::

      inventory.binary_oracle = {
        "binaries": [{"path": "...", "build_id": "..."}, ...],
        "counts": {"classified": N, "symbol_present": N, "inlined": N,
                   "absent": N, "folded": N},
        "skipped_non_native": M,
        "earns_suppression": True,
      }

    Non-native items (Python / JS / Java / C#) are skipped — binary_oracle
    isn't the right oracle for them. Returns the counts dict so callers
    can log / report what was classified.
    """
    # Normalise: single path becomes a list of one.
    if isinstance(binaries, (str, Path)):
        binary_paths = [Path(binaries)]
    else:
        binary_paths = [Path(b) for b in binaries]

    counts = {"classified": 0, "symbol_present": 0, "inlined": 0,
              "absent": 0, "folded": 0, "skipped_non_native": 0}

    binary_paths = [p for p in binary_paths if p.is_file()]
    if not binary_paths:
        logger.info("binary_oracle: no usable binaries; skipping enrichment")
        return counts

    # Collect native function names per file. Track (file_idx, item_idx)
    # back to each name so we can write the combined verdict without re-
    # scanning.
    targets: List[Tuple[int, int, str]] = []
    files = inventory.get("files") or []
    for fi, f in enumerate(files):
        lang = (f.get("language") or "").lower()
        if lang not in _NATIVE_LANGUAGES:
            for it in f.get("items") or []:
                if it.get("kind", "function") == "function":
                    counts["skipped_non_native"] += 1
            continue
        for ii, item in enumerate(f.get("items") or []):
            if item.get("kind", "function") != "function":
                continue
            name = item.get("name")
            if isinstance(name, str) and name:
                targets.append((fi, ii, name))

    if not targets:
        return counts

    names = sorted({t[2] for t in targets})

    # Classify once per binary. Each classify_binary_evidence call shells
    # to nm + objdump (~1-15s per binary depending on size); for the
    # typical 1-3 binary hybrid case the cost is bounded.
    per_binary: List[Tuple[Path, str, Dict[str, "BinaryOracleWitness"]]] = []
    for bp in binary_paths:
        verdicts = classify_binary_evidence(names, bp)
        build_id = read_build_id(bp) or ""
        per_binary.append((bp, build_id, verdicts))

    if not any(verdicts for _, _, verdicts in per_binary):
        logger.info(
            "binary_oracle: no binary produced verdicts (stripped? missing "
            "DWARF? source/binary mismatch?); skipping enrichment")
        return counts

    # Source-coverage floor (adversarial review P0-D-1: hostile-ELF
    # attack defense). A binary whose DWARF/symbols match almost none
    # of the source-side function names is overwhelmingly likely the
    # WRONG binary — a stray ELF in the target tree (vendored testdata,
    # prior-project leftover, or a maliciously planted artefact whose
    # DWARF points to unrelated code). Without this floor, an unrelated
    # binary returns "absent" for every source function (no match in
    # foreign DWARF) and downstream chokepoints silently suppress every
    # native finding.
    #
    # Two refinements that make the floor decisive against the
    # smartest attacker shape (planted binary with ``main`` to inflate
    # the match rate against small targets):
    #   1. Exclude universally-common boilerplate names from the
    #      candidate count — ``main`` exists in every C program and
    #      a planted binary always has its own ``main``.
    #   2. Require an absolute minimum of MATCHED names (so a 3-function
    #      project doesn't pass with a single boilerplate hit).
    SRC_COVERAGE_FLOOR = 0.05
    SRC_COVERAGE_MIN_MATCHED = 3
    # The floor only kicks in once the source has enough non-boilerplate
    # names to make the planted-binary attack realistic. For a tiny
    # one-file fixture (a handful of functions) the floor would reject
    # legitimate small targets — and the planted-binary attack on a
    # 3-function project isn't a meaningful operator scenario anyway
    # (an attacker who can plant code in the target tree has bigger
    # vectors). Real /agentic targets have dozens-to-thousands of
    # functions and the floor's signal is strong there.
    SRC_FLOOR_MIN_PROJECT_NAMES = 8
    _BOILERPLATE_NAMES = frozenset({
        "main", "_start", "_init", "_fini",
        "__libc_csu_init", "__libc_csu_fini",
        "__do_global_dtors_aux", "register_tm_clones",
        "deregister_tm_clones", "frame_dummy",
    })
    project_names = [n for n in names if n not in _BOILERPLATE_NAMES]
    n_project = len(project_names)
    kept: List[Tuple[Path, str, Dict[str, "BinaryOracleWitness"]]] = []
    for bp, build_id, verdicts in per_binary:
        if not verdicts:
            kept.append((bp, build_id, verdicts))
            continue
        # "Matched" = the binary has *some* evidence (not absent),
        # excluding universally-common boilerplate names that say
        # nothing about whether this binary is from this source tree.
        matched = sum(
            1 for n in project_names
            if (w := verdicts.get(n)) is not None
            and w.classification != "absent"
        )
        ratio = matched / n_project if n_project else 0.0
        # Only enforce the floor on full-tier evidence (symbol-only
        # binaries systematically under-match because they can't see
        # inlined-only or DWARF-only names; their earns_suppression
        # downgrade is the safety net) and only on projects wide
        # enough for the floor to be meaningful.
        any_full = any(w.tier == "full" for w in verdicts.values())
        if (any_full
                and n_project >= SRC_FLOOR_MIN_PROJECT_NAMES
                and (matched < SRC_COVERAGE_MIN_MATCHED
                     or ratio < SRC_COVERAGE_FLOOR)):
            logger.warning(
                "binary_oracle: dropping %s — only %d of %d project source "
                "names matched (%.1f%%, floor %.0f%% / min %d). Likely the "
                "WRONG binary for this target (unrelated build artefact, "
                "vendored test binary, or planted ELF). Pass --binary "
                "explicitly to override.",
                bp.name, matched, n_project, ratio * 100,
                SRC_COVERAGE_FLOOR * 100, SRC_COVERAGE_MIN_MATCHED,
            )
            continue
        kept.append((bp, build_id, verdicts))
    per_binary = kept
    if not per_binary:
        logger.warning(
            "binary_oracle: all binaries dropped by source-coverage floor; "
            "skipping enrichment")
        return counts

    # Combine + annotate. The combined classification is what downstream
    # consumers (reach_witness, /codeql autonomous_analyzer, /validate
    # demoter) read; per-binary detail is preserved for audit / debug.
    # Track whether ANY contributing binary was symbol-only (stripped);
    # downgrades the inventory's earns_suppression flag conservatively.
    any_symbol_only = any(
        any(w.tier == "symbol_only" for w in verdicts.values())
        for _, _, verdicts in per_binary
    )
    for fi, ii, name in targets:
        per_binary_entries: List[Dict[str, object]] = []
        for bp, build_id, verdicts in per_binary:
            w = verdicts.get(name)
            if w is None:
                continue
            per_binary_entries.append({
                "path":           str(bp),
                "build_id":       build_id,
                "classification": w.classification,
                "address":        w.address,
                "tier":           w.tier,
            })
        if not per_binary_entries:
            continue
        combined = _combine_verdicts(
            (entry["classification"], entry["tier"])
            for entry in per_binary_entries)
        # NB: ``setdefault('metadata', {})`` returns the *existing* value
        # if the key is present — even when that value is ``None``. A
        # parser-emitted ``metadata: None`` would then crash on item
        # assignment. Initialise / replace any non-dict explicitly.
        item = files[fi]["items"][ii]
        meta = item.get("metadata")
        if not isinstance(meta, dict):
            meta = {}
            item["metadata"] = meta
        meta["binary_oracle"] = {
            "classification": combined,
            "binaries":       per_binary_entries,
        }
        counts["classified"] += 1
        counts[combined] = counts.get(combined, 0) + 1

    # Per-binary evidence tier — exposed so consumers (and operator
    # audits) can see WHICH binaries fell back to symbol-only mode.
    # Determined by inspecting the first verdict from each binary (all
    # verdicts from one classify call share a tier).
    binaries_with_tier: List[Dict[str, object]] = []
    for bp, bid, verdicts in per_binary:
        first = next(iter(verdicts.values()), None)
        # When a binary produced zero verdicts (corrupt ELF, sandbox
        # killed mid-classify, no source-name overlap at all), record
        # ``tier="unknown"`` rather than misleadingly defaulting to
        # ``full`` — full implies "full-DWARF evidence ran cleanly",
        # which is wrong here (adversarial review Agent A P2).
        binaries_with_tier.append({
            "path":     str(bp),
            "build_id": bid,
            "tier":     first.tier if first else "unknown",
        })

    inventory["binary_oracle"] = {
        "binaries": binaries_with_tier,
        "counts": {k: v for k, v in counts.items() if k != "skipped_non_native"},
        "skipped_non_native": counts["skipped_non_native"],
        # Soundness tier — downstream consumers may hard-suppress on
        # ``absent``. Evidence base:
        #
        #   * 1952/1952 absent verdicts correct across 6 corpora the
        #     classifier was iteratively tuned against (synthetic,
        #     zlib, libsodium, snappy, leveldb, regex-rust). This is a
        #     CONSISTENCY claim, not a generalization estimate —
        #     classifier patches followed from corpus FPs, so the
        #     number is a fit, not a hold-out.
        #
        #   * 187/187 absent verdicts correct on a held-out corpus
        #     (zstd v1.5.6) with NO classifier tuning permitted on
        #     its output. Rule-of-three 95% UB miss rate ≤1.6% on
        #     first-contact-with-unseen-data — the actual estimator
        #     of out-of-sample behaviour.
        #
        # The earned property is also CONDITIONAL on full-DWARF
        # evidence — a stripped binary in the analysed set means we
        # can't distinguish ``inlined`` from ``absent``, so suppression
        # could license a false negative. Downgrade conservatively
        # when ANY contributing binary is symbol-only (E1 stripped-
        # binary fallback).
        "earns_suppression": not any_symbol_only,
        # Surfaced for operator-visible evidence-tier reporting.
        "any_symbol_only": any_symbol_only,
    }
    return counts


__all__ = [
    "BinaryOracleWitness",
    "classify_binary_evidence",
    "enrich_inventory_with_binary_oracle",
    "read_build_id",
]
