"""Zero-length loop-entry detection over generated AArch64 assembly.

Mechanical, detection-grade check for the class observed in OpenSSL's
AES-CBC-HMAC perlasm kernels (``crypto/aes/asm/aes-sha1-armv8.pl``,
``aes-sha256-armv8.pl``): a loop whose trip counter derives from a
caller-supplied length (``lsr x10, x2, 4`` — bytes to blocks) is
reached without any zero test on the counter, and the loop body stores
output *before* the first in-body zero test of that counter. A zero
length therefore processes one block, and the ``sub x10, x10, 1`` /
``cbz`` sequence wraps the counter to 2**64-1 — unbounded processing
over attacker-adjacent memory.

The conforming sibling shape (``aes-sha512-armv8.pl``) is the leading
zero guard: ``lsr x11, x2, #4`` followed by ``cbz x11, .Lret`` before
any dispatch — that shape is recognised and suppresses the lead.

Scope and honesty:

- AArch64 GAS syntax only — the flavour of the two observed findings.
  Other ISAs pass through with zero findings (never a crash).
- Linear-scan and branch-insensitive except for one modelled shape:
  a ``cmp C, #N`` + ``b.lt <label>`` magnitude dispatch marks the
  fall-through region as guarded (``C >= N``) and the branch-target
  region as the zero-inclusive short path.
- Findings are detection-grade leads pointing at exact labels/lines
  for LLM or human review of the flagged kernel. They are never
  verdict-grade and never promote on their own (fail_open_roles
  doctrine: a single heuristic source cannot classify code as
  vulnerable).

Routing: :func:`scan_inventory_asm` walks ``language == "asm-generated"``
inventory records (emitted by :mod:`core.inventory.perlasm`) and
returns findings in the mechanical-detector shape, merged into
``mechanical-findings.json`` by the orchestrator exactly like the
``semantic_consistency`` precedent.
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

DETECTOR_NAME = "asm_zero_len_loop"

# Generated .S read cap — mirrors the inventory builder's bounded read.
_MAX_ASM_BYTES = 8 * 1024 * 1024

# Function boundaries: column-0 labels, local (.L*) and numeric labels
# excluded — byte-for-byte the AsmExtractor routine rule, so findings
# land on the same units the inventory enumerates.
_FUNC_LABEL_RE = re.compile(r"^([A-Za-z_][\w.$]*):")
# All label definitions (including .L locals) — loop targets.
_ANY_LABEL_RE = re.compile(r"^([A-Za-z_.][\w.$]*):")
_INSN_RE = re.compile(r"^\s+([a-z][\w.]*)(?:\s+(.*))?$")
_REG_RE = re.compile(r"^[xw]\d+$")

# AArch64 general-purpose argument registers: a counter derived from
# one of these (directly, or through one `mov` copy) is derived from a
# caller-controlled value — the "trip count derives from a length"
# signal. x2 is the `len` argument in the observed kernels.
_ARG_REGS = frozenset(
    {f"x{i}" for i in range(8)} | {f"w{i}" for i in range(8)}
)

_STORE_PREFIX = "st"  # st1..st4, str, strb, strh, stp, stur, stlr, ...
_ZERO_BRANCHES = frozenset({"cbz", "cbnz"})
# cmp C, #N + one of these => magnitude dispatch (target gets C < N).
_LT_BRANCHES = frozenset({"b.lt", "b.ls", "b.le", "blt", "bls", "ble"})
_EQ_BRANCHES = frozenset({"b.eq", "b.ne", "beq", "bne"})


def _strip_comment(line: str, in_block: bool) -> tuple[str, bool]:
    """Remove ``//`` and ``/* ... */`` comments; track block state."""
    out: list[str] = []
    i = 0
    while i < len(line):
        if in_block:
            end = line.find("*/", i)
            if end == -1:
                return "".join(out), True
            i = end + 2
            in_block = False
            continue
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block = True
            i += 2
            continue
        out.append(line[i])
        i += 1
    return "".join(out), in_block


def _parse(asm_text: str) -> list[dict]:
    """Tokenise into label / insn records with 1-based line numbers."""
    records: list[dict] = []
    in_block = False
    for lineno, raw in enumerate(asm_text.split("\n"), start=1):
        line, in_block = _strip_comment(raw, in_block)
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped.startswith("#") or stripped.startswith("."):
            # cpp directive / assembler directive — but a column-0
            # ``.Llabel:`` is a label, not a directive.
            m = _ANY_LABEL_RE.match(line)
            if m:
                records.append(
                    {"kind": "label", "name": m.group(1), "line": lineno}
                )
            continue
        m = _ANY_LABEL_RE.match(line)
        if m:
            records.append(
                {"kind": "label", "name": m.group(1), "line": lineno}
            )
            rest = line[m.end():]
            im = _INSN_RE.match(" " + rest)
            if im:
                records.append({
                    "kind": "insn", "mn": im.group(1),
                    "ops": _split_ops(im.group(2)), "line": lineno,
                })
            continue
        im = _INSN_RE.match(line)
        if im:
            records.append({
                "kind": "insn", "mn": im.group(1),
                "ops": _split_ops(im.group(2)), "line": lineno,
            })
    return records


def _split_ops(ops: str | None) -> list[str]:
    if not ops:
        return []
    return [o.strip() for o in ops.split(",") if o.strip()]


def _imm(op: str) -> int | None:
    op = op.lstrip("#")
    try:
        return int(op, 0)
    except ValueError:
        return None


def _function_regions(records: list[dict]) -> list[tuple[str, int, int]]:
    """(name, start_idx, end_idx) spans split on non-local labels."""
    bounds = [
        (i, r["name"]) for i, r in enumerate(records)
        if r["kind"] == "label" and _FUNC_LABEL_RE.match(r["name"] + ":")
        and not r["name"].startswith(".L")
    ]
    regions = []
    for n, (idx, name) in enumerate(bounds):
        end = bounds[n + 1][0] if n + 1 < len(bounds) else len(records)
        regions.append((name, idx, end))
    return regions


def _is_zero_test(rec: dict, counter: str) -> bool:
    """True when this insn observes ``counter == 0`` (flags or branch)."""
    mn, ops = rec["mn"], rec["ops"]
    if mn in _ZERO_BRANCHES and ops and ops[0] == counter:
        return True
    if mn == "cmp" and len(ops) >= 2 and ops[0] == counter:
        return _imm(ops[1]) == 0
    # subs on the counter sets flags off the new value — the classic
    # decrement-and-test. (Plain `sub` does not.)
    return mn == "subs" and len(ops) >= 2 and ops[0] == counter and ops[1] == counter


def _is_decrement(rec: dict, counter: str) -> bool:
    mn, ops = rec["mn"], rec["ops"]
    return (
        mn in ("sub", "subs")
        and len(ops) >= 3
        and ops[0] == counter
        and ops[1] == counter
        and _imm(ops[2]) == 1
    )


def _length_counters(records: list[dict], start: int, end: int,
                     ) -> dict[str, list[int]]:
    """Counters derived from an argument register via ``lsr``.

    One level of ``mov`` copy is chased (``mov x11, x2`` then
    ``lsr x12, x11, 6`` still counts as length-derived).
    """
    copies: dict[str, str] = {}
    out: dict[str, list[int]] = {}
    for i in range(start, end):
        rec = records[i]
        if rec["kind"] != "insn":
            continue
        ops = rec["ops"]
        if rec["mn"] == "mov" and len(ops) == 2 and _REG_RE.match(ops[0] or "") \
                and ops[1] in _ARG_REGS:
            copies[ops[0]] = ops[1]
        if rec["mn"] == "lsr" and len(ops) >= 3 and _REG_RE.match(ops[0] or ""):
            src = ops[1]
            if src in _ARG_REGS or src in copies:
                out.setdefault(ops[0], []).append(i)
    return out


def _find_loops(records: list[dict], start: int, end: int,
                label_at: dict[str, int]) -> list[dict]:
    """Backward conditional branches => candidate loops."""
    loops = []
    for i in range(start, end):
        rec = records[i]
        if rec["kind"] != "insn":
            continue
        mn, ops = rec["mn"], rec["ops"]
        target = None
        ctr_hint = None
        if mn == "cbnz" and len(ops) == 2:
            target, ctr_hint = ops[1], ops[0]
        elif mn in _EQ_BRANCHES and len(ops) == 1:
            target = ops[0]
        if target is None:
            continue
        t_idx = label_at.get(target)
        if t_idx is None or not (start <= t_idx < i):
            continue
        loops.append({
            "label": target, "start": t_idx, "branch": i,
            "ctr_hint": ctr_hint,
        })
    return loops


def _guarded_before(records: list[dict], counter: str, lo: int, hi: int,
                    loop_start: int, label_at: dict[str, int],
                    ) -> tuple[bool, str | None]:
    """Scan [lo, hi) for a zero guard or a covering magnitude dispatch.

    Returns (guarded, dispatch_note). ``dispatch_note`` names an
    uncovering ``cmp/b.lt`` routing when the loop sits in the
    zero-inclusive short path (evidence for the finding).
    """
    dispatch_note = None
    i = lo
    while i < hi:
        rec = records[i]
        i += 1
        if rec["kind"] != "insn":
            continue
        mn, ops = rec["mn"], rec["ops"]
        if mn in _ZERO_BRANCHES and ops and ops[0] == counter:
            return True, None
        if mn == "cmp" and len(ops) >= 2 and ops[0] == counter:
            imm = _imm(ops[1])
            branch = _next_insn(records, i, hi)
            if branch is None:
                continue
            bmn, bops = branch["mn"], branch["ops"]
            if imm == 0 and bmn in _EQ_BRANCHES:
                return True, None
            if imm is not None and imm >= 1 and bmn in _LT_BRANCHES and bops:
                t_idx = label_at.get(bops[0])
                if t_idx is None:
                    continue
                if loop_start < t_idx:
                    # Loop lives in the fall-through region => C >= imm.
                    return True, None
                dispatch_note = (
                    f"cmp {counter},{ops[1]} / {bmn} {bops[0]} "
                    f"(line {rec['line']}) routes {counter} < {imm} — "
                    f"including 0 — to this path with no zero test"
                )
    return False, dispatch_note


def _next_insn(records: list[dict], i: int, hi: int) -> dict | None:
    while i < hi:
        if records[i]["kind"] == "insn":
            return records[i]
        i += 1
    return None


def check_zero_length_loop_entry(asm_text: str) -> list[dict]:
    """Detect zero-length loop entry in AArch64 assembly text.

    Returns detection-grade finding dicts (see module docstring for
    the class). Empty list on non-AArch64 or conforming input.
    """
    if len(asm_text.encode("utf-8", "replace")) > _MAX_ASM_BYTES:
        asm_text = asm_text[:_MAX_ASM_BYTES]
    records = _parse(asm_text)
    findings: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for fname, start, end in _function_regions(records):
        label_at = {
            r["name"]: i for i, r in enumerate(records[start:end], start)
            if r["kind"] == "label"
        }
        counters = _length_counters(records, start, end)
        if not counters:
            continue
        loops = _find_loops(records, start, end, label_at)
        for loop in loops:
            for counter, derivs in counters.items():
                if loop["ctr_hint"] is not None and loop["ctr_hint"] != counter:
                    continue
                deriv = max(
                    (d for d in derivs if d < loop["start"]), default=None,
                )
                if deriv is None:
                    continue
                body = range(loop["start"], loop["branch"] + 1)
                if not any(
                    records[i]["kind"] == "insn"
                    and _is_decrement(records[i], counter)
                    for i in body
                ):
                    continue
                store_idx = next(
                    (i for i in body if records[i]["kind"] == "insn"
                     and records[i]["mn"].startswith(_STORE_PREFIX)),
                    None,
                )
                test_idx = next(
                    (i for i in body if records[i]["kind"] == "insn"
                     and _is_zero_test(records[i], counter)),
                    None,
                )
                if store_idx is None:
                    continue
                if test_idx is not None and test_idx < store_idx:
                    continue
                guarded, dispatch = _guarded_before(
                    records, counter, deriv + 1, loop["start"],
                    loop["start"], label_at,
                )
                if guarded:
                    continue
                key = (fname, loop["label"], counter)
                if key in seen:
                    continue
                seen.add(key)
                deriv_rec = records[deriv]
                findings.append({
                    "function": fname,
                    "loop_label": loop["label"],
                    "counter": counter,
                    "length_source": deriv_rec["ops"][1]
                    if len(deriv_rec["ops"]) > 1 else "",
                    "derived_at_line": deriv_rec["line"],
                    "loop_at_line": records[loop["start"]]["line"],
                    "store_at_line": records[store_idx]["line"],
                    "first_test_at_line": records[test_idx]["line"]
                    if test_idx is not None else None,
                    "dispatch": dispatch,
                    "confidence": 0.6 if dispatch else 0.5,
                    "cwe": "CWE-191",
                })
    return findings


def _describe(f: dict) -> str:
    test = (
        f"first zero test at line {f['first_test_at_line']}"
        if f["first_test_at_line"] is not None
        else "no zero test inside the loop"
    )
    parts = [
        f"zero-length loop entry: counter {f['counter']} = "
        f"{f['length_source']} >> k (line {f['derived_at_line']}) reaches "
        f"loop {f['loop_label']} (line {f['loop_at_line']}) with no zero "
        f"guard; the body stores output at line {f['store_at_line']} "
        f"before the {test} — a zero length processes one block and the "
        f"decrement wraps {f['counter']} to 2**64-1",
    ]
    if f.get("dispatch"):
        parts.append(f"routing: {f['dispatch']}")
    parts.append(
        f"[{f['cwe']}, confidence {f['confidence']:.2f}, detection-grade "
        f"lead — review the flagged kernel]"
    )
    return "; ".join(parts)


def asm_findings_to_mechanical(
    findings: list[dict], *, file_path: str, provenance: str = "",
) -> list[dict]:
    """Convert to the mechanical-detector finding shape
    (``file``/``function``/``detector``/``line``/``description``) —
    the ``semantic_findings_to_mechanical`` precedent.
    """
    out = []
    for f in findings:
        desc = _describe(f)
        if provenance:
            desc += f" ({provenance})"
        out.append({
            "file": file_path,
            "function": f["function"],
            "detector": DETECTOR_NAME,
            "line": f["loop_at_line"],
            "description": desc,
        })
    return out


def scan_inventory_asm(checklist: dict | None) -> list[dict]:
    """Run the check over every ``asm-generated`` inventory record.

    Reads the cached generated assembly named by each record's
    ``perlasm.generated_path`` (RAPTOR's own cache artifact; its
    *content* is untrusted target-derived data handled only by the
    pure-regex scanner above). Returns mechanical-shape findings;
    read failures are logged, never raised.
    """
    if not checklist:
        return []
    results: list[dict] = []
    for frec in checklist.get("files", []):
        if frec.get("language") != "asm-generated":
            continue
        meta = frec.get("perlasm") or {}
        gen_path = meta.get("generated_path")
        if not gen_path:
            continue
        try:
            with open(gen_path, "rb") as fh:
                text = fh.read(_MAX_ASM_BYTES).decode("utf-8", "replace")
        except OSError as exc:
            logger.warning(
                "asm_zero_len_loop: cannot read generated asm %s: %s",
                gen_path, exc,
            )
            continue
        findings = check_zero_length_loop_entry(text)
        if not findings:
            continue
        provenance = (
            f"generated from {meta.get('generator', '?')} "
            f"flavour={meta.get('flavour', '?')}"
        )
        results.extend(asm_findings_to_mechanical(
            findings, file_path=frec.get("path", gen_path),
            provenance=provenance,
        ))
    return results
