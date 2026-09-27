"""Ghidra eBPF ISA probe — measure decode fidelity against llvm-objdump.

Generates small eBPF objects AT PROBE TIME from RAPTOR-authored
assembly sources (clang ``--target=bpfel -mcpu=v1/v2/v3/v4``; nothing
is ever committed as a binary), disassembles them with llvm-objdump
(ground truth), imports them into a scratch Ghidra project, and
compares Ghidra's decode per ISA feature:

* **boundary** — every ground-truth instruction offset decodes to an
  instruction of the same length (an unknown opcode shows up as an
  undecoded gap);
* **distinguishability** — a feature instruction that differs from a
  confusable baseline only in its modifier field (``sdiv`` vs ``div``
  via off, ``movsx`` vs ``mov`` via off, ``bswap`` vs ``le`` via
  class, jmp32 vs 64-bit jmp, atomic and/or/xor/fetch/xchg/cmpxchg
  vs plain xadd via imm) must RENDER differently in Ghidra — a spec
  that ignores the modifier decodes both to the same text and would
  silently misrepresent semantics downstream;
* **branch targets** — rendered targets must land where ground truth
  says (``gotol``'s imm32 target, conditional-jump off16 targets).

Coverage is one representative per encoding family, not the full ISA
matrix: a SLEIGH spec decodes a family through one constructor, so
one representative exercises it. Unprobed variants: the remaining
atomic imm selectors (``fetch_or`` 0x41, ``fetch_xor`` 0xa1), 32-bit
``w``-register atomics, ``sdiv32``/``smod32``, and the ALU32 movsx
forms.

The result becomes the persisted capability record consumed by
:func:`packages.ghidra.ebpf_capability.ebpf_lifter_capability` — the
BLOCKING gate for the eBPF lifter lane. Hermetic degradation: when
the LLVM BPF toolchain or Ghidra is absent the probe reports
``status="unavailable"`` with a named reason and writes nothing
(capability stays unknown ⇒ consumers stay downgraded).

Entry point: ``packages/ghidra/scripts/ebpf-lifter-probe``.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

#: Per-object clang invocation budget. Lower risks killing a
#: legitimate first (cold-cache) compile on a loaded host; higher
#: lets a wedged toolchain stall the whole probe run.
CLANG_TIMEOUT_S = 60
#: Same trade-off for one llvm-objdump disassembly of a <1 KiB object.
OBJDUMP_TIMEOUT_S = 30
#: One analyzeHeadless run importing all probe objects. Measured ~4 s
#: for the full set on a warm host; lower risks killing a legitimate
#: cold JVM boot on a slow machine, higher holds the probe hostage to
#: a wedged JVM.
GHIDRA_PROBE_TIMEOUT_S = 600
#: Ceiling on the Ghidra dump file. The probe corpus dumps < 10 KiB;
#: lower could refuse a legitimate future corpus extension, higher
#: buffers a malfunctioning script's flood wholesale.
MAX_DUMP_BYTES = 8 * 1024 * 1024
#: Per-object ground-truth instruction ceiling. Probe sources are
#: < 32 instructions; lower would refuse legitimate probe growth,
#: higher lets unexpected objdump output balloon the parse.
MAX_GT_INSNS = 512
#: Versioned-tool suffix scan range (``clang-21``.. style names).
#: The floor is the first LLVM release with full BPF v4 support
#: (older clangs cannot assemble the probe corpus anyway); the
#: ceiling just bounds the PATH probe loop a few releases past
#: current so new toolchains are found without a code change.
TOOL_SUFFIX_MIN = 17
TOOL_SUFFIX_MAX = 30

#: eBPF instructions are 8-byte units (lddw = 16). Used for
#: undecoded-gap stepping and branch-target arithmetic.
EBPF_INSN_UNIT = 8


@dataclass(frozen=True)
class FeatureCheck:
    """One ISA-feature verdict extracted from a probe object.

    ``feature_re`` locates the feature instruction in the
    ground-truth (llvm-objdump) text; ``baseline_re`` locates the
    confusable baseline instruction (placed BEFORE the feature in the
    source so a failed feature decode cannot cascade onto it) —
    when set, Ghidra's renderings of the two must differ.
    ``target_check`` additionally requires Ghidra's rendered branch
    target to match ground truth.
    """

    name: str
    feature_re: str
    baseline_re: Optional[str] = None
    target_check: bool = False


@dataclass(frozen=True)
class ProbeObject:
    """One generated-at-probe-time object exercising ISA features."""

    name: str
    mcpu: str
    asm: str
    checks: tuple[FeatureCheck, ...]


def _asm(body: str, label: str) -> str:
    return "\t.text\n\t.globl " + label + "\n" + label + ":\n" + body


#: The probe corpus. Q3 ruling scope: ISA v2 (jlt-family), v3
#: (jmp32, atomics beyond xadd), v4 (sdiv/smod, movsx, bswap,
#: gotol) — plus a v1 baseline object (if even v1 fails to decode,
#: nothing downstream is trustworthy). Baselines always precede
#: features in program order: Ghidra disassembly follows flow, so a
#: feature that fails to decode must not take its own baseline down
#: with it.
PROBE_OBJECTS: tuple[ProbeObject, ...] = (
    ProbeObject(
        name="base_v1",
        mcpu="v1",
        asm=_asm(
            "\tr1 += r2\n"
            "\tif r1 > r2 goto LBL_END\n"
            "\tr0 = 0\n"
            "LBL_END:\n"
            "\texit\n",
            "probe_base_v1",
        ),
        checks=(
            FeatureCheck("v1_alu64_add", r"r1 \+= r2"),
            FeatureCheck("v1_jgt", r"if r1 > r2", target_check=True),
        ),
    ),
    ProbeObject(
        name="jlt_v2",
        mcpu="v2",
        asm=_asm(
            "\tif r1 > r2 goto LBL_T\n"
            "\tif r1 < r2 goto LBL_T\n"
            "\tr0 = 0\n"
            "LBL_T:\n"
            "\texit\n",
            "probe_jlt_v2",
        ),
        checks=(
            # Same operands, same label: ground truth differs ONLY in
            # the compare direction, so identical Ghidra text = the
            # v2 opcode decoded as its v1 confusable.
            FeatureCheck("v2_jlt", r"if r1 < r2",
                         baseline_re=r"if r1 > r2", target_check=True),
        ),
    ),
    ProbeObject(
        name="jmp32_v3",
        mcpu="v3",
        asm=_asm(
            "\tif r1 == r2 goto LBL_T\n"
            "\tif w1 == w2 goto LBL_T\n"
            "\tr0 = 0\n"
            "LBL_T:\n"
            "\texit\n",
            "probe_jmp32_v3",
        ),
        checks=(
            # jmp32 compares 32-bit subregisters — semantically
            # different from the 64-bit compare, so the rendering
            # must distinguish them.
            FeatureCheck("v3_jmp32_jeq", r"if w1 == w2",
                         baseline_re=r"if r1 == r2", target_check=True),
        ),
    ),
    ProbeObject(
        name="sdiv_v4",
        mcpu="v4",
        asm=_asm(
            "\tr1 /= r2\n"
            "\tr1 s/= r2\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_sdiv_v4",
        ),
        checks=(
            FeatureCheck("v4_sdiv", r"s/= r2", baseline_re=r"/= r2"),
        ),
    ),
    ProbeObject(
        name="smod_v4",
        mcpu="v4",
        asm=_asm(
            "\tr1 %= r2\n"
            "\tr1 s%= r2\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_smod_v4",
        ),
        checks=(
            FeatureCheck("v4_smod", r"s%= r2", baseline_re=r"%= r2"),
        ),
    ),
    ProbeObject(
        name="movsx_v4",
        mcpu="v4",
        asm=_asm(
            "\tr1 = r2\n"
            "\tr1 = (s8)r2\n"
            "\tr1 = (s16)r2\n"
            "\tr1 = (s32)r2\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_movsx_v4",
        ),
        checks=(
            FeatureCheck("v4_movsx8", r"\(s8\)r2",
                         baseline_re=r"r1 = r2$"),
            FeatureCheck("v4_movsx16", r"\(s16\)r2",
                         baseline_re=r"r1 = r2$"),
            FeatureCheck("v4_movsx32", r"\(s32\)r2",
                         baseline_re=r"r1 = r2$"),
        ),
    ),
    ProbeObject(
        name="bswap_v4",
        mcpu="v4",
        asm=_asm(
            "\tr1 = le16 r1\n"
            "\tr1 = le32 r1\n"
            "\tr1 = le64 r1\n"
            "\tr1 = bswap16 r1\n"
            "\tr1 = bswap32 r1\n"
            "\tr1 = bswap64 r1\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_bswap_v4",
        ),
        checks=(
            # v4 unconditional bswap vs the v1 endian ops it shares
            # the BPF_END opcode with (class bit is the only
            # difference at equal widths).
            FeatureCheck("v4_bswap16", r"bswap16", baseline_re=r"le16"),
            FeatureCheck("v4_bswap32", r"bswap32", baseline_re=r"le32"),
            FeatureCheck("v4_bswap64", r"bswap64", baseline_re=r"le64"),
        ),
    ),
    ProbeObject(
        name="gotol_v4",
        mcpu="v4",
        asm=_asm(
            "\tgoto LBL_A\n"
            "LBL_A:\n"
            "\tgotol LBL_B\n"
            "\tr0 = 1\n"
            "\tr0 = 2\n"
            "LBL_B:\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_gotol_v4",
        ),
        checks=(
            # gotol's semantics equal goto's (unconditional jump) —
            # the fidelity question is whether the imm32 target field
            # is decoded correctly, so this is a target check, not a
            # distinguishability check.
            FeatureCheck("v4_gotol", r"^gotol ", target_check=True),
        ),
    ),
    ProbeObject(
        name="atomic_bitops_v3",
        mcpu="v3",
        asm=_asm(
            "\tlock *(u64 *)(r1 + 0) += r2\n"
            "\tlock *(u64 *)(r1 + 0) &= r2\n"
            "\tlock *(u64 *)(r1 + 0) |= r2\n"
            "\tlock *(u64 *)(r1 + 0) ^= r2\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_atomic_bitops_v3",
        ),
        checks=(
            # All share the BPF_ATOMIC opcode with xadd; only imm
            # selects the operation — a spec ignoring imm decodes
            # every one of these as xadd.
            FeatureCheck("v3_atomic_and", r"&= r2",
                         baseline_re=r"\+= r2"),
            FeatureCheck("v3_atomic_or", r"\|= r2",
                         baseline_re=r"\+= r2"),
            FeatureCheck("v3_atomic_xor", r"\^= r2",
                         baseline_re=r"\+= r2"),
        ),
    ),
    ProbeObject(
        name="atomic_fetch_v3",
        mcpu="v3",
        asm=_asm(
            "\tlock *(u64 *)(r1 + 0) += r2\n"
            "\tr2 = atomic_fetch_add((u64 *)(r1 + 0), r2)\n"
            "\tr2 = atomic_fetch_and((u64 *)(r1 + 0), r2)\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_atomic_fetch_v3",
        ),
        checks=(
            FeatureCheck("v3_atomic_fetch_add", r"atomic_fetch_add",
                         baseline_re=r"\+= r2"),
            FeatureCheck("v3_atomic_fetch_and", r"atomic_fetch_and",
                         baseline_re=r"\+= r2"),
        ),
    ),
    ProbeObject(
        name="atomic_xchg_v3",
        mcpu="v3",
        asm=_asm(
            "\tlock *(u64 *)(r1 + 0) += r2\n"
            "\tr2 = xchg_64(r1 + 0, r2)\n"
            "\tr0 = cmpxchg_64(r1 + 0, r0, r2)\n"
            "\tr0 = 0\n"
            "\texit\n",
            "probe_atomic_xchg_v3",
        ),
        checks=(
            FeatureCheck("v3_atomic_xchg", r"= xchg_64\(",
                         baseline_re=r"\+= r2"),
            FeatureCheck("v3_atomic_cmpxchg", r"= cmpxchg_64\(",
                         baseline_re=r"\+= r2"),
        ),
    ),
)


#: Ghidra post-script: walk every initialized executable block,
#: disassembling at each 8-byte boundary that auto-flow did not
#: reach, and emit one INSN/UNDEF line per unit. Appends across
#: programs (one analyzeHeadless run imports the whole corpus).
PROBE_DUMP_JAVA = r"""
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import java.io.FileWriter;

public class EbpfProbeDump extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FileWriter w = new FileWriter(args[0], true);
        try {
            w.write("PROGRAM\t" + currentProgram.getName() + "\t"
                    + currentProgram.getLanguageID() + "\n");
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                if (!b.isExecute() || !b.isInitialized()) continue;
                w.write("BLOCK\t" + b.getName() + "\t"
                        + b.getStart().getOffset() + "\t" + b.getSize()
                        + "\n");
                Address a = b.getStart();
                while (a != null && a.compareTo(b.getEnd()) <= 0) {
                    Instruction ins =
                        currentProgram.getListing().getInstructionAt(a);
                    if (ins == null) {
                        DisassembleCommand cmd = new DisassembleCommand(
                            a, new AddressSet(b.getStart(), b.getEnd()),
                            true);
                        cmd.applyTo(currentProgram, monitor);
                        ins = currentProgram.getListing()
                            .getInstructionAt(a);
                    }
                    long off = a.subtract(b.getStart());
                    long remain = b.getSize() - off;
                    if (ins != null) {
                        w.write("INSN\t" + b.getName() + "\t" + off
                                + "\t" + ins.getLength() + "\t"
                                + ins.toString() + "\n");
                        if (remain <= ins.getLength()) break;
                        a = a.add(ins.getLength());
                    } else {
                        w.write("UNDEF\t" + b.getName() + "\t" + off
                                + "\n");
                        if (remain <= 8) break;
                        a = a.add(8);
                    }
                }
            }
        } finally {
            w.close();
        }
    }
}
"""


@dataclass(frozen=True)
class EbpfToolchain:
    """Resolved LLVM BPF toolchain (producer side + ground truth)."""

    clang: str
    objdump: str


def _find_versioned(base: str) -> Optional[str]:
    """Locate *base* on PATH, trying the plain name then versioned
    suffixes newest-first (distros ship ``llvm-objdump-21``-style
    names without a plain alias)."""
    found = shutil.which(base)
    if found:
        return found
    for suffix in range(TOOL_SUFFIX_MAX, TOOL_SUFFIX_MIN - 1, -1):
        found = shutil.which(f"{base}-{suffix}")
        if found:
            return found
    return None


def find_toolchain() -> Optional[EbpfToolchain]:
    """Resolve clang + llvm-objdump, or None when either is absent."""
    clang = _find_versioned("clang")
    objdump = _find_versioned("llvm-objdump")
    if not clang or not objdump:
        return None
    return EbpfToolchain(clang=clang, objdump=objdump)


def _safe_env() -> dict:
    from core.security.env_sanitisation import safe_subprocess_env
    return safe_subprocess_env()


def _stderr_tail(text: Optional[str], limit: int) -> str:
    """Bounded, escaped tool-stderr excerpt for record reasons.

    Tool stderr can echo attacker-adjacent bytes; the excerpt lands in
    the persisted record and in operator-facing output, so escape
    non-printables (the ``core.security.log_sanitisation`` contract)
    after bounding.
    """
    from core.security.log_sanitisation import escape_nonprintable
    return escape_nonprintable((text or "")[-limit:])


def _tool_version(tool: str) -> str:
    """First line of ``<tool> --version`` (best-effort, for the
    record's provenance block)."""
    try:
        r = subprocess.run(
            [tool, "--version"], capture_output=True, text=True,
            timeout=OBJDUMP_TIMEOUT_S, env=_safe_env(),
        )
        first = (r.stdout or r.stderr or "").splitlines()
        return first[0].strip() if first else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


@dataclass(frozen=True)
class GTInsn:
    """One ground-truth instruction from llvm-objdump."""

    offset: int
    length: int
    text: str


# The byte-pair window is BOUNDED so no two unbounded whitespace-
# capable repeats sit adjacent (an overlapping pair re-splits a
# space run from every boundary while the mnemonic fails to appear).
# 64 pairs is 4x the widest real line (a 16-byte lddw); raising it
# buys nothing until objdump prints wider lines, lowering it under
# 16 drops lddw lines from the ground truth.
_GT_LINE_RE = re.compile(
    r"^\s*[0-9a-f]+:((?:\s+[0-9a-f]{2}){1,64})\s+(\S.*)$")
_GT_SECTION_RE = re.compile(r"^Disassembly of section (\S+):")


def parse_ground_truth(text: str) -> list[GTInsn]:
    """Parse llvm-objdump ``-d`` output for the ``.text`` section.

    Offsets are accumulated from each line's byte count — never taken
    from objdump's leading counter, whose unit (byte vs 8-byte slot)
    has differed across objdump versions and targets.
    """
    insns: list[GTInsn] = []
    offset = 0
    in_text = True
    for line in text.splitlines():
        m = _GT_SECTION_RE.match(line)
        if m:
            in_text = m.group(1) == ".text"
            continue
        if not in_text:
            continue
        m = _GT_LINE_RE.match(line)
        if not m:
            continue
        nbytes = len(m.group(1).split())
        insns.append(GTInsn(offset=offset, length=nbytes,
                            text=m.group(2).strip()))
        offset += nbytes
        if len(insns) >= MAX_GT_INSNS:
            logger.warning("ground truth truncated at %d instructions",
                           MAX_GT_INSNS)
            break
    return insns


@dataclass
class GhidraProgramDump:
    """Ghidra's decode of one imported probe object (``.text``)."""

    language_id: str = ""
    block_start: Optional[int] = None
    block_size: Optional[int] = None
    #: section offset -> (decoded length, rendered text)
    insns: dict[int, tuple[int, str]] = field(default_factory=dict)
    undefs: set[int] = field(default_factory=set)


def parse_dump(text: str) -> dict[str, GhidraProgramDump]:
    """Parse the EbpfProbeDump output into per-program decode maps."""
    programs: dict[str, GhidraProgramDump] = {}
    current: Optional[GhidraProgramDump] = None
    for line in text.splitlines():
        parts = line.rstrip("\n").split("\t")
        tag = parts[0] if parts else ""
        if tag == "PROGRAM" and len(parts) >= 3:
            current = GhidraProgramDump(language_id=parts[2])
            programs[parts[1]] = current
        elif current is None:
            continue
        elif tag == "BLOCK" and len(parts) >= 4:
            # First executable block wins — probe objects carry a
            # single .text and nothing else executable.
            if parts[1] == ".text" and current.block_start is None:
                try:
                    current.block_start = int(parts[2])
                    current.block_size = int(parts[3])
                except ValueError:
                    pass
        elif tag == "INSN" and len(parts) >= 5 and parts[1] == ".text":
            try:
                current.insns[int(parts[2])] = (
                    int(parts[3]), "\t".join(parts[4:]))
            except ValueError:
                pass
        elif tag == "UNDEF" and len(parts) >= 3 and parts[1] == ".text":
            try:
                current.undefs.add(int(parts[2]))
            except ValueError:
                pass
    return programs


def generate_objects(
    toolchain: EbpfToolchain,
    work_dir: Path,
) -> dict[str, dict[str, Any]]:
    """Assemble every probe source: name -> {path|None, error}."""
    src_dir = work_dir / "src"
    obj_dir = work_dir / "objs"
    src_dir.mkdir(parents=True, exist_ok=True)
    obj_dir.mkdir(parents=True, exist_ok=True)
    results: dict[str, dict[str, Any]] = {}
    for probe in PROBE_OBJECTS:
        src = src_dir / f"{probe.name}.s"
        obj = obj_dir / f"{probe.name}.o"
        src.write_text(probe.asm, encoding="utf-8")
        argv = [
            toolchain.clang, "--target=bpfel", f"-mcpu={probe.mcpu}",
            "-c", str(src), "-o", str(obj),
        ]
        try:
            r = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=CLANG_TIMEOUT_S, env=_safe_env(),
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            results[probe.name] = {"path": None,
                                   "error": f"clang failed: {exc}"}
            continue
        if r.returncode != 0 or not obj.is_file():
            tail = _stderr_tail(r.stderr, 500)
            results[probe.name] = {
                "path": None,
                "error": f"clang exited {r.returncode}: {tail}",
            }
            continue
        results[probe.name] = {"path": obj, "error": ""}
    return results


def disassemble_ground_truth(
    toolchain: EbpfToolchain,
    obj_path: Path,
) -> tuple[list[GTInsn], str]:
    """llvm-objdump ground truth for one object: (insns, error)."""
    argv = [toolchain.objdump, "-d", "--triple=bpfel", str(obj_path)]
    try:
        r = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=OBJDUMP_TIMEOUT_S, env=_safe_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"llvm-objdump failed: {exc}"
    if r.returncode != 0:
        return [], f"llvm-objdump exited {r.returncode}: " \
                   f"{_stderr_tail(r.stderr, 300)}"
    insns = parse_ground_truth(r.stdout or "")
    if not insns:
        return [], "llvm-objdump produced no .text instructions"
    return insns, ""


def ghidra_decode(
    object_paths: list[Path],
    work_dir: Path,
    *,
    timeout: int = GHIDRA_PROBE_TIMEOUT_S,
) -> tuple[dict[str, GhidraProgramDump], str]:
    """Import the probe objects into a scratch project and dump the
    decode: (per-program dumps keyed by program name, error).

    Same sandbox posture as :mod:`packages.ghidra.headless` (network
    denied, reads restricted to system dirs + the work dir + the
    Ghidra install, writes scoped to the work dir) — the inputs are
    RAPTOR-generated, the posture is uniformity plus belt-and-braces.
    """
    from .headless import (
        GhidraError,
        _find_headless,
        _install_read_paths,
        _jvm_scoped_env,
        _refuse_hidden_path_elements,
    )
    try:
        headless = _find_headless()
    except GhidraError as exc:
        return {}, str(exc)
    try:
        _refuse_hidden_path_elements(work_dir, "probe project")
    except GhidraError as exc:
        return {}, str(exc)

    proj_dir = work_dir / "proj"
    script_dir = work_dir / "gscripts"
    proj_dir.mkdir(parents=True, exist_ok=True)
    script_dir.mkdir(parents=True, exist_ok=True)
    (script_dir / "EbpfProbeDump.java").write_text(
        PROBE_DUMP_JAVA, encoding="utf-8")
    dump_path = work_dir / "probe-dump.txt"
    if dump_path.exists():
        dump_path.unlink()

    env = _jvm_scoped_env(work_dir)
    cmd = [
        headless,
        str(proj_dir),
        "raptor-ebpf-probe",
        "-import", *[str(p) for p in object_paths],
        "-noanalysis",
        "-scriptPath", str(script_dir),
        "-postScript", "EbpfProbeDump.java", str(dump_path),
        "-deleteProject",
    ]
    logger.info("running eBPF probe import (%d objects)",
                len(object_paths))
    try:
        from core.sandbox import run as _sandbox_run
        result = _sandbox_run(
            cmd,
            block_network=True,
            target=str(work_dir),
            output=str(work_dir),
            restrict_reads=True,
            readable_paths=_install_read_paths(headless),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            # env comes from safe_subprocess_env() via
            # _jvm_scoped_env — already allowlist-filtered upstream.
            env_caller_filtered=True,
        )
    except subprocess.TimeoutExpired:
        return {}, f"analyzeHeadless probe timed out after {timeout}s"
    except OSError as exc:
        return {}, f"failed to run analyzeHeadless: {exc}"

    if not dump_path.is_file():
        tail = _stderr_tail(result.stderr, 500)
        return {}, (
            f"probe dump not produced (analyzeHeadless exited "
            f"{result.returncode}): {tail}"
        )
    try:
        if dump_path.stat().st_size > MAX_DUMP_BYTES:
            return {}, "probe dump over budget"
        text = dump_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {}, f"probe dump unreadable: {exc}"
    return parse_dump(text), ""


def _norm(text: str) -> str:
    """Rendering-comparison normalisation: whitespace + case only —
    anything stronger could mask a genuine operand difference."""
    return " ".join(text.split()).upper()


_GT_BRANCH_RE = re.compile(r"([+-])0x([0-9a-f]+)")

#: Hex operand tokens in a Ghidra rendering: ``0x``-prefixed literals
#: plus label-style suffixes (``LAB_00100018``). Target checks compare
#: token VALUES for equality — a substring test would false-pass when
#: the wanted address renders short (small block starts) and its
#: digits appear anywhere else on the line.
_GH_HEX_TOKEN_RE = re.compile(r"(?:0x|_)([0-9a-f]+)\b")


def _expected_target_offset(gt: GTInsn) -> Optional[int]:
    """Branch target (section offset) from a ground-truth rendering.

    llvm-objdump renders BPF branch targets as instruction-slot
    deltas (``goto +0x2``); the target is the next instruction plus
    that many 8-byte units.
    """
    m = _GT_BRANCH_RE.search(gt.text)
    if not m:
        return None
    slots = int(m.group(2), 16)
    delta = slots if m.group(1) == "+" else -slots
    return gt.offset + gt.length + delta * EBPF_INSN_UNIT


def _first_match(
    insns: list[GTInsn], pattern: str,
) -> Optional[GTInsn]:
    rx = re.compile(pattern)
    for insn in insns:
        if rx.search(insn.text):
            return insn
    return None


def evaluate_object(
    probe: ProbeObject,
    gt_insns: list[GTInsn],
    dump: Optional[GhidraProgramDump],
) -> dict[str, dict[str, Any]]:
    """Verdicts for every check of one probe object."""
    features: dict[str, dict[str, Any]] = {}

    def fail_all(reason: str) -> dict[str, dict[str, Any]]:
        for check in probe.checks:
            features[check.name] = {
                "object": probe.name, "mcpu": probe.mcpu,
                "pass": False, "reason": reason, "checks": {},
            }
        return features

    if dump is None:
        return fail_all("Ghidra produced no decode dump for this "
                        "object")
    language_ok = dump.language_id.startswith("eBPF")
    if not language_ok:
        return fail_all(
            f"Ghidra imported the object as language "
            f"{dump.language_id!r}, not eBPF"
        )
    if dump.block_start is None:
        return fail_all("Ghidra dump has no .text block")

    total = sum(i.length for i in gt_insns)
    boundary_misses = [
        gt.offset for gt in gt_insns
        if dump.insns.get(gt.offset, (None, ""))[0] != gt.length
    ]
    undef_in_range = sorted(
        off for off in dump.undefs if 0 <= off < total)
    decoded_all = not boundary_misses and not undef_in_range

    for check in probe.checks:
        entry: dict[str, Any] = {
            "object": probe.name, "mcpu": probe.mcpu,
            "checks": {"language_ok": True, "decoded_all": decoded_all},
        }
        reasons: list[str] = []
        if not decoded_all:
            reasons.append(
                f"decode gaps: boundary misses at {boundary_misses}, "
                f"undecoded units at {undef_in_range}"
            )

        gt_feat = _first_match(gt_insns, check.feature_re)
        if gt_feat is None:
            entry["pass"] = False
            entry["reason"] = (
                "feature instruction absent from ground truth — "
                "probe source or toolchain drift"
            )
            features[check.name] = entry
            continue
        entry["ground_truth_text"] = gt_feat.text
        gh_feat = dump.insns.get(gt_feat.offset)
        entry["checks"]["feature_decoded"] = gh_feat is not None
        if gh_feat is None:
            reasons.append("feature instruction not decoded by Ghidra")
        else:
            entry["ghidra_text"] = gh_feat[1]

        if check.baseline_re is not None:
            gt_base = _first_match(gt_insns, check.baseline_re)
            gh_base = dump.insns.get(gt_base.offset) if gt_base else None
            if gt_base is None or gh_base is None:
                entry["checks"]["distinguishable"] = False
                reasons.append("confusable baseline instruction "
                               "missing from decode")
            else:
                entry["ghidra_baseline_text"] = gh_base[1]
                distinct = (gh_feat is not None
                            and _norm(gh_feat[1]) != _norm(gh_base[1]))
                entry["checks"]["distinguishable"] = distinct
                if not distinct:
                    reasons.append(
                        "Ghidra renders the feature identically to "
                        "its confusable baseline"
                    )

        if check.target_check:
            expected = _expected_target_offset(gt_feat)
            if expected is None:
                target_ok = False
                reasons.append("ground truth carries no parseable "
                               "branch target")
            elif gh_feat is None:
                target_ok = False
            else:
                want = dump.block_start + expected
                rendered = _GH_HEX_TOKEN_RE.findall(gh_feat[1].lower())
                target_ok = any(
                    int(token, 16) == want for token in rendered)
                if not target_ok:
                    reasons.append(
                        f"no rendered hex operand equals the expected "
                        f"branch target 0x{want:x}"
                    )
            entry["checks"]["target_ok"] = target_ok

        entry["pass"] = all(entry["checks"].values())
        entry["reason"] = "; ".join(reasons)
        features[check.name] = entry
    return features


def run_probe(
    work_dir: Optional[Path] = None,
    *,
    timeout: int = GHIDRA_PROBE_TIMEOUT_S,
) -> dict[str, Any]:
    """Run the full probe. Returns::

        {"status": "ran", "record": {...}}
        {"status": "unavailable", "reason": "<named degradation>"}

    ``unavailable`` (LLVM BPF toolchain or Ghidra/eBPF module absent)
    writes no record: capability stays UNKNOWN, which consumers must
    treat exactly like a failed probe (fail-closed). The caller
    persists a ``ran`` record via
    :func:`packages.ghidra.ebpf_capability.save_capability_record`.
    """
    from .ebpf_capability import (
        CAPABILITY_KIND,
        CAPABILITY_SCHEMA,
        _application_version,
        ghidra_install_root,
        install_fingerprint,
    )

    toolchain = find_toolchain()
    if toolchain is None:
        return {"status": "unavailable",
                "reason": "LLVM BPF toolchain not found (need clang "
                          "and llvm-objdump on PATH)"}
    root = ghidra_install_root()
    if root is None:
        return {"status": "unavailable",
                "reason": "Ghidra not found (analyzeHeadless not on "
                          "PATH and GHIDRA_INSTALL_DIR unset/invalid)"}
    fingerprint = install_fingerprint(root)
    if fingerprint is None:
        return {"status": "unavailable",
                "reason": "Ghidra eBPF processor module absent or "
                          "unfingerprintable in this install"}

    own_tmp = None
    if work_dir is None:
        own_tmp = tempfile.TemporaryDirectory(prefix="raptor-ebpf-probe-")
        work_dir = Path(own_tmp.name)
    try:
        generated = generate_objects(toolchain, work_dir)

        gt: dict[str, list[GTInsn]] = {}
        gt_errors: dict[str, str] = {}
        good_objects: list[Path] = []
        for probe in PROBE_OBJECTS:
            gen = generated[probe.name]
            if gen["path"] is None:
                continue
            insns, err = disassemble_ground_truth(toolchain, gen["path"])
            if err:
                gt_errors[probe.name] = err
                continue
            gt[probe.name] = insns
            good_objects.append(gen["path"])

        dumps: dict[str, GhidraProgramDump] = {}
        ghidra_error = ""
        if good_objects:
            dumps, ghidra_error = ghidra_decode(
                good_objects, work_dir, timeout=timeout)

        features: dict[str, dict[str, Any]] = {}
        for probe in PROBE_OBJECTS:
            gen = generated[probe.name]
            if gen["path"] is None:
                for check in probe.checks:
                    features[check.name] = {
                        "object": probe.name, "mcpu": probe.mcpu,
                        "pass": False, "checks": {},
                        "reason": f"probe object generation failed: "
                                  f"{gen['error']}",
                    }
                continue
            if probe.name in gt_errors:
                for check in probe.checks:
                    features[check.name] = {
                        "object": probe.name, "mcpu": probe.mcpu,
                        "pass": False, "checks": {},
                        "reason": f"ground truth unavailable: "
                                  f"{gt_errors[probe.name]}",
                    }
                continue
            if ghidra_error:
                for check in probe.checks:
                    features[check.name] = {
                        "object": probe.name, "mcpu": probe.mcpu,
                        "pass": False, "checks": {},
                        "reason": f"Ghidra decode failed: "
                                  f"{ghidra_error}",
                    }
                continue
            dump = dumps.get(gen["path"].name)
            features.update(
                evaluate_object(probe, gt[probe.name], dump))
    finally:
        if own_tmp is not None:
            own_tmp.cleanup()

    failed = sorted(
        name for name, entry in features.items()
        if entry.get("pass") is not True
    )
    record: dict[str, Any] = {
        "schema": CAPABILITY_SCHEMA,
        "kind": CAPABILITY_KIND,
        "install_fingerprint": fingerprint,
        "ghidra_version": _application_version(root),
        "toolchain": {
            "clang": _tool_version(toolchain.clang),
            "llvm_objdump": _tool_version(toolchain.objdump),
        },
        "features": features,
        "failed_features": failed,
        "pass": bool(features) and not failed,
    }
    try:
        from core.coverage.journal import now_iso
        record["generated_at"] = now_iso()
    except Exception:  # noqa: BLE001 — timestamp is best-effort
        pass
    return {"status": "ran", "record": record}
