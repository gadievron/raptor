#!/usr/bin/env python3
"""E2E script for the operator-facing ``--execute-exploits`` flow.

Exercises every layer end-to-end, using the *real* configured LLM:

  1. Compile a trivially-fuzzable target binary with
     ``-fsanitize=address``.
  2. Produce a real crash by running the target with an
     overflowing input.
  3. Build a ``CrashContext`` shaped like ``addr2line + AFL``
     output would produce.
  4. Instantiate ``CrashAnalysisAgent`` with
     ``execute_exploits=True`` and
     ``execute_sanitizers=["address"]``.
  5. Call ``generate_exploit(crash_context)`` — the real LLM
     synthesises an exploit, ``compile_and_execute`` runs it in
     the sandbox, ``observe._interpret_result`` classifies the
     outcome, and the recorder writes a ``Witness`` to disk.
  6. Inspect the manifest on disk.

Cost: one LLM call per run (~5–50K tokens depending on provider).
Skip-gated on ``gcc -fsanitize=address`` availability + a working
LLM config; prints what was checked / what was skipped.

Run from the repo root:

    python3 packages/llm_analysis/scripts/e2e_execute_witness.py
"""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


# packages/llm_analysis/scripts/e2e_execute_witness.py
#   parents[0] = scripts/
#   parents[1] = llm_analysis/
#   parents[2] = packages/
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))


_TARGET_SOURCE = """
#include <string.h>
#include <unistd.h>
int main(void) {
    char buf[8];
    char input[64];
    ssize_t n = read(0, input, sizeof(input) - 1);
    if (n <= 0) return 1;
    input[n] = 0;
    strcpy(buf, input);
    return 0;
}
"""


def _has_libasan() -> bool:
    if shutil.which("gcc") is None:
        return False
    try:
        result = subprocess.run(
            ["gcc", "-fsanitize=address", "-x", "c", "-",
             "-o", "/dev/null"],
            input="int main(void){return 0;}",
            text=True,
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except Exception:  # noqa: BLE001
        return False


def main() -> int:
    if not _has_libasan():
        print("SKIP: gcc -fsanitize=address not usable on this host")
        return 0

    from core.llm.detection import detect_llm_availability
    avail = detect_llm_availability()
    if not avail.external_llm:
        print("SKIP: no external LLM configured "
              "(need ANTHROPIC_API_KEY / OPENAI_API_KEY / etc.)")
        return 0

    from core.witness import WitnessOutcome, WitnessStore
    from packages.binary_analysis.crash_analyser import CrashContext
    from packages.llm_analysis.crash_agent import CrashAnalysisAgent

    with tempfile.TemporaryDirectory(prefix="e2e-execute-witness-") as td:
        td_path = Path(td)
        print(f"[1/6] Workdir: {td_path}")

        # --- 1. Build target binary with ASAN ---
        src = td_path / "target.c"
        src.write_text(_TARGET_SOURCE)
        binary = td_path / "target"
        subprocess.run(
            ["gcc", "-O0", "-g", "-fno-omit-frame-pointer",
             "-fsanitize=address", "-o", str(binary), str(src)],
            check=True, timeout=30,
        )
        print(f"[2/6] Built ASAN-instrumented target: {binary.name}")

        # --- 2. Crash input (BOF — 20 'A's into an 8-byte buf) ---
        crash_dir = td_path / "crashes"
        crash_dir.mkdir()
        crash_file = crash_dir / "id_000000"
        crash_file.write_bytes(b"A" * 20)
        print(f"[3/6] Wrote crash input: {crash_file.name} "
              f"({crash_file.stat().st_size}B)")

        # --- 3. Real CrashContext ---
        crash = CrashContext(
            crash_id="000000",
            binary_path=binary,
            input_file=crash_file,
            signal="11",
            stack_trace=(
                "#0 strcpy in target.c:10\n"
                "#1 main in target.c:9"
            ),
            registers={"rip": "0x401234", "rsp": "0x7ffeXXX0"},
            crash_instruction="mov BYTE PTR [rdi], al",
            crash_address="0x7ffeYYYY",
            stack_hash="deadbeefcafebabe",
            disassembly="0x401234: mov BYTE PTR [rdi], al",
            function_name="strcpy",
            source_location="target.c:10",
            binary_info={
                "asan_enabled": "true",
                "aslr_enabled": "true",
                "nx_enabled": "true",
                "stack_canaries": "true",
            },
            exploitability="exploitable",
            crash_type="stack_overflow",
            cvss_estimate=7.5,
            analysis={},
            exploit_code=None,
        )
        print(f"[4/6] Built CrashContext: {crash.crash_type} "
              f"at {crash.source_location}")

        # --- 4. Real CrashAnalysisAgent with execute=True ---
        out_dir = td_path / "out"
        agent = CrashAnalysisAgent(
            binary_path=binary,
            out_dir=out_dir,
            verify_exploits=True,
            judge_intent=False,  # save the extra LLM tiebreak call
            record_witnesses=True,
            execute_exploits=True,
            execute_timeout=15,
            execute_sanitizers=["address"],
        )

        # --- 5. Real LLM exploit generation + execution ---
        print(f"[5/6] Invoking LLM (provider="
              f"{agent.llm_config.primary_model.provider}, "
              f"model={agent.llm_config.primary_model.model_name})...")
        ok = agent.generate_exploit(crash)
        if not ok:
            print("FAIL: generate_exploit returned False — "
                  "LLM produced no usable exploit code")
            return 1

        # --- 6. Inspect the recorded Witness ---
        store_root = out_dir / "witnesses"
        manifests = sorted((store_root / "manifests").glob("*.json"))
        blobs = sorted((store_root / "blobs").glob("*"))
        print(f"[6/6] Witnesses on disk: "
              f"{len(manifests)} manifests, {len(blobs)} blobs")

        store = WitnessStore(store_root)
        for m in manifests:
            w = store.get_witness(m.stem)
            print(f"  - bytes_hash={w.bytes_hash[:16]}... "
                  f"bytes_len={w.bytes_len} "
                  f"source={w.source.value} "
                  f"outcome={w.observed_outcome.value}")
            for k, v in sorted(w.outcome_detail.items()):
                if k == "evidence":
                    print(f"    {k}: {v[:100]}{'...' if len(str(v)) > 100 else ''}")
                else:
                    print(f"    {k}: {v}")

        # --- Hard assertions ---
        ok_compile = crash.exploit_compiled is True
        ok_executed = crash.execute_outcome is not None
        outcome_value = crash.execute_outcome
        # ASAN should have fired since we asked for sanitizers=["address"]
        # AND the LLM was prompted with a stack_overflow crash context.
        # If the LLM emitted code that doesn't trigger ASAN, we still
        # consider the wiring proven — the substrate did its job.
        print()
        print("=" * 60)
        print(f"compile_verify success: {ok_compile}")
        print(f"execute attempted:      {ok_executed}")
        print(f"observed outcome:       {outcome_value}")
        if outcome_value == WitnessOutcome.SANITIZER_REPORT.value:
            print("✓ ASAN fired — full chain proven end-to-end "
                  "(LLM emit → sanitised compile → sandbox run → "
                  "ASAN detect → witness with SANITIZER_REPORT)")
        elif outcome_value == WitnessOutcome.EXIT_SIGNAL.value:
            print("· Exit-signal outcome (substrate proven; LLM exploit "
                  "didn't trigger ASAN — fine, the wiring still works)")
        elif outcome_value == WitnessOutcome.NO_OBVIOUS_EFFECT.value:
            print("· No-effect outcome (substrate proven; LLM exploit "
                  "compiled + ran cleanly without triggering the bug)")
        else:
            print(f"· Other outcome: {outcome_value}")

        # Pin the exploit_code → bytes_hash → manifest invariant
        if crash.exploit_code:
            expected = hashlib.sha256(
                crash.exploit_code.encode("utf-8", errors="replace")
            ).hexdigest()
            blob_path = store_root / "blobs" / f"{expected}.bin"
            if blob_path.exists():
                print(f"✓ Exploit bytes_hash matches on-disk blob: "
                      f"{expected[:16]}...")
            else:
                print(f"FAIL: expected blob {expected[:16]}... "
                      f"not on disk")
                return 1

        return 0 if (ok_compile and ok_executed) else 1


if __name__ == "__main__":
    sys.exit(main())
