#!/usr/bin/env python3
"""E2E script for the Witness data model + store + fuzz adapter.

Demonstrates the end-to-end flow:

  1. Synthesise an AFL++ ``Crash`` object pointing at a real
     bytes file
  2. Wrap as a ``Witness`` via the fuzz adapter
  3. Persist to a ``WitnessStore`` under a tempdir
  4. Load back; verify hash, source, outcome, and bytes match
  5. Show the on-disk JSON manifest operators can inspect

Run from the repo root:

    python3 core/witness/scripts/e2e_witness.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

# core/witness/scripts/e2e_witness.py
#   parents[0] = scripts/
#   parents[1] = witness/
#   parents[2] = core/
#   parents[3] = repo root
REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
os.environ.setdefault("RAPTOR_DIR", str(REPO))

from core.witness import WitnessOutcome, WitnessSource, WitnessStore  # noqa: E402
from packages.fuzzing.crash_collector import Crash  # noqa: E402
from packages.fuzzing.witness_adapter import witness_from_crash  # noqa: E402


def _hr(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="e2e-witness-") as tmp:
        tmp_path = Path(tmp)

        # ---- Stage 1: synthesise a fuzz crash artefact ----
        _hr("Stage 1: synthesise an AFL++ Crash")
        crash_input = tmp_path / "id_000042"
        crash_data = b"A" * 256 + b"\x00BBBB" + b"\xde\xad\xbe\xef"
        crash_input.write_bytes(crash_data)
        crash = Crash(
            crash_id="000042",
            input_file=crash_input,
            signal="11",  # SIGSEGV
            stack_hash="cafef00d",
            size=len(crash_data),
        )
        print(f"  crash_id:     {crash.crash_id}")
        print(f"  signal:       {crash.signal}")
        print(f"  input_file:   {crash.input_file}")
        print(f"  size:         {crash.size} bytes")

        # Fake target binary (any bytes will do for the hash test).
        target_bin = tmp_path / "target_binary"
        target_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)
        print(f"  target_bin:   {target_bin}")

        # ---- Stage 2: adapter ----
        _hr("Stage 2: Crash → Witness via witness_from_crash")
        witness, data = witness_from_crash(
            crash,
            target_binary_path=target_bin,
            target_source_hash="abc" * 21 + "d",  # 64-char placeholder
        )
        print(f"  bytes_hash:   {witness.bytes_hash[:16]}...")
        print(f"  bytes_len:    {witness.bytes_len}")
        print(f"  source:       {witness.source.value}")
        print(f"  outcome:      {witness.observed_outcome.value}")
        print(f"  target_binary_hash: {(witness.target_binary_hash or '')[:16]}...")
        print(f"  outcome_detail: {witness.outcome_detail}")

        # ---- Stage 3: persist to WitnessStore ----
        _hr("Stage 3: persist to WitnessStore")
        store_root = tmp_path / "store"
        store = WitnessStore(store_root)
        blob_path = store.put(witness, data)
        print(f"  store root:   {store_root}")
        print(f"  blob path:    {blob_path}")
        print(f"  manifest:     "
              f"{store_root}/manifests/{witness.bytes_hash[:16]}...json")

        # ---- Stage 4: load back ----
        _hr("Stage 4: load back via store.get_witness + store.get_bytes")
        loaded_w = store.get_witness(witness.bytes_hash)
        loaded_bytes = store.get_bytes(witness.bytes_hash)
        print(f"  loaded hash:    {loaded_w.bytes_hash[:16]}...  "
              f"(matches: {loaded_w.bytes_hash == witness.bytes_hash})")
        print(f"  loaded source:  {loaded_w.source.value}")
        print(f"  loaded outcome: {loaded_w.observed_outcome.value}")
        print(f"  loaded bytes match: {loaded_bytes == data}")

        # ---- Stage 5: show the manifest JSON ----
        _hr("Stage 5: on-disk manifest (operator-readable JSON)")
        manifest_path = store_root / "manifests" / f"{witness.bytes_hash}.json"
        manifest_data = json.loads(manifest_path.read_text())
        print(json.dumps(manifest_data, indent=2))

        # ---- Stage 6: list all witnesses in the store ----
        _hr("Stage 6: store enumeration")
        # Add a second witness so list() has multiple to surface
        second_data = b"different bytes"
        from core.witness.types import Witness
        from core.witness.types import compute_bytes_hash
        second_witness = Witness(
            bytes_hash=compute_bytes_hash(second_data),
            source=WitnessSource.MANUAL,
            observed_outcome=WitnessOutcome.NO_OBVIOUS_EFFECT,
            produced_by="operator-supplied",
        )
        store.put(second_witness, second_data)
        for w in store.list_witnesses():
            print(f"  {w.bytes_hash[:16]}...  source={w.source.value:<22}  "
                  f"outcome={w.observed_outcome.value}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
