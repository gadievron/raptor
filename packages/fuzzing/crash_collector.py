#!/usr/bin/env python3
"""
RAPTOR Crash Collector

Collects and deduplicates crashes from AFL output.
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from core.hash import sha256_file
from core.logging import get_logger

logger = get_logger()


@dataclass
class Crash:
    """Represents a unique crash."""
    crash_id: str
    input_file: Path
    signal: Optional[str] = None
    stack_hash: Optional[str] = None
    size: int = 0
    timestamp: Optional[float] = None

    def __repr__(self):
        return f"Crash(id={self.crash_id}, signal={self.signal}, size={self.size})"


class CrashCollector:
    """Collects and deduplicates crashes from fuzzing output."""

    def __init__(self, crashes_dir: Path):
        self.crashes_dir = Path(crashes_dir)
        if not self.crashes_dir.exists():
            raise FileNotFoundError(f"Crashes directory not found: {crashes_dir}")

    def collect_crashes(
        self,
        max_crashes: Optional[int] = None,
        stack_hasher: Optional[Callable[[Path], Optional[str]]] = None,
    ) -> List[Crash]:
        """
        Collect unique crashes from AFL output.

        Deduplication key: the crash's stack hash when analysis is
        available (``stack_hasher`` — e.g. a wrapper over
        ``CrashAnalyser._compute_stack_hash`` on the debugger trace),
        falling back to the input-file content hash otherwise. Two
        different inputs hitting the same bug share a stack hash but
        never an input hash, so the fallback under-dedups — callers
        with a debugger available should pass ``stack_hasher``.

        ``max_crashes`` bounds the number of UNIQUE crashes returned.
        The cap is applied after dedup: pre-fix the file list was
        sliced first, so duplicate inputs consumed the budget and a
        directory whose first N files were duplicates starved the
        collection of distinct crashes that sorted later.

        Args:
            max_crashes: Maximum number of unique crashes to collect
            stack_hasher: Optional callable mapping a crash input file
                to a stack hash (or None when analysis fails); enables
                root-cause dedup instead of input-content dedup

        Returns:
            List of Crash objects
        """
        logger.info("Collecting crashes from: %s", self.crashes_dir)

        crash_files = sorted([
            f for f in self.crashes_dir.iterdir()
            if f.name.startswith("id:") and f.is_file()
        ])

        if not crash_files:
            logger.warning("No crashes found!")
            return []

        logger.info("Found %d crash files", len(crash_files))

        crashes = []
        seen_keys = set()

        for crash_file in crash_files:
            if max_crashes is not None and len(crashes) >= max_crashes:
                break

            crash = self._parse_crash_file(crash_file)

            if stack_hasher is not None and not crash.stack_hash:
                try:
                    crash.stack_hash = stack_hasher(crash_file) or None
                except Exception as e:  # noqa: BLE001 — analysis is best-effort; fall back to input hash
                    logger.debug(
                        "stack_hasher failed for %s: %s", crash_file.name, e,
                    )

            # Namespace the key so a stack hash can never collide with
            # an input hash (both are hex prefixes).
            if crash.stack_hash:
                key = ("stack", crash.stack_hash)
            else:
                key = ("input", self._hash_file(crash_file))

            if key not in seen_keys:
                crashes.append(crash)
                seen_keys.add(key)
            else:
                logger.debug("Skipping duplicate crash: %s", crash_file.name)

        logger.info("Collected %d unique crashes", len(crashes))

        return crashes

    def _parse_crash_file(self, crash_file: Path) -> Crash:
        """Parse crash metadata from filename and content."""
        # AFL crash format: id:000000,sig:06,src:000000,op:havoc,rep:16
        parts = crash_file.stem.split(",")

        crash_id = None
        signal = None

        for part in parts:
            if part.startswith("id:"):
                crash_id = part.split(":")[1]
            elif part.startswith("sig:"):
                signal = part.split(":")[1]

        size = crash_file.stat().st_size
        timestamp = crash_file.stat().st_mtime

        return Crash(
            crash_id=crash_id or crash_file.stem,
            input_file=crash_file,
            signal=signal,
            size=size,
            timestamp=timestamp,
        )

    def _hash_file(self, file_path: Path) -> str:
        """Short SHA-256 hash of file (first 16 hex chars)."""
        return sha256_file(file_path)[:16]

    def rank_crashes_by_exploitability(self, crashes: List[Crash]) -> List[Crash]:
        """
        Rank crashes by likely exploitability.

        Signal priority (most to least exploitable):
        - 11 (SIGSEGV): Memory access violation
        - 6 (SIGABRT): Assertion failure / heap corruption
        - 4 (SIGILL): Invalid instruction
        - 8 (SIGFPE): Floating point exception
        """
        signal_priority = {
            "11": 1,  # SIGSEGV - highest priority
            "06": 2,  # SIGABRT
            "04": 3,  # SIGILL
            "08": 4,  # SIGFPE
        }

        def crash_priority(crash: Crash) -> int:
            return signal_priority.get(crash.signal, 99)

        ranked = sorted(crashes, key=crash_priority)

        logger.info("Crash ranking:")
        for idx, crash in enumerate(ranked[:10], 1):
            signal_name = self._signal_name(crash.signal)
            logger.info("  %s. %s - %s", idx, crash.crash_id, signal_name)

        return ranked

    def _signal_name(self, signal: Optional[str]) -> str:
        """Convert signal number to name."""
        signal_names = {
            "04": "SIGILL (Illegal Instruction)",
            "05": "SIGTRAP (Trace/Breakpoint Trap)",
            "06": "SIGABRT (Abort)",
            "07": "SIGBUS (Bus Error)",
            "08": "SIGFPE (Floating Point Exception)",
            "11": "SIGSEGV (Segmentation Fault)",
        }
        return signal_names.get(signal, f"Signal {signal}" if signal else "Unknown")
