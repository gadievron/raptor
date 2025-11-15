#!/usr/bin/env python3
"""
RAPTOR Crash Collector

Collects and deduplicates crashes from AFL output.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

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

    def collect_crashes(self, max_crashes: Optional[int] = None) -> List[Crash]:
        """
        Collect unique crashes from AFL output.

        Args:
            max_crashes: Maximum number of crashes to collect

        Returns:
            List of Crash objects
        """
        logger.info(f"Collecting crashes from: {self.crashes_dir}")

        crash_files = sorted([
            f for f in self.crashes_dir.iterdir()
            if f.name.startswith("id:") and f.is_file()
        ])

        if not crash_files:
            logger.warning("No crashes found!")
            return []

        logger.info(f"Found {len(crash_files)} crash files")

        crashes = []
        seen_hashes = set()

        for crash_file in crash_files[:max_crashes] if max_crashes else crash_files:
            crash = self._parse_crash_file(crash_file)

            # Deduplicate by input hash (simple approach)
            # In practice, you'd want stack hash deduplication
            input_hash = self._hash_file(crash_file)

            if input_hash not in seen_hashes:
                crashes.append(crash)
                seen_hashes.add(input_hash)
            else:
                logger.debug(f"Skipping duplicate crash: {crash_file.name}")

        logger.info(f"Collected {len(crashes)} unique crashes")

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
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()[:16]

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
            logger.info(f"  {idx}. {crash.crash_id} - {signal_name}")

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
