#!/usr/bin/env python3
"""
Corpus Manager

Manages fuzzing corpus (seed inputs).
"""

from pathlib import Path
from typing import List

from core.logging import get_logger

logger = get_logger()


class CorpusManager:
    """Manages fuzzing corpus."""

    def __init__(self, corpus_dir: Path):
        self.corpus_dir = Path(corpus_dir)
        self.corpus_dir.mkdir(parents=True, exist_ok=True)

    def add_seed(self, data: bytes, name: str) -> Path:
        """Add a seed input to corpus.

        `name` MUST be a single bare filename. Pre-fix
        `self.corpus_dir / name` interpolated whatever the
        caller passed — for `name="../../etc/cron.daily/evil"`
        the joined path escaped corpus_dir entirely. The
        `write_bytes` then created files OUTSIDE the corpus,
        with attacker-supplied content.

        Real attack vector: corpus seeding is sometimes driven
        by automated pipelines that pull seed names from
        external sources (CVE PoC catalogues, fuzzing
        leaderboard exports). A malicious entry with a
        traversal-shaped name plants files anywhere the
        analyser process can write.

        Reject:
          * Names containing `/` or `\\`.
          * `..` segments.
          * NUL bytes.
          * Empty / whitespace-only names.

        Path traversal in seed names is structurally never
        legitimate — corpus seeds are flat-filename by
        convention.
        """
        if (
            not name
            or not name.strip()
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or name in {".", ".."}
            or name.startswith("..")
        ):
            raise ValueError(
                f"corpus seed name must be a single bare filename "
                f"(got {name!r})"
            )
        seed_file = self.corpus_dir / name
        seed_file.write_bytes(data)
        logger.debug(f"Added seed: {name} ({len(data)} bytes)")
        return seed_file

    def add_seeds(self, seeds: List[bytes]) -> int:
        """Add multiple seeds to corpus."""
        for idx, seed in enumerate(seeds):
            self.add_seed(seed, f"seed{idx}")
        logger.info(f"Added {len(seeds)} seeds to corpus")
        return len(seeds)

    # Per-file read cap for create_from_directory. Real fuzzing
    # seeds are kilobytes-to-low-MB; 32 MB allows for unusually
    # large parser inputs (image fuzz corpora etc.) while bounding
    # OOM on a malicious / mislabeled file.
    _MAX_SEED_BYTES = 32 * 1024 * 1024

    def create_from_directory(self, source_dir: Path) -> int:
        """Copy all files from source directory to corpus."""
        import os
        source = Path(source_dir)
        if not source.exists():
            raise FileNotFoundError(f"Source directory not found: {source_dir}")

        # `os.walk(followlinks=False)` instead of `Path.rglob` —
        # `rglob` follows symlinks under Python <3.13. Two failure
        # modes:
        #   1. Symlink loop in source_dir → infinite walk.
        #   2. Symlink pointing at /etc/shadow / /var/log/* → the
        #      `file.read_bytes()` would pull privileged content
        #      into corpus_dir as a "seed" the fuzzer then includes
        #      in its mutation corpus (and eventually exposes via
        #      crash artifacts / coverage reports).
        # Skip leaf symlinks too — a symlinked seed file could
        # still point outside source_dir even with followlinks=False
        # on dirs.
        count = 0
        source_str = str(source)
        for dirpath, _dirnames, filenames in os.walk(source_str, followlinks=False):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                try:
                    if fpath.is_symlink():
                        continue
                    if not fpath.is_file():
                        continue
                    st = fpath.stat()
                except OSError:
                    continue
                if st.st_size > self._MAX_SEED_BYTES:
                    logger.warning(
                        f"corpus_manager: skipping {fpath} "
                        f"({st.st_size} bytes > {self._MAX_SEED_BYTES} cap)"
                    )
                    continue
                dest = self.corpus_dir / fpath.relative_to(source)
                dest.parent.mkdir(parents=True, exist_ok=True)
                # Bounded read — file may have grown between stat and read.
                with open(fpath, "rb") as fh:
                    dest.write_bytes(fh.read(self._MAX_SEED_BYTES + 1)[:self._MAX_SEED_BYTES])
                count += 1

        logger.info(f"Copied {count} files to corpus from {source_dir}")
        return count

    def list_seeds(self) -> List[Path]:
        """List all seeds in corpus."""
        return list(self.corpus_dir.rglob("*"))

    def get_stats(self) -> dict:
        """Get corpus statistics."""
        seeds = self.list_seeds()
        total_size = sum(f.stat().st_size for f in seeds if f.is_file())

        return {
            "num_seeds": len(seeds),
            "total_size": total_size,
            "avg_size": total_size // len(seeds) if seeds else 0,
        }
