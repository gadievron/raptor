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
        """Add a seed input to corpus."""
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

    def create_from_directory(self, source_dir: Path) -> int:
        """Copy all files from source directory to corpus."""
        source = Path(source_dir)
        if not source.exists():
            raise FileNotFoundError(f"Source directory not found: {source_dir}")

        count = 0
        for file in source.rglob("*"):
            if file.is_file():
                dest = self.corpus_dir / file.relative_to(source)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(file.read_bytes())
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
