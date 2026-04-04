#!/usr/bin/env python3
"""Directory hashing utilities."""

import hashlib
from pathlib import Path
from typing import Optional

from core.config import RaptorConfig
from core.logging import get_logger

logger = get_logger()


def sha256_tree(root: Path, max_file_size: Optional[int] = None, chunk_size: Optional[int] = None) -> str:
    """
    Hash directory tree with size limits and consistent chunk size.
    
    Args:
        root: Root directory to hash
        max_file_size: Maximum file size to include. 
                      None = use config default (100MB limit)
                      Use a very large number (e.g., 10**12) to disable limit
        chunk_size: Chunk size for reading files. 
                   None = use config default (1MB)
                   Use 8192 for backward compatibility with old recon agent
        
    Returns:
        SHA256 hex digest of the directory tree
        
    Note:
        - Chunk size does NOT affect hash result (only reading efficiency)
        - Large files exceeding max_file_size are skipped and logged
        - For backward compatibility with old recon agent (no file size limit):
          pass max_file_size=10**12 or a very large number
    """
    h = hashlib.sha256()
    skipped_files = []

    # Use config defaults if not specified
    if max_file_size is None:
        max_file_size = RaptorConfig.MAX_FILE_SIZE_FOR_HASH
    if chunk_size is None:
        chunk_size = RaptorConfig.HASH_CHUNK_SIZE

    for p in sorted(root.rglob("*")):
        if p.is_file():
            stat = p.stat()
            # Skip large files if limit is set (and not disabled with huge number)
            if max_file_size is not None and max_file_size < 10**12 and stat.st_size > max_file_size:
                skipped_files.append(str(p.relative_to(root)))
                continue
            h.update(p.relative_to(root).as_posix().encode())
            with p.open("rb") as f:
                for chunk in iter(lambda: f.read(chunk_size), b""):
                    h.update(chunk)
    
    if skipped_files:
        logger.debug(f"Skipped {len(skipped_files)} large files during hashing")
    
    return h.hexdigest()
