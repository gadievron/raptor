"""Negative control: "path traversal" keyword family (Python).

os.path.join followed by realpath containment check — the joined path
is verified to stay under the base directory before open().
"""

import os
from pathlib import Path


def read_within(base, name):
    path = os.path.realpath(os.path.join(base, name))
    base_real = os.path.realpath(base)
    if not path.startswith(base_real + os.sep):
        msg = "path escapes base directory"
        raise ValueError(msg)
    with Path(path).open() as f:
        return f.read()
