"""Negative control: "command injection" keyword family (Python).

Fixed program name and argv list — no attacker input reaches the
command line and no shell is involved.
"""

import os


def run_sync():
    os.execvp("sync", ["sync"])  # constant program and arguments
