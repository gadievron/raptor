"""Helpers for building target repos under the sandbox.

Split from `core/sandbox/` because detection logic (toolchain-home
resolution, build-file parsing) isn't sandbox plumbing — it's
filesystem/OS probing that the sandbox's caller composes into the
build subprocess's env. Keeping it here keeps `core/sandbox/` narrow
to the sandbox itself.
"""
