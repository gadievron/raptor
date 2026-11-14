"""Bounded explicit parent input bytes; not an observed execution receipt.

This module does not import sandbox code or run a child. It is restricted
initially to exact built-in strings/containers and absolute executable/cwd
spellings. The bytes would need to be consumed by the same reviewed backend
attempt after its trusted overlays, without later mutation or re-filtering.
Raw environment material stays in memory and must not be persisted or logged.
"""

from dataclasses import dataclass, field
import hashlib
import os
import sys


class InputsUnavailable(ValueError):
    pass


@dataclass(frozen=True)
class ParentExecInputs:
    argv: tuple[bytes, ...] = field(repr=False)
    environment: tuple[tuple[bytes, bytes], ...] = field(repr=False)
    cwd: bytes = field(repr=False)
    sha256: str
    payload_bytes: int
    filesystem_encoding: str
    filesystem_errors: str

    @property
    def authenticated_build(self) -> bool:
        return False

    @property
    def observed_child_context(self) -> bool:
        return False

    def exec_inputs(self) -> tuple[tuple[bytes, ...], dict[bytes, bytes], bytes]:
        """Return fresh container material with the exact captured leaf bytes."""
        return self.argv, dict(self.environment), self.cwd


def snapshot_parent_inputs(argv, environment, cwd, *, max_args: int, max_env: int,
                           max_item_bytes: int, max_total_bytes: int) -> ParentExecInputs:
    """Frame bounded fsencoded bytes without shell parsing or normalization.

    Limits count raw encoded payload, not Python heap or framing overhead.
    Order and exact spellings remain visible. This is neither backend producer
    provenance nor proof of actual child cwd, namespace or successful exec.
    """
    if any(type(cap) is not int or cap < 1
           for cap in (max_args, max_env, max_item_bytes, max_total_bytes)):
        raise InputsUnavailable("invalid_input_budget")
    if type(argv) not in (list, tuple) or not argv or len(argv) > max_args:
        raise InputsUnavailable("argument_count_unavailable")
    if type(environment) is not dict or len(environment) > max_env:
        raise InputsUnavailable("environment_count_unavailable")
    total = 0

    def encode(value):
        nonlocal total
        if type(value) is not str or "\0" in value:
            raise InputsUnavailable("exact_string_unavailable")
        # At least one encoded byte is required per character in this scope;
        # refuse enormous strings before allocating their encoded form.
        if len(value) > max_item_bytes:
            raise InputsUnavailable("input_item_byte_budget")
        try:
            encoded = os.fsencode(value)
        except UnicodeError as exc:
            raise InputsUnavailable("input_encoding_unavailable") from exc
        if len(encoded) > max_item_bytes:
            raise InputsUnavailable("input_item_byte_budget")
        if len(encoded) > max_total_bytes - total:
            raise InputsUnavailable("input_total_byte_budget")
        total += len(encoded)
        return encoded

    # Bound indexed capture even if an external owner mutates a list. This
    # does not claim an atomic snapshot of concurrently changing containers.
    argument_count = len(argv)
    if argument_count < 1 or argument_count > max_args:
        raise InputsUnavailable("argument_count_unavailable")
    try:
        args = tuple(encode(argv[index]) for index in range(argument_count))
    except IndexError as exc:
        raise InputsUnavailable("input_container_changed") from exc
    if len(argv) != argument_count:
        raise InputsUnavailable("input_container_changed")
    directory = encode(cwd)
    if not args[0].startswith(b"/") or not directory.startswith(b"/"):
        raise InputsUnavailable("absolute_execution_spelling_required")
    pairs = []
    names = set()
    try:
        for index, (key, value) in enumerate(environment.items()):
            if index >= max_env:
                raise InputsUnavailable("environment_count_unavailable")
            name, content = encode(key), encode(value)
            if not name or b"=" in name or name in names:
                raise InputsUnavailable("environment_name_ambiguous")
            names.add(name)
            pairs.append((name, content))
    except RuntimeError as exc:
        raise InputsUnavailable("input_container_changed") from exc
    pairs = tuple(pairs)
    digest = hashlib.sha256(b"raptor-parent-exec-inputs\0v1\0")

    def frame(value):
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)

    codec = sys.getfilesystemencoding()
    errors = sys.getfilesystemencodeerrors()
    digest.update(b"F")
    frame(codec.encode("ascii"))
    frame(errors.encode("ascii"))
    digest.update(b"C")
    frame(directory)
    digest.update(b"A")
    digest.update(len(args).to_bytes(8, "big"))
    for value in args:
        frame(value)
    digest.update(b"E")
    digest.update(len(pairs).to_bytes(8, "big"))
    for name, content in pairs:
        frame(name)
        frame(content)
    return ParentExecInputs(args, pairs, directory, digest.hexdigest(), total, codec, errors)
