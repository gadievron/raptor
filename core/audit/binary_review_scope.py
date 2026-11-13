"""Live binary-module stamps for review dispatch, never checker evidence.

A module stamp binds observed file bytes and their physical version. It does
not establish extraction correspondence, image base, ABI or build closure.
It is transient and must not be restored from model output or journal JSON.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import re
from pathlib import Path

from .knowledge_requests import KnowledgeOrigin


@dataclass(frozen=True)
class BinaryModuleSnapshot:
    path: Path
    resolved_path: Path
    sha256: str
    version: tuple[int, ...]

    def current(self) -> bool:
        return capture_binary_module(self.path) == self


def capture_binary_module(path: Path | str) -> BinaryModuleSnapshot | None:
    """Capture a stable regular module using the existing full-content reader.

    A project container is not its selected binary. Until a selected module
    is available explicitly it remains unknown here. Before/after checks are
    best effort; they do not make a mutable module immutable.
    """
    from .binary_context import _binary_content_version, _target_content_sha

    try:
        candidate = Path(path).absolute()
        if candidate.suffix.lower() == ".gpr":
            return None
        resolved = candidate.resolve()
        before = _binary_content_version(candidate.stat())
        digest = _target_content_sha(candidate)
        if (digest is None or candidate.resolve() != resolved
                or _binary_content_version(candidate.stat()) != before):
            return None
        return BinaryModuleSnapshot(candidate, resolved, digest, before)
    except (OSError, ValueError, TypeError, RuntimeError):
        return None


@dataclass(frozen=True)
class BinaryReviewPublicationScope:
    """One recorded binary occurrence and its original live module bytes.

    Address and size are recorded view metadata, not a decoded extent, FID,
    image-base proof or correspondence between instructions and decompilation.
    """
    module: BinaryModuleSnapshot
    file: str
    function: str
    address: int
    size: int
    context_digest: str | None = None
    # Transient pipeline view ownership, never reconstructed from journal data.
    view_context: dict | None = field(default=None, compare=False, repr=False)
    view_identity: BinaryInputIdentity | None = None

    def record(self) -> dict:
        value = {"version": 1, "domain": "binary_module", "file": self.file,
                 "function": self.function, "module_sha256": self.module.sha256,
                 "address": self.address, "size": self.size}
        return {**value, "context_digest": self.context_digest} if self.context_digest is not None else value

    def matches(self, outcome, gap: dict) -> bool:
        from .record import _as_int

        from .binary_context_inputs import binary_context_record_digest

        result = getattr(outcome, "review_result", None) or {}
        history = result.get("review_claims")
        has_context = isinstance(history, dict) and "binary_inputs" in history
        if has_context != (self.context_digest is not None):
            return False
        if has_context:
            from .review_claims import read_history

            retained = read_history(history)
            if (retained is None or not isinstance(self.context_digest, str)
                    or _SHA256.fullmatch(self.context_digest) is None
                    or binary_context_record_digest(retained.get("binary_inputs")) != self.context_digest):
                return False
        metadata = gap.get("metadata")
        metadata = metadata if isinstance(metadata, dict) else {}
        address = gap.get("address", metadata.get("address"))
        size = gap.get("size", metadata.get("size"))
        return ((outcome.file, outcome.function) == (self.file, self.function)
                and type(outcome.line) is int and outcome.line == 0
                and gap.get("file") == self.file
                and gap.get("name", gap.get("function")) == self.function
                and type(gap.get("line_start", 0)) is int and gap.get("line_start", 0) == 0
                and (gap.get("line_end") is None
                     or type(gap.get("line_end")) is int and gap.get("line_end") == 0)
                # Gap projections may omit address/size. The collector also
                # requires the checklist-derived full anchor to match this
                # scope, so an omitted projection never supplies an extent.
                and (address is None or _as_int(address) == self.address)
                and (size is None or _as_int(size) == self.size))

    def current(self, target_path) -> bool:
        try:
            if Path(target_path).absolute() != self.module.path or not self.module.current():
                return False
            if self.view_context is None and self.view_identity is None:
                # A contextual assessment cannot fall back to the legacy
                # module-only capability after a lossy transient-field copy.
                return self.context_digest is None
            ctx = self.view_context
            if not isinstance(ctx, dict) or self.view_identity is None:
                return False
            metadata = ctx.get("metadata")
            view_target = ctx.get("target_path")
            if not isinstance(view_target, (str, Path)):
                return False
            return (ctx.get("_binary_module_snapshot") is self.module
                    and Path(view_target).absolute() == self.module.path
                    and (ctx.get("file"), ctx.get("function"), ctx.get("address"))
                        == (self.file, self.function, self.address)
                    and type(ctx.get("address")) is int
                    and isinstance(metadata, dict) and type(metadata.get("size")) is int
                    and metadata["size"] == self.size
                    and capture_binary_input_identity(ctx, self) == self.view_identity)
        except (TypeError, ValueError, OSError, RuntimeError):
            return False

    def anchor(self) -> str:
        plain = self.module_anchor()
        return (f"bin:ctx1:{self.context_digest}:{plain[4:]}"
                if self.context_digest is not None else plain)

    def module_anchor(self) -> str:
        from .record import binary_item_hash

        value = binary_item_hash({"sha256": self.module.sha256},
                                 {"address": self.address, "size": self.size})
        assert value is not None
        return value


def capture_binary_publication_scope(ctx: dict, module: BinaryModuleSnapshot) -> BinaryReviewPublicationScope | None:
    from core.inventory.binary_builder import BINARY_PATH_PREFIX

    file, function = ctx.get("file"), ctx.get("function")
    address = ctx.get("address")
    metadata = ctx.get("metadata")
    size = metadata.get("size") if isinstance(metadata, dict) else None
    if (not isinstance(file, str) or not file.startswith(BINARY_PATH_PREFIX)
            or not isinstance(function, str) or not function
            or type(address) is not int or address < 0 or type(size) is not int or size <= 0):
        return None
    scope = BinaryReviewPublicationScope(module, file, function, address, size)
    identity = capture_binary_input_identity(ctx, scope)
    return (BinaryReviewPublicationScope(module, file, function, address, size,
                view_context=ctx, view_identity=identity) if identity is not None else scope)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class BinaryInputIdentity:
    """Original module and available view inputs, not extraction evidence.

    The physical version is an in-run observation. The view digest covers
    supplied raw text, not its postfit delivery or machine-code fidelity.
    """
    module_sha256: str
    module_version: tuple[int, ...]
    address: int
    size: int
    representation: str
    view_sha256: str
    domain: str = field(default="binary_view", init=False)

    def __post_init__(self):
        if (not isinstance(self.module_sha256, str) or _SHA256.fullmatch(self.module_sha256) is None
                or not isinstance(self.view_sha256, str) or _SHA256.fullmatch(self.view_sha256) is None
                or not isinstance(self.module_version, tuple) or len(self.module_version) != 5
                or any(type(value) is not int for value in self.module_version)
                or type(self.address) is not int or self.address < 0
                or type(self.size) is not int or self.size <= 0
                or self.representation not in ("decompilation", "disassembly")):
            raise ValueError("binary identity requires complete original input stamps")


@dataclass(frozen=True, kw_only=True)
class BinaryKnowledgeOrigin(KnowledgeOrigin):
    """Binary input occurrence; source-line identities remain inapplicable."""
    binary_identity: BinaryInputIdentity

    def __post_init__(self):
        from core.inventory.binary_builder import BINARY_PATH_PREFIX

        if (not isinstance(self.binary_identity, BinaryInputIdentity)
                or self.source_identity is not None
                or type(self.line_start) is not int or self.line_start != 0
                or type(self.line_end) is not int or self.line_end != 0
                or not isinstance(self.pass_id, str) or not self.pass_id
                or not isinstance(self.file, str) or not self.file.startswith(BINARY_PATH_PREFIX)
                or not isinstance(self.function, str) or not self.function):
            raise ValueError("binary origin cannot substitute for a source identity")


def capture_binary_input_identity(ctx: dict, scope: BinaryReviewPublicationScope) -> BinaryInputIdentity | None:
    """Capture input data from a current original scope, never model stamps."""
    source, representation = ctx.get("source"), ctx.get("representation")
    if (not isinstance(source, str) or not source.strip()
            or not isinstance(representation, str) or representation not in ("decompilation", "disassembly")
            or not scope.module.current()):
        return None
    try:
        return BinaryInputIdentity(scope.module.sha256, scope.module.version,
            scope.address, scope.size, representation, sha256(source.encode("utf-8")).hexdigest())
    except (UnicodeEncodeError, ValueError):
        return None


def origin_input_identity(origin: KnowledgeOrigin):
    """Retain the domain; a binary input is never a SourceIdentity."""
    return origin.binary_identity if isinstance(origin, BinaryKnowledgeOrigin) else origin.source_identity


def same_review_snapshot(left: KnowledgeOrigin, right: KnowledgeOrigin) -> bool:
    if not isinstance(left, KnowledgeOrigin) or not isinstance(right, KnowledgeOrigin):
        return False
    if isinstance(left, BinaryKnowledgeOrigin) != isinstance(right, BinaryKnowledgeOrigin):
        return False
    return ((left.file, left.function, left.line_start, left.line_end, origin_input_identity(left))
            == (right.file, right.function, right.line_start, right.line_end, origin_input_identity(right)))
