"""Bind source-study fragments before dispatch and recheck before delivery.

This protects the inputs to semantic explanations. It does not certify an
explanation, a comment, an invariant or the correctness of the target code.
"""

from __future__ import annotations

from dataclasses import asdict, replace
from pathlib import Path
import re
from threading import RLock
from uuid import uuid4

from core.concepts.subject_study import SubjectExplanation, SubjectMaterial, SubjectPacket
from core.source import read_contained
from core.source.lines import join_lf_slice

from .refutation_source import MAX_SOURCE_BYTES, SourceIdentity, capture_source_identity


class StudyInputBindings:
    """Invocation-owned identities for exact material instances.

    Equal snippets from different batches get distinct binding IDs. A later
    read must never refresh the identity of an explanation already produced.
    Bindings are deliberately not reconstructed from model output on resume.
    """

    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self._lock = RLock()
        self._roots = {"target": self.root}
        self._bindings: dict[str, tuple[SubjectMaterial, SourceIdentity, Path]] = {}

    def register_root(self, label: str, root: Path) -> None:
        """Register an explicit pipeline root without rebinding old material."""
        if not isinstance(label, str) or re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label) is None:
            raise ValueError("invalid source-root label")
        resolved = Path(root).resolve()
        with self._lock:
            if label in self._roots and self._roots[label] != resolved:
                raise ValueError("source-root label already names a different root")
            self._roots[label] = resolved

    def bind(self, packet: SubjectPacket, *,
             expected: dict[str, SourceIdentity] | None = None) -> SubjectPacket:
        with self._lock:
            roots = dict(self._roots)
        files = {(material.source_root, material.file) for material in packet.materials}
        snapshots: dict[tuple[str, str], tuple[str, SourceIdentity, Path]] = {}
        for label, file in files:
            root = roots.get(label)
            if root is None:
                continue
            before = capture_source_identity(root, file)
            if before is None:
                continue
            text = read_contained(root, file, max_chars=MAX_SOURCE_BYTES, newline="")
            after = capture_source_identity(root, file)
            if text is not None and before == after:
                # Source-prep locations count LF lines. Bare CR is not a
                # scanner line boundary and must not shift these locations.
                snapshots[(label, file)] = (text.replace("\r\n", "\n"), before, root)
        bound = []
        excluded = []
        for material in packet.materials:
            # The current study formatter sends at most 800 definition
            # characters. This is not a binding for omitted fields/text.
            known = snapshots.get((material.source_root, material.file))
            expected_identity = (expected.get(material.source_item_id or material.material_id)
                                 if expected is not None else None)
            if (known is None or type(material.line) is not int
                    or material.line < 1 or not material.text or len(material.text) > 800
                    or (expected is not None and (expected_identity is None or expected_identity != known[1]))):
                excluded.append(replace(material, binding_id=""))
                continue
            text, identity, root = known
            snippet = material.text.replace("\r\n", "\n")
            window = join_lf_slice(text, material.line - 1, material.line + snippet.count("\n"))
            if not window.startswith(snippet):
                excluded.append(replace(material, binding_id=""))
                continue
            captured = replace(material, binding_id=uuid4().hex)
            with self._lock:
                self._bindings[captured.binding_id] = (captured, identity, root)
            bound.append(captured)
        return replace(packet, materials=tuple(bound), excluded_materials=tuple(excluded))

    def admit(self, answer: SubjectExplanation) -> tuple[bool, str]:
        """Reject unknown, substituted or changed inputs without grading prose."""
        if not answer.materials:
            return False, "no_source_material"
        if not answer.inputs:
            return False, "input_snapshot_unavailable"
        if any(material not in answer.inputs for material in answer.materials):
            return False, "material_not_bound_at_dispatch"
        return self.admit_inputs(answer.inputs)

    def admit_inputs(self, materials: tuple[SubjectMaterial, ...]) -> tuple[bool, str]:
        """Check the captured input packet before a paid call or delivery."""
        if not materials:
            return False, "input_snapshot_unavailable"
        current: dict[tuple[Path, str], SourceIdentity | None] = {}
        # A model's selected citations are not its dependency declaration.
        # An uncited input can still have influenced the explanation.
        for material in materials:
            with self._lock:
                captured = self._bindings.get(material.binding_id)
            if captured is None or captured[0] != material:
                return False, "material_not_bound_at_dispatch"
            key = (captured[2], material.file)
            if key not in current:
                current[key] = capture_source_identity(captured[2], material.file)
            if current[key] is None or current[key] != captured[1]:
                return False, "study_material_changed"
        return True, "source_fragments_unchanged; explanation_remains_untrusted"

    def records(self) -> list[dict]:
        """Export captured inputs, without asserting their current freshness."""
        with self._lock:
            return [{"material": asdict(material), "source_identity": asdict(identity),
                     "source_root": material.source_root, "root": str(root)}
                    for material, identity, root in self._bindings.values()]
