"""Per-function prose annotations stored as markdown mirroring the
source tree.

An annotation is free-form prose written by the LLM or by a human
operator, attached to one function in one source file. Annotations
are markdown files at ``<base>/<source_path>.md`` containing
``## <function>`` sections, each with an HTML-comment metadata line
and a prose body.

Initial consumers:
  * ``/audit`` (Phase A) — captures hypothesis-then-validate evidence
    per function.
  * ``/understand`` — exploration notes during code-mapping.
  * ``/agentic`` — false-positive triage prose, attached to the
    function the LLM analysed.

Why markdown not JSON:
  * Operator-readable. A reviewer can ``cat`` an annotation file
    and understand what was tested without parsing.
  * Diff-friendly under git. Changes show as text diffs.
  * Free-form body but structured metadata (frontmatter), so Python
    can extract status/cwe while leaving prose untouched.

Design constraints:
  * One annotation file per source file. Avoids per-function file
    explosion.
  * Function name as section heading (``## name``). Class-scoped
    methods qualified as ``ClassName.method_name``.
  * HTML comment immediately under the heading carries machine-
    readable metadata (``<!-- meta: status=clean cwe=CWE-78 -->``).
  * Atomic write via tempfile + rename so concurrent operators
    can't corrupt mid-write.
  * Path-traversal defended: any ``..`` segment in a source path
    raises before touching the filesystem.

Companion design doc: ~/design/audit.md (sections "Annotations
(markdown)", "Annotation location").
"""

from __future__ import annotations

from .models import Annotation
from .storage import (
    annotation_path,
    compute_function_hash,
    iter_all_annotations,
    read_annotation,
    read_file_annotations,
    remove_annotation,
    write_annotation,
)


__all__ = [
    "Annotation",
    "annotation_path",
    "compute_function_hash",
    "iter_all_annotations",
    "read_annotation",
    "read_file_annotations",
    "remove_annotation",
    "write_annotation",
]
