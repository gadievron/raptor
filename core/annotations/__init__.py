"""Per-function prose annotations stored as markdown mirroring the
source tree.

An annotation is free-form prose attached to one function in one
source file. Annotations are markdown files at
``<base>/<source_path>.md`` containing ``## <function>`` sections,
each with an HTML-comment metadata line and a prose body.

Annotations are the OPERATOR's layer: they are written through the
``/annotate`` CLI (and the ``/review note`` wrapper), never by
pipelines. LLM review verdicts live in the review journal
(``core.coverage.journal``) — the pre-migration LLM annotation
producers were removed, and machinery only READS annotation files
(feedback vetoes, FP primers, coverage evidence, IRIS promotion,
context slices).

Provenance model (see :mod:`core.annotations.provenance`):
``metadata.source`` is caller-asserted — honest framing: nothing
here proves a human typed the note, and cryptographic
proof-of-human was deliberately rejected as overkill. Instead every
CLI add/edit records the invocation context (which std fds were
TTYs) alongside the claim, so a laundered "human" note is
structurally detectable rather than impossible: readers grant
human-grade weight only to ``source=human`` plus an interactive
stamp (or legacy stamp-less notes), and demote everything else to
their machine/hint tier. A genuinely human but fully-detached add
(cron, all fds redirected) is stamped ``non-tty``; re-run
interactively or accept hint-tier weight.

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

Companion design doc: the design memo (sections "Annotations
(markdown)", "Annotation location").
"""

from __future__ import annotations

from .models import Annotation
from .provenance import (
    INTERACTIVE_TTY,
    LEGACY,
    NON_TTY,
    PROVENANCE_KEYS,
    classify_provenance,
    detect_invocation_context,
    is_human_grade,
)
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
    "INTERACTIVE_TTY",
    "LEGACY",
    "NON_TTY",
    "PROVENANCE_KEYS",
    "Annotation",
    "annotation_path",
    "classify_provenance",
    "compute_function_hash",
    "detect_invocation_context",
    "is_human_grade",
    "iter_all_annotations",
    "read_annotation",
    "read_file_annotations",
    "remove_annotation",
    "write_annotation",
]
