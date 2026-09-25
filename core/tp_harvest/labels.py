"""Provenance-gated corpus labels + disclosure-backlog pointers.

Label truth is the defect mechanism, and corpus labels need PUBLIC
provenance — a label for an undisclosed vulnerability would smuggle
the vulnerability's existence (and location) into the private label
store and every artefact derived from it. The gate here is therefore
explicit and DEFAULT-CLOSED:

* The harvest itself never labels. Every newly harvested finding gets
  a disclosure-backlog POINTER record instead (location identity
  only), so the promotion queue is durable without being a label.
* A label is emitted only when the operator flips provenance for one
  specific finding: ``public`` (requires a CVE or an upstream fix
  commit as the public anchor — the same ``cve``/``fix_commit``
  anchors the corpus lint checks) or ``own-target`` (the operator
  asserts the target is their own and disclosable to themselves).

Emitted labels go through :class:`core.audit.corpus.label.FunctionLabel`
so schema validation is the corpus's own, and land in the LOCAL
private label store (``core/audit/corpus/labels/<bug_class>/`` by
convention — never distributed, see the corpus README).
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.audit.corpus.label import FunctionLabel, SourcePin
from core.json import save_json
from core.tp_harvest.records import HarvestRecord

PROVENANCE_PUBLIC = "public"
PROVENANCE_OWN_TARGET = "own-target"
VALID_PROVENANCE = frozenset({PROVENANCE_PUBLIC, PROVENANCE_OWN_TARGET})

BACKLOG_FILENAME = "disclosure-backlog.jsonl"
BACKLOG_REASON = "provenance_not_public"

_SCHEMA_VERSION = 1


class ProvenanceGateError(ValueError):
    """Label emission refused: provenance not established."""


class LabelPinError(ValueError):
    """Label emission refused: no verifiable source pin."""


class LabelExistsError(ValueError):
    """Label emission refused: a label file already exists there."""


def check_provenance(
    provenance: str | None, *, cve: str = "", fix_commit: str = "",
) -> None:
    """The provenance gate. Raises unless labelability is established.

    Default-closed: ``None``/empty/unknown values refuse. ``public``
    additionally requires a public anchor (``cve`` or ``fix_commit``)
    — "public" without evidence of disclosure is just an assertion,
    and the anchors are judged STRIPPED (whitespace-only is not an
    anchor). Both directions are load-bearing: loosening this leaks
    undisclosed findings into the label store; tightening beyond the
    two accepted values would strand the operator's own targets (see
    the two-direction tests in tests/test_labels.py).
    """
    cve = (cve or "").strip()
    fix_commit = (fix_commit or "").strip()
    if not provenance:
        raise ProvenanceGateError(
            "finding is not labelable: provenance not established "
            "(default) — pass an explicit provenance of "
            f"{sorted(VALID_PROVENANCE)} to flip it; undisclosed "
            "findings stay on the disclosure backlog instead"
        )
    if provenance not in VALID_PROVENANCE:
        raise ProvenanceGateError(
            f"unknown provenance {provenance!r}: must be one of "
            f"{sorted(VALID_PROVENANCE)} (refusing, never guessing)"
        )
    if provenance == PROVENANCE_PUBLIC and not (cve or fix_commit):
        raise ProvenanceGateError(
            "provenance 'public' needs a public anchor: pass --cve or "
            "--fix-commit (the corpus lint checks the same anchors)"
        )


def derive_target_pin(target_path: str) -> dict[str, Any] | None:
    """Target VCS snapshot for pin derivation (hardened git probes).

    Thin wrapper over ``core.run.provenance.target_snapshot`` — every
    git call it makes treats the target as untrusted. Returns
    ``{"commit", "dirty", "branch", ...}`` or None.
    """
    from core.run.provenance import target_snapshot

    return target_snapshot(target_path)


def default_labels_base() -> Path:
    """The local private label store the corpus loader reads."""
    import core.audit.corpus.label as corpus_label

    return Path(corpus_label.__file__).parent / "labels"


def _function_id(record: HarvestRecord) -> str:
    """Corpus ``function_id`` convention: ``<file>:<function>``."""
    if record.function:
        return f"{record.file}:{record.function}"
    return f"{record.file}:L{record.line}"


_FNAME_SAFE = re.compile(r"[^A-Za-z0-9_.-]+")


def _label_filename(function_id: str) -> str:
    name = _FNAME_SAFE.sub("_", function_id)
    # Collapse dot runs: with "/" already substituted this is belt-and-
    # braces, but a name carrying ".." should not even LOOK like a
    # traversal component.
    name = re.sub(r"\.{2,}", ".", name).strip("._") or "label"
    return f"{name}.label.json"


def emit_label(
    record: HarvestRecord,
    *,
    bug_class: str,
    rationale: str,
    labeler: str,
    provenance: str | None,
    repo: str,
    sha: str,
    labels_base: Path,
    cve: str = "",
    fix_commit: str = "",
    channel: str = "",
) -> Path:
    """Emit one provenance-flipped finding as a corpus label.

    Runs the provenance gate first; validates through the corpus's
    own :class:`FunctionLabel` schema; refuses to overwrite. ``repo``
    and ``sha`` pin the upstream tree (``sha`` is mandatory — a label
    without a verifiable pin cannot be linted, see the corpus
    ``--stamp`` flow).
    """
    cve = (cve or "").strip()
    fix_commit = (fix_commit or "").strip()
    check_provenance(provenance, cve=cve, fix_commit=fix_commit)
    if not repo or not sha:
        raise LabelPinError(
            "label needs a verifiable SourcePin: repo identity and "
            "commit sha are required (derive the sha from the target "
            "tree or pass it explicitly)"
        )
    label = FunctionLabel(
        function_id=_function_id(record),
        bug_class=bug_class,
        expected_status="finding",
        rationale=rationale,
        source=SourcePin(
            repo=repo,
            sha=sha,
            file=record.file,
            line_start=record.line,
            line_end=record.line,
            span_sha=record.span_sha,
        ),
        labeler=labeler,
        labeled_at=datetime.now(timezone.utc).isoformat(),
        cwe=record.cwe,
        cve=cve,
        fix_commit=fix_commit,
        channel=channel,
    )
    path = labels_base / bug_class / _label_filename(label.function_id)
    if path.exists():
        raise LabelExistsError(
            f"label already exists at {path} — duplicate function_id "
            "records are a corpus error; edit the existing label by hand"
        )
    save_json(path, label.to_dict(), sort_keys=True)
    return path


def backlog_pointer(record: HarvestRecord) -> dict[str, Any]:
    """A disclosure-backlog pointer for a not-labelable finding.

    Location identity + status only — the pointer marks WHAT needs a
    disclosure decision, it does not restate the defect.
    """
    return {
        "schema_version": _SCHEMA_VERSION,
        "harvest_id": record.harvest_id,
        "finding_id": record.finding_id,
        "cwe": record.cwe,
        "vuln_type": record.vuln_type,
        "file": record.file,
        "function": record.function,
        "line": record.line,
        "status": record.status,
        "run_dir": record.run_dir,
        "reason": BACKLOG_REASON,
        "pointed_at": datetime.now(timezone.utc).isoformat(),
    }


def append_backlog_pointer(backlog_path: Path, record: HarvestRecord) -> None:
    """Append one pointer record (one JSON object per line).

    O_NOFOLLOW append: a bare ``open("a")`` FOLLOWS a pre-planted
    symlink at the backlog path — a hostile run dir aimed one at an
    arbitrary host file and the harvest appended into it. With
    O_NOFOLLOW the open refuses (ELOOP) and the refusal propagates
    loudly instead of writing through. Parent-directory symlinks are
    the harvest-entry structure gate's job
    (``core.tp_harvest.harvest`` refuses any symlink under
    ``tp-harvest/`` before writing anything).
    """
    backlog_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(
        str(backlog_path),
        os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
        0o644,
    )
    line = json.dumps(backlog_pointer(record), sort_keys=True) + "\n"
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write(line)
