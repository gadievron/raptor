"""
Diff extraction: `git diff <before>..<after>` on a local clone.

Plain and thin on purpose — the reference project's `diff_methods.py` and
`edge_case_handler.py` combined to 1000+ LOC that never out-performed the
one-liner (see plan's Port/Rewrite/Discard table).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from core.git import get_safe_git_env

from cve_diff.core.exceptions import AnalysisError
from cve_diff.core.models import CommitSha, DiffBundle, FileChange, RepoRef
from cve_diff.core.path_classifier import is_test_path
from core.url_patterns import GITHUB_REPO_URL_RE, normalize_slug
from cve_diff.diffing import shape_dynamic
from cve_diff.infra import github_client

DEFAULT_TIMEOUT_S = 300

# Per-file source-blob cap for FileChange.before_source / after_source.
# Empirically tuned on the full 128-CVE random_200 PASS set
# (`tools/analyze_stage4.py` A/B, 2026-04-24): at 8 KB, 76 % of files
# hit the cap; at 32 KB, 40 %; at 128 KB, 11.6 % (95-percentile file is
# 128 KB — so one extra doubling wouldn't move the needle). See
# `data/baselines/stage4_tier1_analysis_2026-04-24.md`.
MAX_FILE_BYTES = 128 * 1024


def _slug_of(url: str) -> str | None:
    """Extract GitHub `owner/repo` slug from a repo URL.

    Uses ``GITHUB_REPO_URL_RE`` from ``core.url_re`` (anchored at
    ``https?://github.com/...``). Note: we use ``search`` here, not
    ``match``, to tolerate paths embedded in non-URL strings — the
    legacy regex used ``search`` and we preserve that.
    """
    m = GITHUB_REPO_URL_RE.search(url or "")
    if not m:
        return None
    return normalize_slug(m.group(1))


def extract_diff(
    repo_path: Path,
    cve_id: str,
    ref: RepoRef,
    commit_before: CommitSha,
    commit_after: CommitSha,
    timeout_s: int = DEFAULT_TIMEOUT_S,
    max_file_bytes: int | None = None,
) -> DiffBundle:
    completed = subprocess.run(
        [
            "git", "-C", str(repo_path),
            "diff", "--no-color", "--binary",
            f"{commit_before}..{commit_after}",
        ],
        capture_output=True,
        timeout=timeout_s,
        check=False,
        env=get_safe_git_env(),
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"git diff {commit_before}..{commit_after} failed: "
            f"{completed.stderr.decode('utf-8', errors='replace').strip()}"
        )
    diff_text = completed.stdout.decode("utf-8", errors="replace")

    file_names = _list_files(repo_path, commit_before, commit_after, timeout_s)

    # An empty diff slipping through to `render` would produce an OSV
    # report with files_changed=0 / bytes_size=0 — valid-shaped but
    # empty. Fail fast with AnalysisError so the pipeline's error
    # path surfaces this cleanly (CLI exit 9).
    if not file_names and len(diff_text) == 0:
        raise AnalysisError(
            f"{cve_id}: empty diff ({commit_before[:7]}..{commit_after[:7]}) — "
            "before/after resolve to identical trees; the agent's pick may be "
            "a tag rather than a fix commit"
        )
    shape = shape_dynamic.classify(
        file_names,
        slug=_slug_of(ref.repository_url),
        fetch=github_client.get_languages,
    )
    files = _build_file_changes(
        repo_path, commit_before, commit_after, file_names, diff_text, timeout_s,
        cap_bytes=max_file_bytes if max_file_bytes is not None else MAX_FILE_BYTES,
    )
    return DiffBundle(
        cve_id=cve_id,
        repo_ref=ref,
        commit_before=commit_before,
        commit_after=commit_after,
        diff_text=diff_text,
        files_changed=len(file_names),
        bytes_size=len(diff_text.encode("utf-8")),
        shape=shape,
        files=files,
    )


def _count_hunks_per_file(diff_text: str) -> dict[str, int]:
    """Parse `diff_text` once; return {path_after: hunk_count}.

    A ``diff --git a/X b/Y`` header starts a new file record; hunks are
    ``@@ ... @@`` lines. We key on the `b/` (post-fix) path since it's
    what ``git diff --name-only`` also reports.
    """
    counts: dict[str, int] = {}
    current: str | None = None
    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            # `diff --git a/<before> b/<after>`
            parts = line.split(" b/", 1)
            current = parts[1] if len(parts) == 2 else None
            if current is not None:
                counts.setdefault(current, 0)
        elif line.startswith("@@ ") and current is not None:
            counts[current] = counts.get(current, 0) + 1
    return counts


def _show_blob(repo: Path, sha: CommitSha, path: str, timeout_s: int,
               cap_bytes: int = MAX_FILE_BYTES) -> str | None:
    """Return the file content at `sha:path`, or None if it doesn't exist there.

    Used to populate FileChange.before_source / after_source. `git show`
    returns non-zero for paths that don't exist at that commit (e.g. a
    newly added file has no `before`, a deleted file has no `after`) —
    we treat that as None, not an error.
    """
    completed = subprocess.run(
        ["git", "-C", str(repo), "show", f"{sha}:{path}"],
        capture_output=True, timeout=timeout_s, check=False,
        env=get_safe_git_env(),
    )
    if completed.returncode != 0:
        return None
    raw = completed.stdout
    if len(raw) > cap_bytes:
        raw = raw[:cap_bytes]
    text = raw.decode("utf-8", errors="replace")
    if len(completed.stdout) > cap_bytes:
        text += "\n... [truncated]\n"
    return text


def _build_file_changes(
    repo: Path,
    before: CommitSha,
    after: CommitSha,
    paths: list[str],
    diff_text: str,
    timeout_s: int,
    cap_bytes: int = MAX_FILE_BYTES,
) -> tuple[FileChange, ...]:
    """Materialize per-file details for each path in the diff.

    Cost: 2N+1 git subprocesses (one parse of `diff_text` for hunk counts,
    then `git show <before>:path` and `git show <after>:path` per file).
    At our ~3 files/CVE average, this is negligible next to the existing
    `git diff` call.
    """
    hunk_counts = _count_hunks_per_file(diff_text)
    out: list[FileChange] = []
    for path in paths:
        out.append(FileChange(
            path=path,
            is_test=is_test_path(path),
            hunks_count=hunk_counts.get(path, 0),
            before_source=_show_blob(repo, before, path, timeout_s, cap_bytes),
            after_source=_show_blob(repo, after, path, timeout_s, cap_bytes),
        ))
    return tuple(out)


def _list_files(
    repo_path: Path,
    before: CommitSha,
    after: CommitSha,
    timeout_s: int,
) -> list[str]:
    completed = subprocess.run(
        [
            "git", "-C", str(repo_path),
            "diff", "--name-only", f"{before}..{after}",
        ],
        capture_output=True,
        timeout=timeout_s,
        check=False,
        env=get_safe_git_env(),
    )
    if completed.returncode != 0:
        return []
    text = completed.stdout.decode("utf-8", errors="replace")
    return [line for line in text.splitlines() if line.strip()]
