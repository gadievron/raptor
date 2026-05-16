"""Tests for cve_diff/diffing/extraction_agreement.py — cross-check verdicts."""
from __future__ import annotations

from cve_diff.core.models import (
    CommitSha,
    DiffBundle,
    FileChange,
    RepoRef,
)
from cve_diff.diffing import extraction_agreement as ea


def _bundle(*, files: list[str], bytes_size: int) -> DiffBundle:
    return DiffBundle(
        cve_id="CVE-X",
        repo_ref=RepoRef(
            repository_url="https://github.com/acme/widget",
            fix_commit="deadbeef" * 5,
            introduced=None,
            canonical_score=100,
        ),
        commit_before=CommitSha("c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"),
        commit_after=CommitSha("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
        diff_text="x" * bytes_size,
        files_changed=len(files),
        bytes_size=bytes_size,
        files=tuple(
            FileChange(path=p, is_test=False, hunks_count=1) for p in files
        ),
    )


def test_compare_pair_agree_on_identical_paths_and_bytes() -> None:
    clone = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1000)
    api = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1010)  # 1% delta
    assert ea._compare_pair(clone, api) == "agree"


def test_compare_pair_partial_when_paths_almost_match() -> None:
    clone = _bundle(files=["a", "b", "c", "d", "e"], bytes_size=1000)
    api = _bundle(files=["a", "b", "c", "d"], bytes_size=900)  # 4 of 5 paths
    assert ea._compare_pair(clone, api) == "partial"


def test_compare_pair_disagrees_when_no_overlap() -> None:
    clone = _bundle(files=["src/a.c"], bytes_size=1000)
    api = _bundle(files=["docs/changelog.md"], bytes_size=200)
    assert ea._compare_pair(clone, api) == "disagree"


def test_compare_pair_partial_when_api_truncated() -> None:
    """API caps at ~300 files — large refactors aren't real disagreements."""
    clone_paths = [f"src/file_{i}.c" for i in range(500)]
    api_paths = clone_paths[:300]  # API truncated
    clone = _bundle(files=clone_paths, bytes_size=200_000)
    api = _bundle(files=api_paths, bytes_size=120_000)
    assert ea._compare_pair(clone, api) == "partial"


def test_compute_returns_none_for_unsupported_forge() -> None:
    """Forges without an API extractor (savannah cgit, googlesource,
    sourceware) return None — caller renders ``single_source``. GitHub
    and gitlab.* are supported and would dispatch to a live API call;
    a cgit URL is the canonical "no API extractor" case."""
    ref = RepoRef(
        repository_url="https://git.savannah.gnu.org/cgit/bash.git",
        fix_commit="deadbeef" * 5,
        introduced=None,
        canonical_score=100,
    )
    clone = _bundle(files=["a.c"], bytes_size=100)
    assert ea.compute_extraction_agreement("CVE-X", ref, clone) is None


def test_compute_returns_none_when_no_extras_available(monkeypatch) -> None:
    """Dispatcher returns an empty list (no second source for this forge,
    or every extractor failed) → ``compute_extraction_agreement`` returns
    None. Auxiliary check only — never blocks the pipeline."""
    monkeypatch.setattr(ea, "extract_for_agreement", lambda *_a, **_kw: [])

    ref = RepoRef(
        repository_url="https://github.com/acme/widget",
        fix_commit="deadbeef" * 5,
        introduced=None,
        canonical_score=100,
    )
    clone = _bundle(files=["a.c"], bytes_size=100)
    assert ea.compute_extraction_agreement("CVE-X", ref, clone) is None


def test_compute_returns_extras_list_on_success(monkeypatch) -> None:
    """``compute_extraction_agreement`` returns ``(agreement, extras)``
    where ``extras`` is a list of ``(method_name, DiffBundle)`` tuples —
    one per second-source that succeeded. The caller persists each
    bundle's diff body as ``<cve>.<method>.patch``."""
    api = _bundle(files=["a.c"], bytes_size=100)
    patch = _bundle(files=["a.c"], bytes_size=100)
    monkeypatch.setattr(
        ea, "extract_for_agreement",
        lambda *_a, **_kw: [("github_api", api), ("patch_url", patch)],
    )

    ref = RepoRef(
        repository_url="https://github.com/acme/widget",
        fix_commit="deadbeef" * 5,
        introduced=None,
        canonical_score=100,
    )
    clone = _bundle(files=["a.c"], bytes_size=100)
    result = ea.compute_extraction_agreement("CVE-X", ref, clone)
    assert result is not None
    agreement, extras = result
    assert isinstance(agreement, dict)
    assert agreement["verdict"] == "agree"
    # All three sources reported in the summary
    assert len(agreement.get("sources") or []) == 3
    src_names = {s["name"] for s in agreement["sources"]}
    assert src_names == {"clone", "github_api", "patch_url"}
    # Extras are passed through so the caller can persist each .patch
    methods = [m for m, _ in extras]
    assert methods == ["github_api", "patch_url"]


# ---- N-source agreement (3-source + cgit 2-source) -----------------------

def test_summarize_three_source_all_agree() -> None:
    """3 sources all match — top-level verdict is `agree` and all
    pairwise verdicts are `agree`."""
    clone = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1000)
    api = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1010)
    patch = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1000)
    out = ea._summarize_n([("clone", clone), ("github_api", api),
                           ("patch_url", patch)])
    assert out["verdict"] == "agree"
    # 3 pairwise verdicts: (clone,api), (clone,patch_url), (api,patch_url)
    pw = out["pairwise"]
    assert len(pw) == 3
    assert all(v == "agree" for v in pw.values())
    # Each source listed with its files+bytes
    assert len(out["sources"]) == 3


def test_summarize_three_source_two_of_three_agree() -> None:
    """2 sources match, 1 differs — verdict is ``2/3 agree`` and the
    outlier method is named in the dict so the renderer can surface
    'API differs' specifically."""
    clone = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1000)
    patch = _bundle(files=["src/a.c", "src/b.c"], bytes_size=1000)
    # API differs on paths AND bytes
    api = _bundle(files=["docs/CHANGELOG.md"], bytes_size=200)
    out = ea._summarize_n([("clone", clone), ("github_api", api),
                           ("patch_url", patch)])
    # Top-level verdict marks majority agreement
    assert out["verdict"] == "majority_agree"
    # Outlier identified by method name
    assert out.get("outliers") == ["github_api"]


def test_summarize_three_source_all_disagree() -> None:
    """No two sources agree — verdict is `disagree`."""
    clone = _bundle(files=["src/a.c"], bytes_size=1000)
    api = _bundle(files=["docs/x.md"], bytes_size=500)
    patch = _bundle(files=["build/y.bin"], bytes_size=2000)
    out = ea._summarize_n([("clone", clone), ("github_api", api),
                           ("patch_url", patch)])
    assert out["verdict"] == "disagree"


def test_summarize_two_source_clone_plus_patch_url_for_cgit() -> None:
    """cgit (kernel.org) has no JSON API, but it DOES have a patch URL.
    With 2 sources (clone + patch_url) we get a real verdict — first
    cross-check coverage on cgit-hosted CVEs."""
    clone = _bundle(files=["mm/slub.c"], bytes_size=4000)
    patch = _bundle(files=["mm/slub.c"], bytes_size=4000)
    out = ea._summarize_n([("clone", clone), ("patch_url", patch)])
    assert out["verdict"] == "agree"
    assert len(out["sources"]) == 2
    src_names = {s["name"] for s in out["sources"]}
    assert src_names == {"clone", "patch_url"}
