"""cvefix bridge: fix-diff hunks -> recall manifest + fp-only twin."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from core.recall.cvefix_manifest import (
    CvefixManifestError,
    CvefixSpec,
    generate_manifests,
    main as cvefix_main,
    parse_fix_hunks,
)
from core.recall.manifest import parse_manifest

_VULN = """public class Query {
    void run(String user) throws Exception {
        String q = "SELECT * FROM t WHERE u='" + user + "'";
        stmt.execute(q);
    }
}
"""

_FIXED = """public class Query {
    void run(String user) throws Exception {
        PreparedStatement ps =
            conn.prepareStatement("SELECT * FROM t WHERE u=?");
        ps.setString(1, user);
        ps.execute();
    }
}
"""


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True,
        text=True, check=True).stdout


def _make_fix_repo(tmp_path: Path) -> tuple[Path, str]:
    repo = tmp_path / "proj"
    (repo / "src").mkdir(parents=True)
    (repo / "src/Query.java").write_text(_VULN, encoding="utf-8")
    (repo / "README.md").write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)],
                   check=True)
    env = ["-c", "user.email=t@example.org", "-c", "user.name=t"]
    subprocess.run(["git", "-C", str(repo), *env, "add", "-A"],
                   check=True)
    subprocess.run(["git", "-C", str(repo), *env, "commit", "-qm",
                    "vulnerable"], check=True)
    (repo / "src/Query.java").write_text(_FIXED, encoding="utf-8")
    (repo / "README.md").write_text("y\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), *env, "add", "-A"],
                   check=True)
    subprocess.run(["git", "-C", str(repo), *env, "commit", "-qm",
                    "fix CVE-2020-99999"], check=True)
    fix = _git(repo, "rev-parse", "HEAD").strip()
    return repo, fix


def _spec(repo: Path, fix: str) -> CvefixSpec:
    return CvefixSpec.from_dict({
        "cve_id": "CVE-2020-99999",
        "repo_url": "https://example.org/proj",
        "fix_commit": fix,
        "local_clone": str(repo),
        "language": "java",
        "cwe": "CWE-89",
    })


class TestSpecGate:
    def test_bad_cve_id_refused(self, tmp_path):
        with pytest.raises(CvefixManifestError, match="CVE id"):
            CvefixSpec.from_dict({
                "cve_id": "GHSA-xxxx", "repo_url": "u",
                "fix_commit": "a" * 40, "local_clone": "c",
                "language": "java", "cwe": "CWE-89"})

    def test_short_sha_refused(self):
        with pytest.raises(CvefixManifestError, match="40-hex"):
            CvefixSpec.from_dict({
                "cve_id": "CVE-2020-99999", "repo_url": "u",
                "fix_commit": "abc123", "local_clone": "c",
                "language": "java", "cwe": "CWE-89"})


class TestHunks:
    def test_java_only_and_pure_addition_sides(self):
        diff = (
            "--- a/src/A.java\n+++ b/src/A.java\n"
            "@@ -10,2 +10,0 @@\n-x\n-y\n"
            "@@ -20,0 +19,3 @@\n+a\n+b\n+c\n"
            "--- a/doc.md\n+++ b/doc.md\n"
            "@@ -1 +1 @@\n-o\n+n\n")
        spans = parse_fix_hunks(diff, (".java",))
        assert len(spans) == 2
        assert spans[0].pre == (10, 11) and spans[0].post is None
        assert spans[1].pre is None and spans[1].post == (19, 21)


class TestGenerate:
    def test_manifest_pair_shapes(self, tmp_path):
        repo, fix = _make_fix_repo(tmp_path)
        recall_m, twin = generate_manifests(_spec(repo, fix))
        # recall manifest: pre-fix pin, candidate expected, review field
        assert recall_m["target"]["pinned_sha"] == _git(
            repo, "rev-parse", "HEAD^").strip()
        assert recall_m["expected"], "pre-image spans expected"
        e = recall_m["expected"][0]
        assert e["review"] == "unreviewed-candidate"
        assert e["provenance"] == {
            "kind": "cve", "cve_id": "CVE-2020-99999",
            "fix_commit": fix}
        assert e["file"] == "src/Query.java"
        assert "corrupt the FN gate" in recall_m["notes"]["label_caveat"]
        # both parse (public-provenance gate + fp-only schema)
        parsed = parse_manifest(json.loads(json.dumps(recall_m)))
        assert parsed.corpus_kind == "recall"
        twin_parsed = parse_manifest(json.loads(json.dumps(twin)))
        assert twin_parsed.corpus_kind == "fp-only"
        assert not twin_parsed.expected
        assert twin_parsed.clean_regions
        assert twin["target"]["pinned_sha"] == fix

    def test_merge_commit_refused(self, tmp_path):
        repo, fix = _make_fix_repo(tmp_path)
        env = ["-c", "user.email=t@example.org", "-c", "user.name=t"]
        subprocess.run(["git", "-C", str(repo), "checkout", "-qb",
                        "side", "HEAD^"], check=True)
        (repo / "other.txt").write_text("s\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), *env, "add", "-A"],
                       check=True)
        subprocess.run(["git", "-C", str(repo), *env, "commit", "-qm",
                        "side"], check=True)
        subprocess.run(["git", "-C", str(repo), "checkout", "-q",
                        "main"], check=True)
        subprocess.run(["git", "-C", str(repo), *env, "merge", "-q",
                        "--no-ff", "-m", "merge", "side"], check=True)
        merge = _git(repo, "rev-parse", "HEAD").strip()
        with pytest.raises(CvefixManifestError, match="single-parent"):
            generate_manifests(_spec(repo, merge))

    def test_non_java_only_fix_refused(self, tmp_path):
        repo, fix = _make_fix_repo(tmp_path)
        env = ["-c", "user.email=t@example.org", "-c", "user.name=t"]
        (repo / "README.md").write_text("z\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), *env, "add", "-A"],
                       check=True)
        subprocess.run(["git", "-C", str(repo), *env, "commit", "-qm",
                        "docs only"], check=True)
        docs = _git(repo, "rev-parse", "HEAD").strip()
        with pytest.raises(CvefixManifestError, match="touches no"):
            generate_manifests(_spec(repo, docs))

    def test_cli_end_to_end(self, tmp_path, capsys):
        repo, fix = _make_fix_repo(tmp_path)
        spec_path = tmp_path / "spec.json"
        spec_path.write_text(json.dumps({
            "cve_id": "CVE-2020-99999",
            "repo_url": "https://example.org/proj",
            "fix_commit": fix,
            "local_clone": str(repo),
            "language": "java",
            "cwe": "CWE-89",
        }), encoding="utf-8")
        out = tmp_path / "corpus"
        rc = cvefix_main(["--spec", str(spec_path),
                          "--out-dir", str(out)])
        assert rc == 0
        assert "hand-verify" in capsys.readouterr().out
        pre = json.loads(
            (out / "cve-2020-99999-prefix.json").read_text())
        post = json.loads(
            (out / "cve-2020-99999-postfix.json").read_text())
        assert pre["name"] == "cvefix-CVE-2020-99999"
        assert post["corpus_kind"] == "fp-only"


class TestHostileCloneConfig:
    @pytest.mark.skipif(
        shutil.which("git") is None, reason="git not installed",
    )
    def test_hostile_diff_external_not_executed(self, tmp_path):
        """A hostile clone's .git/config must not execute commands.

        The clone is internet-sourced; its config can name arbitrary
        programs (diff.external, core.fsmonitor, core.pager). The
        bridge's git invocations must neutralise them — the canary
        below fires if `git diff` honours the repo-configured
        external diff driver.
        """
        repo, fix = _make_fix_repo(tmp_path)
        canary = tmp_path / "canary"
        evil = tmp_path / "evil.sh"
        evil.write_text(
            "#!/bin/sh\n"
            f"touch '{canary}'\n"
        )
        evil.chmod(0o755)
        for key in ("diff.external", "core.fsmonitor", "core.pager"):
            subprocess.run(
                ["git", "-C", str(repo), "config", key, str(evil)],
                check=True)

        recall_m, twin = generate_manifests(_spec(repo, fix))

        assert not canary.exists(), (
            "hostile .git/config command executed during manifest "
            "generation"
        )
        # The hardening must not break the actual work: the fix diff
        # still yields candidate labels.
        assert recall_m["expected"]
        assert twin["clean_regions"]
