"""Tests for the parser-API pack harvester (WP6 vocab migration).

Hermetic throughout: git-repo harvesting runs against throwaway local
repos built in tmp_path (no network, no stubs needed — the strict
read-only git argv works on local objects), diff-dir harvesting against
fixture diffs written inline.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from core.dataflow.parser_pack_harvest import (
    PROVENANCE_CVE_FIX,
    PROVENANCE_LEGACY,
    HarvestSource,
    dumps_pack,
    extract_fix_functions,
    harvest,
    harvest_diff_dir,
    harvest_git_repo,
    load_pack,
    load_sources,
    main,
    merge_results,
    write_pack,
)

_FIX_DIFF = """\
diff --git a/lib/xmlparse.c b/lib/xmlparse.c
index 111..222 100644
--- a/lib/xmlparse.c
+++ b/lib/xmlparse.c
@@ -10,6 +10,8 @@ static void helperThing(int x)
 context
-old
+new
@@ -100,7 +100,7 @@ enum XML_Status XMLCALL XML_ParseBuffer(XML_Parser parser, int len)
 context
-bad
+good
diff --git a/README.md b/README.md
index 333..444 100644
--- a/README.md
+++ b/README.md
@@ -1,2 +1,2 @@ XML_NotAFunction(ignored)
-docs
+docs2
"""


# --- diff parsing ----------------------------------------------------------


def test_extract_fix_functions_from_hunk_headers():
    names = extract_fix_functions(_FIX_DIFF)
    assert "XML_ParseBuffer" in names
    assert "helperThing" in names            # unfiltered at this layer


def test_extract_ignores_non_c_files():
    names = extract_fix_functions(_FIX_DIFF)
    assert "XML_NotAFunction" not in names   # hunk in README.md


def test_extract_takes_last_call_like_identifier():
    diff = (
        "diff --git a/x.c b/x.c\n"
        "@@ -1,1 +1,1 @@ static int foo(struct bar *b, baz_t qux(void))\n"
        "-a\n+b\n"
    )
    # The context's *last* `name(` is the parameter here — precision is
    # delegated to the api_patterns filter, this layer just extracts.
    assert extract_fix_functions(diff) == {"qux"}


def test_extract_handles_headerless_hunks():
    diff = "diff --git a/x.c b/x.c\n@@ -1,1 +1,1 @@\n-a\n+b\n"
    assert extract_fix_functions(diff) == set()


# --- git-repo harvesting (hermetic local repo) ------------------------------


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True, capture_output=True, text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
            "HOME": str(repo),
        },
    )


@pytest.fixture
def fix_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "expat"
    repo.mkdir()
    _git(repo, "init", "-q")
    src = repo / "xmlparse.c"
    src.write_text(
        "/* fixture parser */\n"
        "#include <stddef.h>\n"
        "\n"
        "enum XML_Status XML_ParseBuffer(XML_Parser p, int len) {\n"
        "    int y = 1;\n"
        "    int z = 2;\n"
        "    int w = 3;\n"
        "    int v = 4;\n"
        "    return y + z + w + v;\n"
        "}\n"
        "\n"
        "static int internalHelper(int x) {\n"
        "    int a = 1;\n"
        "    int b = 2;\n"
        "    int c = 3;\n"
        "    int d = 4;\n"
        "    return a + b + c + d + x;\n"
        "}\n"
    )
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "initial import")
    # A security fix referencing a CVE, inside the public function.
    src.write_text(src.read_text().replace(
        "    return y + z + w + v;\n",
        "    if (len < 0) { return 0; }\n    return y + z + w + v;\n",
    ).replace(
        "    return a + b + c + d + x;\n",
        "    if (x < 0) { return 0; }\n    return a + b + c + d + x;\n",
    ))
    _git(repo, "add", "-A")
    _git(
        repo, "commit", "-q", "-m",
        "Fix out-of-bounds read (CVE-2099-12345)\n\nAlso hardens helper.",
    )
    # An unrelated commit that must not contribute.
    src.write_text(src.read_text() + "/* comment */\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "docs: add comment")
    return repo


def test_harvest_git_repo_extracts_public_api_with_cve(fix_repo: Path):
    source = HarvestSource(
        library="expat", api_patterns=("^XML_",), repo_dir=str(fix_repo),
    )
    result = harvest_git_repo(source)
    assert result.errors == []
    assert result.commits_walked == 1
    assert result.names == {"XML_ParseBuffer": {"CVE-2099-12345"}}


def test_harvest_git_repo_filters_internal_helpers(fix_repo: Path):
    source = HarvestSource(
        library="expat", api_patterns=("^XML_",), repo_dir=str(fix_repo),
    )
    result = harvest_git_repo(source)
    assert "internalHelper" not in result.names


def test_harvest_git_repo_missing_repo_reports_error(tmp_path: Path):
    source = HarvestSource(
        library="x", api_patterns=("^x",), repo_dir=str(tmp_path / "nope"),
    )
    result = harvest_git_repo(source)
    assert result.names == {}
    assert result.errors


def test_harvest_dispatch_requires_an_input():
    result = harvest(HarvestSource(library="x", api_patterns=("^x",)))
    assert result.errors


# --- diff-dir harvesting ----------------------------------------------------


def test_harvest_diff_dir_cve_from_filename(tmp_path: Path):
    (tmp_path / "CVE-2099-11111.diff").write_text(_FIX_DIFF)
    source = HarvestSource(
        library="expat", api_patterns=("^XML_",), diff_dir=str(tmp_path),
    )
    result = harvest_diff_dir(source)
    assert result.names == {"XML_ParseBuffer": {"CVE-2099-11111"}}


def test_harvest_diff_dir_cve_from_sidecar(tmp_path: Path):
    (tmp_path / "fix1.patch").write_text(_FIX_DIFF)
    (tmp_path / "fix1.json").write_text(
        json.dumps({"cve_id": "CVE-2099-22222"})
    )
    source = HarvestSource(
        library="expat", api_patterns=("^XML_",), diff_dir=str(tmp_path),
    )
    result = harvest_diff_dir(source)
    assert result.names["XML_ParseBuffer"] == {"CVE-2099-22222"}


def test_harvest_diff_dir_without_cve_id_still_harvests(tmp_path: Path):
    (tmp_path / "unlabeled.diff").write_text(_FIX_DIFF)
    source = HarvestSource(
        library="expat", api_patterns=("^XML_",), diff_dir=str(tmp_path),
    )
    result = harvest_diff_dir(source)
    assert result.names == {"XML_ParseBuffer": set()}


# --- sources config ---------------------------------------------------------


def test_load_sources_roundtrip(tmp_path: Path):
    cfg = tmp_path / "sources.json"
    cfg.write_text(json.dumps({"sources": [
        {"library": "expat", "api_patterns": ["^XML_"],
         "clone_url": "https://example.invalid/expat.git"},
    ]}))
    sources = load_sources(cfg)
    assert len(sources) == 1
    assert sources[0].library == "expat"
    assert sources[0].compiled_patterns()[0].search("XML_Parse")


def test_load_sources_rejects_incomplete_entries(tmp_path: Path):
    cfg = tmp_path / "sources.json"
    cfg.write_text(json.dumps({"sources": [{"library": "x"}]}))
    with pytest.raises(ValueError):
        load_sources(cfg)


def test_shipped_sources_config_loads():
    from core.dataflow.parser_pack_harvest import DEFAULT_SOURCES_PATH
    sources = load_sources(DEFAULT_SOURCES_PATH)
    libs = {s.library for s in sources}
    assert {"expat", "libxml2", "zlib", "zstd"} <= libs
    for s in sources:
        assert s.clone_url, s.library
        s.compiled_patterns()  # every pattern must compile


# --- pack merge (additive-only) ----------------------------------------------


def _result(library: str, names: dict) -> object:
    from core.dataflow.parser_pack_harvest import HarvestResult
    r = HarvestResult(library=library)
    for n, cves in names.items():
        r.add(n, set(cves))
    return r


def test_merge_is_additive_only():
    pack = {"entries": [
        {"name": "TIFFOpen", "library": "libtiff",
         "provenance": [PROVENANCE_LEGACY], "cves": []},
    ]}
    merged = merge_results(pack, [_result("expat", {"XML_GetBuffer": {"CVE-2099-1"}})])
    names = {e["name"] for e in merged["entries"]}
    # A harvest that saw nothing for libtiff must not drop the entry.
    assert names == {"TIFFOpen", "XML_GetBuffer"}


def test_merge_corroborates_legacy_entry():
    pack = {"entries": [
        {"name": "XML_ParseBuffer", "library": "expat",
         "provenance": [PROVENANCE_LEGACY], "cves": []},
    ]}
    merged = merge_results(
        pack, [_result("expat", {"XML_ParseBuffer": {"CVE-2015-1283"}})],
    )
    (entry,) = merged["entries"]
    assert entry["provenance"] == sorted(
        [PROVENANCE_CVE_FIX, PROVENANCE_LEGACY]
    )
    assert entry["cves"] == ["CVE-2015-1283"]


def test_merge_output_deterministic():
    pack = {"entries": []}
    results = [
        _result("zlib", {"inflateInit2": {"CVE-2099-2"}}),
        _result("expat", {"XML_GetBuffer": {"CVE-2099-1"}}),
    ]
    a = dumps_pack(merge_results(pack, results))
    b = dumps_pack(merge_results(pack, list(reversed(results))))
    assert a == b


def test_merge_drops_malformed_existing_names():
    pack = {"entries": [
        {"name": "not a name!", "library": "x", "provenance": [], "cves": []},
        {"name": "fine_name", "library": "x", "provenance": [], "cves": []},
    ]}
    merged = merge_results(pack, [])
    assert {e["name"] for e in merged["entries"]} == {"fine_name"}


def test_load_pack_skeleton_when_missing(tmp_path: Path):
    pack = load_pack(tmp_path / "nope.json")
    assert pack["pack"] == "parser_apis"
    assert pack["entries"] == []


def test_write_pack_roundtrip(tmp_path: Path):
    path = tmp_path / "sub" / "p.json"
    pack = load_pack(path)
    pack["entries"] = [{
        "name": "XML_GetBuffer", "library": "expat",
        "provenance": [PROVENANCE_CVE_FIX], "cves": ["CVE-2099-1"],
    }]
    write_pack(pack, path)
    again = load_pack(path)
    assert again["entries"] == pack["entries"]
    assert list(tmp_path.glob("sub/*.tmp")) == []  # no droppings


# --- CLI ---------------------------------------------------------------------


def test_main_dry_run_diff_dir(tmp_path: Path, capsys):
    diffs = tmp_path / "diffs"
    diffs.mkdir()
    (diffs / "CVE-2099-33333.diff").write_text(_FIX_DIFF)
    cfg = tmp_path / "sources.json"
    cfg.write_text(json.dumps({"sources": [
        {"library": "expat", "api_patterns": ["^XML_"],
         "diff_dir": str(diffs)},
    ]}))
    pack_path = tmp_path / "pack.json"
    rc = main([
        "--sources", str(cfg), "--pack", str(pack_path), "--dry-run",
    ])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["entries"][0]["name"] == "XML_ParseBuffer"
    assert not pack_path.exists()  # dry-run never writes


def test_main_writes_pack(tmp_path: Path):
    diffs = tmp_path / "diffs"
    diffs.mkdir()
    (diffs / "CVE-2099-44444.diff").write_text(_FIX_DIFF)
    cfg = tmp_path / "sources.json"
    cfg.write_text(json.dumps({"sources": [
        {"library": "expat", "api_patterns": ["^XML_"],
         "diff_dir": str(diffs)},
    ]}))
    pack_path = tmp_path / "pack.json"
    rc = main(["--sources", str(cfg), "--pack", str(pack_path)])
    assert rc == 0
    pack = json.loads(pack_path.read_text())
    assert {e["name"] for e in pack["entries"]} == {"XML_ParseBuffer"}


def test_main_bad_sources_config(tmp_path: Path):
    assert main(["--sources", str(tmp_path / "nope.json")]) == 2
