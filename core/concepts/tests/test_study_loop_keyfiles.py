"""Tests for raptor-study-loop key-file collection, overview inventory,
and project promotion."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

RAPTOR_DIR = Path(__file__).resolve().parents[3]
STUDY_LOOP = str(RAPTOR_DIR / "libexec" / "raptor-study-loop")


def _load_loop_module() -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(
        "raptor_study_loop_keyfiles", STUDY_LOOP,
    )
    spec = importlib.util.spec_from_file_location(
        "raptor_study_loop_keyfiles", STUDY_LOOP, loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_loop = _load_loop_module()


# ------------------------------------------------------------------
# _collect_key_files
# ------------------------------------------------------------------


class TestCollectKeyFilesIdentifiers:
    def test_null_identifiers_do_not_crash(self) -> None:
        """study-prep writes "identifiers": null for concept-only
        studies; the key present with an explicit null must not raise."""
        data = {"identifiers": None, "items": [], "related_docs": []}
        key_files: list[dict[str, str]] = []
        _loop._collect_key_files(data, key_files, set(), "/nonexistent")
        assert key_files == []

    def test_missing_identifiers_key_still_works(self) -> None:
        data = {"items": [], "related_docs": []}
        key_files: list[dict[str, str]] = []
        _loop._collect_key_files(data, key_files, set(), "/nonexistent")
        assert key_files == []

    def test_string_identifiers_with_absolute_doc(self, tmp_path) -> None:
        doc = tmp_path / "guide.md"
        doc.write_text("# foo_ctx design\n\nfoo_ctx lifetime notes.\n",
                       encoding="utf-8")
        data = {
            "identifiers": "foo_ctx",
            "items": [],
            "related_docs": [{"file": str(doc), "reason": "mentions it"}],
        }
        key_files: list[dict[str, str]] = []
        _loop._collect_key_files(data, key_files, set(), str(tmp_path))
        docs = [kf for kf in key_files if kf["role"] == "documentation"]
        assert [kf["file"] for kf in docs] == [str(doc)]


class TestCollectKeyFilesRelativeDocs:
    def test_relative_doc_resolved_against_source_root(
        self, tmp_path, monkeypatch,
    ) -> None:
        """Source-root-relative doc paths must be scored against the
        recorded root, not the process CWD."""
        docs_dir = tmp_path / "docs"
        docs_dir.mkdir()
        (docs_dir / "foo.md").write_text(
            "# foo_ctx design\n\nfoo_ctx foo_ctx foo_ctx\n",
            encoding="utf-8",
        )
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)  # CWD-relative open would miss

        data = {
            "identifiers": "foo_ctx",
            "source_root": str(tmp_path),
            "items": [],
            "related_docs": [{"file": "docs/foo.md", "reason": "r"}],
        }
        key_files: list[dict[str, str]] = []
        _loop._collect_key_files(data, key_files, set(), str(elsewhere))
        docs = [kf for kf in key_files if kf["role"] == "documentation"]
        assert [kf["file"] for kf in docs] == ["docs/foo.md"]

    def test_relative_doc_falls_back_to_target_str(
        self, tmp_path, monkeypatch,
    ) -> None:
        (tmp_path / "readme.md").write_text(
            "# foo_ctx\n\nfoo_ctx notes\n", encoding="utf-8",
        )
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)

        data = {
            "identifiers": "foo_ctx",
            "items": [],
            "related_docs": [{"file": "readme.md", "reason": "r"}],
        }
        key_files: list[dict[str, str]] = []
        _loop._collect_key_files(data, key_files, set(), str(tmp_path))
        docs = [kf for kf in key_files if kf["role"] == "documentation"]
        assert [kf["file"] for kf in docs] == ["readme.md"]


# ------------------------------------------------------------------
# _promote_to_project
# ------------------------------------------------------------------


class TestPromoteToProject:
    def test_no_artifacts_no_success_line(self, tmp_path, capsys) -> None:
        out_dir = tmp_path / "out"
        concepts = tmp_path / "concepts"
        out_dir.mkdir()
        concepts.mkdir()
        _loop._promote_to_project(out_dir, concepts)
        assert "promoted domain model" not in capsys.readouterr().err

    def test_promotes_and_reports(self, tmp_path, capsys) -> None:
        out_dir = tmp_path / "out"
        concepts = tmp_path / "concepts"
        out_dir.mkdir()
        concepts.mkdir()
        (out_dir / "domain-model.json").write_text("{}", encoding="utf-8")
        _loop._promote_to_project(out_dir, concepts)
        assert (concepts / "domain-model.json").is_file()
        assert "promoted domain model" in capsys.readouterr().err


# ------------------------------------------------------------------
# Overview inventory
# ------------------------------------------------------------------


class _FakeClient:
    def __init__(self, result: dict) -> None:
        self._result = result
        self.prompts: list[str] = []

    def generate_structured(self, prompt: str, schema: dict,
                            max_tokens: int = 0) -> SimpleNamespace:
        self.prompts.append(prompt)
        return SimpleNamespace(result=self._result, cost=0.0)


def _fake_llm_module(client: _FakeClient) -> tuple[ModuleType, list]:
    mod = ModuleType("packages.llm_analysis")
    calls: list = []

    def get_client(config=None):
        calls.append(config)
        return client

    mod.get_client = get_client
    return mod, calls


class TestOverviewInventory:
    def test_cpp_only_tree_is_inventoried(self, tmp_path, monkeypatch) -> None:
        (tmp_path / "widget.cpp").write_text(
            "int run() { return 0; }\n", encoding="utf-8")
        (tmp_path / "widget.hpp").write_text(
            "struct Widget {\n  int a;\n};\n", encoding="utf-8")
        client = _FakeClient({
            "subject_title": "Widgets",
            "summary": "widget code",
            "identifiers": ["Widget"],
            "concepts": ["widget ownership"],
        })
        mod, _calls = _fake_llm_module(client)
        monkeypatch.setitem(sys.modules, "packages.llm_analysis", mod)

        idents, concepts, summary, title = _loop._overview_from_directory(
            tmp_path)
        assert idents == ["Widget"]
        assert concepts == ["widget ownership"]
        assert summary == "widget code"
        assert title == "Widgets"
        # The C++ header contributed to the struct inventory in the prompt
        assert "widget.cpp" in client.prompts[0]
        assert "Widget" in client.prompts[0]

    def test_single_file_target_is_inventoried(
        self, tmp_path, monkeypatch,
    ) -> None:
        src = tmp_path / "single.cc"
        src.write_text("int run() { return 0; }\n", encoding="utf-8")
        client = _FakeClient({
            "subject_title": "T",
            "summary": "",
            "identifiers": ["run_state"],
            "concepts": [],
        })
        mod, _calls = _fake_llm_module(client)
        monkeypatch.setitem(sys.modules, "packages.llm_analysis", mod)

        idents, _concepts, _summary, _title = _loop._overview_from_directory(
            src)
        assert idents == ["run_state"]
        assert "single.cc" in client.prompts[0]

    def test_no_source_files_returns_empty_without_llm(
        self, tmp_path, monkeypatch,
    ) -> None:
        (tmp_path / "notes.txt").write_text("prose\n", encoding="utf-8")
        client = _FakeClient({})
        mod, calls = _fake_llm_module(client)
        monkeypatch.setitem(sys.modules, "packages.llm_analysis", mod)

        assert _loop._overview_from_directory(tmp_path) == ([], [], "", "")
        assert calls == []
        assert client.prompts == []
