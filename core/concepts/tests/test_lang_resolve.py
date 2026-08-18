"""Per-language study resolution — core/concepts/lang_resolve.py.

Fixture trees are built under tmp_path; no LLM, no subprocess.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.concepts.lang_resolve import (
    STUDY_LANGUAGES,
    STUDY_SUFFIXES,
    extract_question_identifiers,
    identifier_tail,
    is_study_supported_path,
    language_for_path,
    resolve_concept_docs,
    resolve_identifiers,
)
from core.testing import requires_ts

# ------------------------------------------------------------------
# Language support surface
# ------------------------------------------------------------------

class TestLanguageSupport:
    def test_first_class_languages_supported(self) -> None:
        for lang in ("python", "go", "java", "javascript", "typescript", "rust"):
            assert lang in STUDY_LANGUAGES

    def test_suffixes_cover_first_class_languages(self) -> None:
        for suffix in (".py", ".go", ".java", ".js", ".ts", ".tsx", ".rs"):
            assert suffix in STUDY_SUFFIXES

    def test_c_is_not_routed_here(self) -> None:
        assert language_for_path("a.c") is None
        assert language_for_path("a.hpp") is None

    def test_c_still_study_supported_overall(self) -> None:
        assert is_study_supported_path("a.c")
        assert is_study_supported_path("a.cpp")
        assert is_study_supported_path("pkg/mod.py")
        assert is_study_supported_path("x.rs")

    def test_unsupported_language(self) -> None:
        assert language_for_path("a.rb") is None
        assert not is_study_supported_path("a.rb")
        assert not is_study_supported_path("a.lua")

    def test_identifier_tail(self) -> None:
        assert identifier_tail("json.loads") == "loads"
        assert identifier_tail("Vec::new") == "new"
        assert identifier_tail("plain") == "plain"


# ------------------------------------------------------------------
# Question identifier extraction
# ------------------------------------------------------------------

class TestExtractQuestionIdentifiers:
    def test_backticks_first(self) -> None:
        out = extract_question_identifiers(
            "Does `json.loads` reject NaN by default?",
        )
        assert out[0] == "json.loads"

    def test_dotted_and_double_colon(self) -> None:
        out = extract_question_identifiers(
            "Does http.Client.Do follow redirects and does Vec::with_capacity zero?",
        )
        assert "http.Client.Do" in out
        assert "Vec::with_capacity" in out

    def test_snake_and_camel_case(self) -> None:
        out = extract_question_identifiers(
            "Does parse_config validate before RateLimiter fires?",
        )
        assert "parse_config" in out
        assert "RateLimiter" in out

    def test_prose_words_ignored(self) -> None:
        out = extract_question_identifiers(
            "does the buffer overflow when input is long",
        )
        assert out == []

    def test_context_contributes(self) -> None:
        out = extract_question_identifiers(
            "Is the retry bounded?", "verdict depends on MAX_RETRIES",
        )
        assert "MAX_RETRIES" in out


# ------------------------------------------------------------------
# Fixture helpers
# ------------------------------------------------------------------

def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


# ------------------------------------------------------------------
# Python
# ------------------------------------------------------------------

class TestPythonResolution:
    @pytest.fixture()
    def tree(self, tmp_path: Path) -> Path:
        _write(tmp_path, "pkg/config.py", '''\
MAX_RETRIES = 5

def parse_config(path):
    """Parse the config file.

    Raises ValueError on malformed input.
    """
    return validate_schema(open(path).read())

class ConfigStore:
    """Holds parsed configuration."""

    def load(self, path):
        """Load and cache."""
        return parse_config(path)
''')
        return tmp_path

    def test_function_with_docstring(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["parse_config"])
        assert len(res.items) == 1
        it = res.items[0]
        assert it.kind == "function"
        assert it.file == "pkg/config.py"
        assert "Raises ValueError" in it.doc_comment
        assert "def parse_config" in it.definition
        assert "validate_schema" in it.calls
        assert not res.unresolved

    def test_method_via_qualified_name(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["ConfigStore.load"])
        assert [it.name for it in res.items] == ["load"]
        assert res.items[0].doc_comment == "Load and cache."
        assert res.items[0].related_items == ["ConfigStore"]

    def test_qualified_mismatch_not_guessed(self, tree: Path) -> None:
        # OtherClass.load does not exist — the ConfigStore method must
        # NOT be offered as its definition.
        res = resolve_identifiers(tree, ["OtherClass.load"])
        assert res.items == []
        assert len(res.unresolved) == 1

    def test_class_resolution(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["ConfigStore"])
        assert len(res.items) == 1
        assert res.items[0].kind == "struct"
        assert "Holds parsed configuration" in res.items[0].doc_comment

    def test_module_constant(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["MAX_RETRIES"])
        assert len(res.items) == 1
        assert "MAX_RETRIES = 5" in res.items[0].definition

    def test_callers_populated(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["parse_config"])
        assert "load" in res.items[0].callers


class TestPythonMonkeyPatching:
    def test_monkey_patch_marked_unresolvable(self, tmp_path: Path) -> None:
        _write(tmp_path, "patch.py", '''\
import json

json.loads = lambda s: s
''')
        res = resolve_identifiers(tmp_path, ["json.loads"])
        assert res.items == []
        assert len(res.unresolved) == 1
        assert "monkey-patching" in res.unresolved[0]["reason"] or (
            "dynamic attribute assignment" in res.unresolved[0]["reason"]
        )

    def test_setattr_marked_unresolvable(self, tmp_path: Path) -> None:
        _write(tmp_path, "patch.py", '''\
import target

setattr(target, "frobnicate", lambda: None)
''')
        res = resolve_identifiers(tmp_path, ["target.frobnicate"])
        assert res.items == []
        assert "monkey-patching" in res.unresolved[0]["reason"]


# ------------------------------------------------------------------
# Go
# ------------------------------------------------------------------

class TestGoResolution:
    @pytest.fixture()
    def tree(self, tmp_path: Path) -> Path:
        _write(tmp_path, "server/header.go", '''\
package server

// MaxHeaderLen bounds the header buffer.
const MaxHeaderLen = 512

// Header is one parsed wire header.
type Header struct {
	Len int
}

// ParseHeader parses one wire header.
// It returns an error when the length field exceeds MaxHeaderLen.
func ParseHeader(b []byte) (*Header, error) {
	return decodeHeader(b)
}
''')
        return tmp_path

    def test_function_with_doc_comment(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["ParseHeader"])
        assert len(res.items) == 1
        it = res.items[0]
        assert it.kind == "function"
        assert "returns an error" in it.doc_comment

    @requires_ts("go")
    def test_function_calls_extracted(self, tree: Path) -> None:
        # Callee extraction needs a tree — without the go grammar the
        # resolver still yields the item, docs and definition, but the
        # calls list stays coarse.
        res = resolve_identifiers(tree, ["ParseHeader"])
        assert "decodeHeader" in res.items[0].calls

    def test_struct_type(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["Header"])
        assert res.items[0].kind == "struct"
        assert "type Header struct" in res.items[0].definition
        assert "parsed wire header" in res.items[0].doc_comment

    def test_constant(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["MaxHeaderLen"])
        assert "const MaxHeaderLen = 512" in res.items[0].definition
        assert "bounds the header buffer" in res.items[0].doc_comment


# ------------------------------------------------------------------
# Java
# ------------------------------------------------------------------

class TestJavaResolution:
    @pytest.fixture()
    def tree(self, tmp_path: Path) -> Path:
        _write(tmp_path, "src/Util.java", '''\
public class Util {
    public static final int MAX_DEPTH = 32;

    /**
     * Sanitizes a path against traversal.
     * @param p raw path
     */
    public static String sanitizePath(String p) {
        return p.replace("..", "");
    }
}
''')
        return tmp_path

    def test_method_with_javadoc(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["Util.sanitizePath"])
        assert len(res.items) == 1
        assert "Sanitizes a path" in res.items[0].doc_comment
        assert res.items[0].kind == "function"

    def test_class(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["Util"])
        assert res.items[0].kind == "struct"

    def test_static_final_constant(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["MAX_DEPTH"])
        assert len(res.items) == 1
        assert "MAX_DEPTH = 32" in res.items[0].definition


# ------------------------------------------------------------------
# JavaScript / TypeScript
# ------------------------------------------------------------------

class TestJsTsResolution:
    @pytest.fixture()
    def tree(self, tmp_path: Path) -> Path:
        _write(tmp_path, "src/helpers.ts", '''\
export const RETRY_LIMIT = 3;

/** Escape HTML entities in user input. */
export function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;");
}

/** Token-bucket limiter. */
export class RateLimiter {
  take(): boolean { return true; }
}
''')
        _write(tmp_path, "src/legacy.js", '''\
// Old-style sanitizer used by the legacy pages.
function legacySanitize(input) {
  return String(input).trim();
}
''')
        return tmp_path

    def test_ts_function(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["escapeHtml"])
        assert len(res.items) == 1
        assert "Escape HTML entities" in res.items[0].doc_comment

    def test_ts_class(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["RateLimiter"])
        assert res.items[0].kind == "struct"
        assert "Token-bucket limiter" in res.items[0].doc_comment

    def test_ts_const(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["RETRY_LIMIT"])
        assert "RETRY_LIMIT = 3" in res.items[0].definition

    def test_js_function(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["legacySanitize"])
        assert len(res.items) == 1
        assert "legacy pages" in res.items[0].doc_comment


# ------------------------------------------------------------------
# Rust
# ------------------------------------------------------------------

class TestRustResolution:
    @pytest.fixture()
    def tree(self, tmp_path: Path) -> Path:
        _write(tmp_path, "src/frame.rs", '''\
/// Upper bound on frame size.
pub const MAX_FRAME: usize = 4096;

/// A decoded frame.
pub struct Frame {
    len: usize,
}

/// Decode a frame from the wire.
///
/// Returns Err on truncated input.
pub fn decode_frame(buf: &[u8]) -> Result<Frame, Error> {
    parse_prefix(buf)
}
''')
        return tmp_path

    def test_function_with_triple_slash_doc(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["decode_frame"])
        assert len(res.items) == 1
        assert "Returns Err on truncated input" in res.items[0].doc_comment

    @requires_ts("rust")
    def test_function_calls_extracted(self, tree: Path) -> None:
        # Same contract as the Go twin: calls need the rust grammar.
        res = resolve_identifiers(tree, ["decode_frame"])
        assert "parse_prefix" in res.items[0].calls

    def test_struct(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["Frame"])
        assert res.items[0].kind == "struct"
        assert "A decoded frame" in res.items[0].doc_comment

    def test_const(self, tree: Path) -> None:
        res = resolve_identifiers(tree, ["MAX_FRAME"])
        assert "MAX_FRAME: usize = 4096" in res.items[0].definition


# ------------------------------------------------------------------
# Unresolvable semantics
# ------------------------------------------------------------------

class TestUnresolvable:
    def test_missing_identifier_has_reason(self, tmp_path: Path) -> None:
        _write(tmp_path, "a.py", "def real():\n    pass\n")
        res = resolve_identifiers(tmp_path, ["totally_missing_fn"])
        assert res.items == []
        assert len(res.unresolved) == 1
        rec = res.unresolved[0]
        assert rec["name"] == "totally_missing_fn"
        assert "not found" in rec["reason"]

    def test_referenced_but_undefined(self, tmp_path: Path) -> None:
        _write(tmp_path, "a.py", "x = external_helper(1)\n")
        res = resolve_identifiers(tmp_path, ["external_helper"])
        assert res.items == []
        assert "no static definition" in res.unresolved[0]["reason"]

    def test_empty_tree(self, tmp_path: Path) -> None:
        res = resolve_identifiers(tmp_path, ["anything_here"])
        assert res.items == []
        assert "no study-resolvable source files" in res.unresolved[0]["reason"]

    def test_no_identifiers_no_output(self, tmp_path: Path) -> None:
        res = resolve_identifiers(tmp_path, [])
        assert res.items == []
        assert res.unresolved == []

    def test_vendor_dirs_skipped(self, tmp_path: Path) -> None:
        _write(tmp_path, "node_modules/lib/index.js",
               "function vendored() {}\n")
        res = resolve_identifiers(tmp_path, ["vendored"])
        assert res.items == []


# ------------------------------------------------------------------
# Concept docs
# ------------------------------------------------------------------

class TestConceptDocs:
    def test_readme_matched(self, tmp_path: Path) -> None:
        _write(tmp_path, "README.md",
               "# proj\nThe rate limiter uses a token bucket that refills "
               "every second.\n")
        docs = resolve_concept_docs(
            tmp_path, ["How does the rate limiter token bucket refill?"],
        )
        assert len(docs) == 1
        assert docs[0]["file"].endswith("README.md")
        assert "reason" in docs[0]

    def test_docs_dir_matched(self, tmp_path: Path) -> None:
        _write(tmp_path, "docs/protocol.md",
               "Frame lengths are validated against MAX_FRAME before "
               "decode_frame runs.\n")
        docs = resolve_concept_docs(
            tmp_path, ["Is MAX_FRAME enforced before decode_frame?"],
        )
        assert any(d["file"].endswith("protocol.md") for d in docs)

    def test_irrelevant_docs_ignored(self, tmp_path: Path) -> None:
        _write(tmp_path, "docs/changelog.md", "v1.0 first release\n")
        docs = resolve_concept_docs(
            tmp_path, ["How does the scheduler assign priorities?"],
        )
        assert docs == []

    def test_no_questions(self, tmp_path: Path) -> None:
        assert resolve_concept_docs(tmp_path, []) == []


# ------------------------------------------------------------------
# Study-list merge
# ------------------------------------------------------------------

class TestMergeIntoStudyList:
    def _item(self, name: str, file: str = "a.py", line: int = 1):
        from core.concepts.model import StudyItem
        return StudyItem(
            id=f"python_function_{name}_{file}_{line}",
            kind="function", name=name, file=file, line=line,
            definition=f"def {name}(): ...",
        )

    def test_creates_skeleton_when_missing(self, tmp_path: Path) -> None:
        import json

        from core.concepts.lang_resolve import merge_into_study_list
        p = tmp_path / "study-list.json"
        added = merge_into_study_list(p, [self._item("fn_a")])
        assert added == 1
        data = json.loads(p.read_text())
        assert data["items"][0]["name"] == "fn_a"

    def test_merges_into_existing(self, tmp_path: Path) -> None:
        import json

        from core.concepts.lang_resolve import merge_into_study_list
        p = tmp_path / "study-list.json"
        p.write_text(json.dumps({
            "target": "/t", "source_root": "/t",
            "items": [{"id": "c_fn_x", "name": "fn_x",
                       "file": "x.c", "line": 3}],
        }))
        added = merge_into_study_list(p, [self._item("fn_a")])
        assert added == 1
        data = json.loads(p.read_text())
        assert {i["name"] for i in data["items"]} == {"fn_x", "fn_a"}
        assert data["target"] == "/t"

    def test_dedups_by_id_and_location(self, tmp_path: Path) -> None:
        from core.concepts.lang_resolve import merge_into_study_list
        p = tmp_path / "study-list.json"
        merge_into_study_list(p, [self._item("fn_a")])
        assert merge_into_study_list(p, [self._item("fn_a")]) == 0

    def test_related_docs_and_unresolved_merged(self, tmp_path: Path) -> None:
        import json

        from core.concepts.lang_resolve import merge_into_study_list
        p = tmp_path / "study-list.json"
        merge_into_study_list(
            p, [],
            related_docs=[{"file": "README.md", "reason": "r"}],
            unresolved=[{"name": "ghost", "reason": "not found",
                         "questions": ["Does ghost exist?"]}],
        )
        data = json.loads(p.read_text())
        assert data["related_docs"][0]["file"] == "README.md"
        assert data["unresolved_identifiers"][0]["name"] == "ghost"
        # merging the same records again does not duplicate
        merge_into_study_list(
            p, [],
            related_docs=[{"file": "README.md", "reason": "r"}],
            unresolved=[{"name": "ghost", "reason": "not found"}],
        )
        data = json.loads(p.read_text())
        assert len(data["related_docs"]) == 1
        assert len(data["unresolved_identifiers"]) == 1
