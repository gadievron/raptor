"""Accesses need object provenance, compatible types and an executed path."""
import json
import shutil
import subprocess
from types import SimpleNamespace

import pytest

from core.detectors.scalar_aliasing import scalar_access_proofs
from core.detectors.budget import WorkBudget

_SOURCE = b"""
int direct(float value) { return *(int*)&value; }
int indirect(float value) { int *p=(int*)&value; return *p; }
int write_access(void) { int value=1; *(float*)&value=2.0f; return value; }
int cast_only(float value) { int *p=(int*)&value; return 0; }
int dead(float value) { if (0) return *(int*)&value; return 0; }
int after_return(float value) { return 0; return *(int*)&value; }
unsigned int corresponding(int value) { return *(unsigned int*)&value; }
char character(int value) { return *(char*)&value; }
int size_only(float value) { return sizeof(*(int*)&value); }
int round_trip(float value) { int *p=(int*)&value; float *q=(float*)p; return 0; }
float round_trip_read(float value) { int *p=(int*)&value; float *q=(float*)p; return *q; }
int reassigned(float value) { int other=1; int *p=(int*)&value; p=&other; return *p; }
void stop(void);
int interrupted(float value) { int *p=(int*)&value; stop(); return *p; }
typedef int alias_int __attribute__((may_alias));
int allowed_alias(float value) { return *(alias_int*)&value; }
int union_access(float value) { union { float f; int i; } u; u.f=value; return u.i; }
int unknown(float *value) { return *(int*)value; }
int uninitialized(void) { float value; return *(int*)&value; }
int branches(float value, int take) { if(take) return *(int*)&value; return 0; }
"""


@pytest.fixture(scope="module")
def parsed(tmp_path_factory):
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("Clang required for owned-source parser controls")
    path = tmp_path_factory.mktemp("scalar-aliasing") / "owned.c"
    path.write_bytes(_SOURCE)
    proc = subprocess.run([clang, "-fsyntax-only", "-Xclang", "-ast-dump=json", str(path)],
                          capture_output=True, timeout=15, check=True)
    return json.loads(proc.stdout)


def test_native_ast_proves_only_supported_actual_accesses(parsed):
    proofs = scalar_access_proofs(parsed, _SOURCE)
    assert {p["function"] for p in proofs} == {"direct", "indirect", "write_access"}
    indirect = next(p for p in proofs if p["function"] == "indirect")
    assert indirect["declared_type"] == "float" and indirect["access_type"] == "int"
    assert indirect["identifiers"] == ["value", "p"]


def test_proof_offsets_use_utf8_bytes(parsed):
    # A byte offset in this AST cannot be interpreted against shorter input.
    assert scalar_access_proofs(parsed, b"short") == []


def test_ast_node_budget_fails_closed(monkeypatch):
    from core.detectors import scalar_aliasing as detector
    monkeypatch.setattr(detector, "_MAX_NODES", 2)
    with pytest.raises(ValueError):
        scalar_access_proofs({"inner": [{"inner": []}, {"inner": []}]}, b"abc")


def test_unknown_ast_shape_fails_closed():
    with pytest.raises(ValueError):
        scalar_access_proofs({"inner": "unexpected"}, b"abc")


@pytest.mark.parametrize("kind", ["IfStmt", "WhileStmt", "CallExpr", "GCCAsmStmt", "UnaryExprOrTypeTraitExpr"])
def test_unsupported_body_discards_every_partial_proof(parsed, kind):
    copied = json.loads(json.dumps(parsed))
    functions = [n for n in copied["inner"] if n.get("kind") == "FunctionDecl" and n.get("name") == "write_access"]
    function = functions[0]
    body = next(n for n in function["inner"] if n["kind"] == "CompoundStmt")
    body["inner"].insert(-1, {"kind": kind})
    assert not any(p["function"] == "write_access" for p in scalar_access_proofs(copied, _SOURCE))


@pytest.mark.parametrize("failure", ["preprocess", "missing_provenance", "redirect", "macro_redirect",
    "header_redirect", "compiler_attribute", "pragma", "ast_exit", "ast_size", "ast_json",
    "timeout", "isolation", "expired"])
def test_failed_or_ambiguous_corroboration_preserves_candidates(tmp_path, monkeypatch, failure):
    from core.audit.preprocessor_view import ExpandedView
    from core.detectors import scalar_aliasing as detector
    target = tmp_path / "repo"
    target.mkdir()
    source = "int f(float value) { return *(int*)&value; }\n"
    (target / "a.c").write_text(source)
    original = source
    if failure == "redirect": original = '#line 1 "a.c"\n' + source
    if failure == "macro_redirect": original = '#define FILE "a.c"\n#line 1 FILE\n' + source
    if failure == "compiler_attribute": original = '__attribute__((optimize("no-strict-aliasing")))\n' + source
    (target / "a.c").write_text(original)
    files = ("a.c",)
    if failure == "header_redirect":
        (target / "empty.h").write_text('#line 1 "a.c"\n')
        files += ("empty.h",)
    if failure == "missing_provenance": files = ()
    view = ExpandedView(ok=failure != "preprocess", file_path="a.c", text=source,
                        line_map=(("a.c", 1), None), source_files=files)
    if failure == "pragma": view.text = '#pragma GCC optimize("no-strict-aliasing")\n' + source
    monkeypatch.setattr("core.audit.preprocessor_view.expand_translation_unit", lambda **kw: view)
    if failure == "ast_size": monkeypatch.setattr(detector, "_MAX_AST_BYTES", 8)
    calls = []
    def run(cmd, **kw):
        calls.append(kw)
        assert kw["block_network"] and kw["target"] == kw["output"] == kw["cwd"]
        assert kw["limits"]["max_file_mb"] == 8
        if failure == "timeout": raise subprocess.TimeoutExpired(cmd, 1)
        if failure == "isolation": raise RuntimeError("isolation refused")
        kw["stdout"].write(b"invalid JSON" if failure == "ast_json" else b" " * 16)
        return SimpleNamespace(returncode=1 if failure == "ast_exit" else 0)
    candidates = [{"file": "a.c", "line": 1}]
    budget = WorkBudget(10)
    if failure == "expired": budget.deadline = 0
    result = detector.corroborate_aliasing(target, "a.c", candidates, gcc="/trusted/gcc",
        clang="/trusted/clang", sandbox_run=run, budget=budget, scratch_root=str(tmp_path))
    assert not result.proofs and result.limitations
    assert candidates == [{"file": "a.c", "line": 1}]
    assert not list(tmp_path.glob("scalar_aliasing_*"))


def test_preprocessor_records_empty_header_before_redirect(tmp_path):
    from core.audit.preprocessor_view import _parse_linemarked_output
    (tmp_path / "a.c").write_text("int a;\n")
    (tmp_path / "empty.h").write_text('#line 1 "a.c"\n')
    sources = set()
    _parse_linemarked_output('# 1 "empty.h" 1\n# 1 "a.c"\nint a;\n',
                             tmp_path, tmp_path, source_files=sources)
    assert sources == {"a.c", "empty.h"}


def test_preprocessor_source_provenance_has_a_bound(tmp_path):
    from core.audit.preprocessor_view import _parse_linemarked_output
    sources = set()
    for i in range(100): (tmp_path / f"h{i}.h").write_text("")
    _parse_linemarked_output("".join(f'# 1 "h{i}.h"\n' for i in range(100)),
                             tmp_path, tmp_path, source_files=sources)
    assert len(sources) == 65  # explicit overflow sentinel, not a complete 64-file set


def test_prepared_view_budget_accounts_for_provenance():
    from core.audit.preprocessor_view import ExpandedView
    from core.detectors.setup import PreparedViews
    small = ExpandedView(ok=True, file_path="a.c", text="int a;\n")
    cache = PreparedViews()
    assert cache.put(("a",), small)
    budget = cache.retained_bytes
    large = ExpandedView(ok=True, file_path="a.c", text="int a;\n", source_files=("x" * 4000,))
    assert not PreparedViews(max_bytes=budget).put(("a",), large)


@pytest.mark.parametrize("late_failure", [False, True])
def test_duplicate_warning_points_are_bounded_and_late_failures_export_nothing(tmp_path, monkeypatch, late_failure):
    from core.audit.preprocessor_view import ExpandedView
    from core.detectors import scalar_aliasing as detector
    source = "int f(float value) { return *(int*)&value; }\n"
    (tmp_path / "a.c").write_text(source)
    view = ExpandedView(ok=True, file_path="a.c", text=source, line_map=(("a.c", 1), None), source_files=("a.c",))
    monkeypatch.setattr("core.audit.preprocessor_view.expand_translation_unit", lambda **kw: view)
    proof = {"line": 1, "cast_start": 1, "cast_end": 1, "object": "value"}
    monkeypatch.setattr(detector, "scalar_access_proofs", lambda *a: [proof, {}] if late_failure else [proof])
    def run(cmd, **kw):
        kw["stdout"].write(b"{}")
        return SimpleNamespace(returncode=0)
    result = detector.corroborate_aliasing(tmp_path, "a.c", [{"file": "a.c", "line": 1}] * 10000,
        gcc="gcc", clang="clang", sandbox_run=run, budget=WorkBudget(10), scratch_root=str(tmp_path))
    assert result.complete is not late_failure
    assert len(result.proofs) == (0 if late_failure else 1)
