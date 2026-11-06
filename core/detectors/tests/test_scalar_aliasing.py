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
int reassigned_access(float value) { int other=1; int *p=&other; p=(int*)&value; return *p; }
int saved_alias(float value) { int other=1; int *p=(int*)&value; int *q=p; p=&other; return *q; }
int assigned_alias(float value) { int other=1; int *p=(int*)&value; int *q=&other; q=p; p=&other; return *q; }
int self_assignment(float value) { int *p=(int*)&value; p=p; return *p; }
int overwritten_alias(float value) { int other=1; int *p=(int*)&value; int *q=p; p=&other; q=p; return *q; }
int scalar_update(float value) { value=1; return *(int*)&value; }
int alias_after_store(float value) { int *p=(int*)&value; value=1; return *p; }
int stored_read(float value) { int other=1; other=*(int*)&value; return other; }
int unused_after_store(float value) { int *p=(int*)&value; value=1; return 0; }
unsigned int compatible_after_store(int value) { unsigned int *p=(unsigned int*)&value; value=2; return *p; }
int float_initializer(void) { float value=1.0; return *(int*)&value; }
int float_to_integer(int value) { return *(float*)&value; }
double float_widening(int value) { return *(float*)&value; }
int numeric_only(float value) { return (int)value; }
double numeric_widening(float value) { return (double)value; }
int unused_float_initializer(void) { float value=1.0; int *p=(int*)&value; return 0; }
int assigned_initializer(void) { float value; value=1; return *(int*)&value; }
int alias_before_initializer(void) { float value; int *p=(int*)&value; value=1; return *p; }
int read_before_initializer(void) { float value; float copy=value; value=1; return *(int*)&value; }
int indirect_initializer(void) { float value; float *p=&value; *p=1; return *(int*)&value; }
int other_initializer(void) { float value; float other; other=1; return *(int*)&value; }
int incompatible_initial_store(void) { int value; *(float*)&value=1; return 0; }
int unused_indirect_initializer(void) { float value; int *q=(int*)&value; float *p=&value; *p=1; return 0; }
int read_during_indirect_initializer(void) { float value; float *p=&value; *p=*p; return *(int*)&value; }
int other_indirect_initializer(void) { float value; float other; float *p=&other; *p=1; return *(int*)&value; }
int character_initializer(void) { int value='x'; return *(float*)&value; }
int complemented_access(float value) { return ~*(int*)&value; }
int negated_access(float value) { return !*(int*)&value; }
int character_only(void) { int value='x'; return value; }
int complement_only(int value) { return ~value; }
int negate_only(float value) { return !value; }
int unused_character_initializer(void) { int value='x'; float *p=(float*)&value; return 0; }
void stop(void);
int interrupted(float value) { int *p=(int*)&value; stop(); return *p; }
typedef int alias_int __attribute__((may_alias));
int allowed_alias(float value) { return *(alias_int*)&value; }
int union_access(float value) { union { float f; int i; } u; u.f=value; return u.i; }
int unknown(float *value) { return *(int*)value; }
int uninitialized(void) { float value; return *(int*)&value; }
int branches(float value, int take) { if(take) return *(int*)&value; return 0; }
"""


# Native tool startup belongs to the slow tier; retain one AST per worker
# even when randomized test ordering revisits this module.
@pytest.fixture(scope="session")
def parsed(tmp_path_factory):
    clang = shutil.which("clang")
    if clang is None:
        pytest.skip("Clang required for owned-source parser controls")
    path = tmp_path_factory.mktemp("scalar-aliasing") / "owned.c"
    path.write_bytes(_SOURCE)
    proc = subprocess.run([clang, "-fsyntax-only", "-Xclang", "-ast-dump=json", str(path)],
                          capture_output=True, timeout=60, check=True)
    return json.loads(proc.stdout)


@pytest.mark.slow
def test_native_ast_proves_only_supported_actual_accesses(parsed):
    proofs = scalar_access_proofs(parsed, _SOURCE)
    assert {p["function"] for p in proofs} == {
        "direct", "indirect", "write_access", "reassigned_access", "saved_alias", "assigned_alias", "self_assignment",
        "scalar_update", "alias_after_store", "stored_read",
        "float_initializer", "float_to_integer", "float_widening",
        "assigned_initializer", "alias_before_initializer",
        "indirect_initializer", "incompatible_initial_store",
        "character_initializer", "complemented_access", "negated_access",
    }
    indirect = next(p for p in proofs if p["function"] == "indirect")
    assert indirect["declared_type"] == "float" and indirect["access_type"] == "int"
    assert indirect["identifiers"] == ["value", "p"]


@pytest.mark.slow
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
@pytest.mark.slow
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


@pytest.mark.slow
def test_sparse_proof_locations_do_not_index_every_source_newline(parsed):
    padding = b"\n" * 100_000
    shifted = json.loads(json.dumps(parsed))
    pending = [shifted]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if "offset" in value:
                value["offset"] += len(padding)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    counted = []

    class MeasuredSource(bytes):
        def __iter__(self):
            pytest.fail("must not build an index of every source newline")

        def count(self, sub, start=0, end=None):
            counted.append((start, end))
            return super().count(sub, start, end)

    original = scalar_access_proofs(parsed, _SOURCE)
    actual = scalar_access_proofs(shifted, MeasuredSource(padding + _SOURCE))
    assert original and len(actual) == len(original)
    expected = [dict(proof, **{key: proof[key] + 100_000
                              for key in ("line", "cast_start", "cast_end")})
                for proof in original]
    assert actual == expected
    assert counted and counted[0][0] == 0
    assert all(left[1] == right[0] for left, right in zip(counted, counted[1:]))
    assert counted[-1][1] <= len(padding + _SOURCE)


def test_no_proofs_require_no_source_line_scan():
    class UnscannedSource(bytes):
        def __iter__(self):
            pytest.fail("no-proof input must not build a source line index")

        def count(self, *args):
            pytest.fail("no-proof input needs no line numbers")

    assert scalar_access_proofs({"inner": []}, UnscannedSource(b"\n" * 100_000)) == []


@pytest.mark.parametrize("nested", [False, True])
def test_wide_ast_is_refused_before_children_are_queued(monkeypatch, nested):
    from core.detectors import scalar_aliasing as detector

    class UnqueuedChildren(list):
        def __iter__(self):
            pytest.fail("over-budget children must not be materialized in the pending stack")

    children = UnqueuedChildren([{}] * 8)
    ast = {"inner": children}
    if nested:
        ast = {"inner": [{}, ast]}  # A sibling is already pending.
    monkeypatch.setattr(detector, "_MAX_NODES", 8)
    with pytest.raises(detector._Unsupported, match="AST shape/cap"):
        scalar_access_proofs(ast, b"abc")


@pytest.mark.parametrize("extra", [-1, 0, 1])
def test_ast_admission_counts_pending_siblings_at_node_budget_boundary(monkeypatch, extra):
    from core.detectors import scalar_aliasing as detector

    # Root, one pending sibling, a branch and its children all consume nodes.
    ast = {"inner": [{}, {"inner": [{}] * (5 + extra)}]}
    monkeypatch.setattr(detector, "_MAX_NODES", 8)
    if extra > 0:
        with pytest.raises(detector._Unsupported, match="AST shape/cap"):
            scalar_access_proofs(ast, b"abc")
    else:
        assert scalar_access_proofs(ast, b"abc") == []
