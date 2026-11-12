"""Owned JSON read-version controls; no binary analysis backend executes."""
import hashlib
import json
import os

import pytest

import core.audit.binary_context as context


def _doc(note, binary="fixture.bin", digest=None):
    metadata = {"analysis_note": note}
    if digest is not None:
        metadata["binary_sha256"] = digest
    return json.dumps({"source_tool": "r2", "binary_path": binary,
                       "functions": [], "metadata": metadata})


def _change(path, before):
    path.write_text(_doc("after!"))
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
    assert path.stat().st_ctime_ns != before.st_ctime_ns


def test_analysis_change_during_parse_cannot_be_cached_as_the_original_version(tmp_path, monkeypatch):
    from packages.ghidra.model import REDatabase
    artifact = tmp_path / "re-database.json"
    artifact.write_text(_doc("before"))
    before = artifact.stat()
    real_parse = REDatabase.from_dict

    def parse_then_change(document):
        database = real_parse(document)
        _change(artifact, before)
        return database

    monkeypatch.setattr(REDatabase, "from_dict", staticmethod(parse_then_change))
    with pytest.raises(OSError):
        context.load_redb(artifact)
    monkeypatch.setattr(REDatabase, "from_dict", real_parse)
    assert context.load_redb(artifact).metadata["analysis_note"] == "after!"


def test_analysis_change_during_cache_hit_is_not_silently_returned(tmp_path, monkeypatch):
    artifact = tmp_path / "re-database.json"
    artifact.write_text(_doc("before"))
    original = context.load_redb(artifact)
    before = artifact.stat()
    real_get = context._REDB_MEMO.get_or_compute

    def get_then_change(key, compute):
        value = real_get(key, compute)
        assert value[0] is original and value[1] is True
        _change(artifact, before)
        return value

    monkeypatch.setattr(context._REDB_MEMO, "get_or_compute", get_then_change)
    with pytest.raises(OSError):
        context.load_redb(artifact)


def test_parse_failure_cannot_select_a_later_foreign_database_without_identity_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "private-raptor"))
    target = tmp_path / "target.bin"
    target.write_bytes(b"owned target bytes")
    assert hashlib.sha256(target.read_bytes()).hexdigest() != "f" * 64
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "re-database.json"
    artifact.write_text("{invalid JSON")
    real_load = context.load_redb
    changed = False

    def replace_after_real_parse_error(path):
        nonlocal changed
        try:
            return real_load(path)
        except ValueError:
            path.write_text(_doc("foreign", binary="other.bin", digest="f" * 64))
            changed = True
            raise

    monkeypatch.setattr(context, "load_redb", replace_after_real_parse_error)
    selected = context.find_redb(run, target)
    assert changed
    if selected is not None:
        assert real_load(selected).metadata["binary_sha256"] == "f" * 64
    assert selected is None
    assert context.find_redb(run, target) is None


@pytest.mark.parametrize("consumer", ["context", "disasm", "decomp"])
def test_context_consumes_the_database_that_passed_identity_not_a_later_reload(tmp_path, monkeypatch, consumer):
    from packages.ghidra.model import REDatabase, REFunction
    from core.inventory.binary_builder import binary_path_key
    monkeypatch.setenv("RAPTOR_DIR", str(tmp_path / "private-raptor"))
    target = tmp_path / "target.bin"
    target.write_bytes(b"owned target bytes")
    run = tmp_path / "run"
    run.mkdir()
    artifact = run / "re-database.json"
    def document(label, digest):
        function = REFunction(name="f", address=4096, size=64, source_tool="ghidra",
                              decompilation=f"void f(void) {{ /* {label} */ }}")
        database = REDatabase(source_tool="ghidra", binary_path=str(target), functions=[function])
        result = database.to_dict()
        result["metadata"] = {"binary_sha256": digest}
        return json.dumps(result)
    artifact.write_text(document("admitted-A", hashlib.sha256(target.read_bytes()).hexdigest()))
    real_find = context.find_redb
    swapped = False
    def find_then_replace(*args, **kwargs):
        nonlocal swapped
        selected = real_find(*args, **kwargs)
        assert selected == artifact
        artifact.write_text(document("foreign-B", "f" * 64))
        swapped = True
        return selected
    def forbidden(*args, **kwargs):
        raise AssertionError("owned decompilation fixture must not dispatch a backend")
    monkeypatch.setattr(context, "find_redb", find_then_replace)
    monkeypatch.setattr(context, "_lazy_decompile", forbidden)
    if consumer == "context":
        result = context.assemble_binary_context(target_path=target, out_dir=run,
            file_path=binary_path_key(target), function_name="f")
        source = result["source"]
    elif consumer == "disasm":
        from core.audit.disasm_xcheck import _load_redb_for
        database = _load_redb_for(run, target)
        assert database is not None
        source = database.functions[0].decompilation
    else:
        from core.audit.decomp_sweep import _locate_or_build_tree
        import packages.ghidra.decomp_tree as decomp_tree
        observed = []
        def capture_before_emit(database, root):
            observed.append(database)
            raise RuntimeError("fixture stopped before materialization")
        monkeypatch.setattr(decomp_tree, "write_decomp_tree", capture_before_emit)
        index, root, reason = _locate_or_build_tree(target, run, {binary_path_key(target)})
        assert index is None and root is None and "fixture stopped before materialization" in reason
        assert len(observed) == 1
        source = observed[0].functions[0].decompilation
    assert swapped
    assert "admitted-A" in source and "foreign-B" not in source
    assert json.loads(artifact.read_text())["metadata"]["binary_sha256"] == "f" * 64
