"""Cache identities must describe complete bounded source inputs."""

from contextlib import contextmanager
import hashlib
import os

import pytest

from core.inventory import perlasm


_PREAMBLE = b'$xlate = "arm-xlate.pl";\n$flavour = shift;\n$output = pop;\n'


def _generator(root):
    source = root / "generator.pl"
    source.write_bytes(_PREAMBLE)
    return perlasm.PerlasmGenerator(source, source.name, "arm-xlate",
                                    hashlib.sha256(_PREAMBLE).hexdigest())


def test_generator_prefixes_are_not_complete_cache_identities(tmp_path, monkeypatch):
    (tmp_path / "one.pl").write_bytes(_PREAMBLE + b"first tail")
    (tmp_path / "two.pl").write_bytes(_PREAMBLE + b"second tail")
    monkeypatch.setattr(perlasm, "_MAX_PL_BYTES", len(_PREAMBLE))
    assert perlasm.detect_perlasm_generators(tmp_path) == []


def test_oversize_driver_is_refused_before_read(tmp_path, monkeypatch):
    gen = _generator(tmp_path)
    driver = tmp_path / "arm-xlate.pl"
    with driver.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)

    def unexpected_read(*args):
        pytest.fail("oversized driver must be rejected before reading")

    original_open = perlasm.open_regular_gated

    @contextmanager
    def guard_read(path, **kwargs):
        with original_open(path, **kwargs) as stream:
            with monkeypatch.context() as fault:
                fault.setattr(stream, "read", unexpected_read)
                yield stream

    monkeypatch.setattr(perlasm, "open_regular_gated", guard_read)
    with pytest.raises(ValueError, match="budget"):
        perlasm._resolve_driver_sha(gen, tmp_path)


@pytest.mark.parametrize("size", [0, 1, 32])
def test_driver_digest_covers_exact_complete_file(tmp_path, monkeypatch, size):
    gen = _generator(tmp_path)
    data = b"x" * size
    (tmp_path / "arm-xlate.pl").write_bytes(data)
    monkeypatch.setattr(perlasm, "_MAX_DRIVER_BYTES", 32)
    assert perlasm._resolve_driver_sha(gen, tmp_path) == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("shape", ["oversize", "fifo", "directory", "loop"])
def test_invalid_driver_cannot_use_unresolved_cache(tmp_path, monkeypatch, shape):
    import core.sandbox.context as context

    gen = _generator(tmp_path)
    cache = tmp_path / "cache"
    cache.mkdir()
    slot = cache / (perlasm._cache_key(gen, "elf", tmp_path) + ".S")
    slot.write_bytes(b"previous cache entry")
    driver = tmp_path / "arm-xlate.pl"
    monkeypatch.setattr(perlasm, "_MAX_DRIVER_BYTES", 32)
    if shape == "oversize":
        driver.write_bytes(b"x" * 33)
    elif shape == "fifo":
        os.mkfifo(driver)
    elif shape == "directory":
        driver.mkdir()
    else:
        driver.symlink_to(driver.name)

    def forbidden_dispatch(*args, **kwargs):
        pytest.fail("invalid driver identity must be refused before dispatch")

    monkeypatch.setattr(context, "run_untrusted", forbidden_dispatch)
    cached, gap = perlasm.generate_asm(gen, "elf", tmp_path, cache)
    assert cached is None and "driver identity unavailable" in gap
    assert slot.read_bytes() == b"previous cache entry"
    assert list(cache.iterdir()) == [slot]


def test_generator_fifo_does_not_block_detection(tmp_path):
    os.mkfifo(tmp_path / "generator.pl")
    assert perlasm.detect_perlasm_generators(tmp_path) == []


@pytest.mark.parametrize("shape", ["oversize", "fifo", "symlink", "directory"])
def test_invalid_build_metadata_does_not_choose_a_flavour(tmp_path, monkeypatch, shape):
    gen = _generator(tmp_path)
    metadata = tmp_path / "configdata.pm"
    monkeypatch.setattr(perlasm, "_MAX_CONFIG_BYTES", 32)
    if shape == "oversize":
        metadata.write_bytes(b"x" * 33)
    elif shape == "fifo":
        os.mkfifo(metadata)
    elif shape == "directory":
        metadata.mkdir()
    else:
        outside = tmp_path / "external"
        outside.write_bytes(b'"perlasm_scheme" => "ios64"')
        metadata.symlink_to(outside)
    flavour, reason = perlasm.derive_flavour(gen, tmp_path)
    assert flavour is None and "build metadata unavailable" in reason


def test_absent_build_metadata_still_uses_family_default(tmp_path):
    gen = _generator(tmp_path)
    flavour, reason = perlasm.derive_flavour(gen, tmp_path)
    assert flavour == "linux64" and "family default" in reason


@pytest.mark.parametrize("mutation", ["grow-over", "grow-within", "rewrite"])
def test_driver_changes_are_refused_and_stream_closed(tmp_path, monkeypatch, mutation):
    gen = _generator(tmp_path)
    driver = tmp_path / "arm-xlate.pl"
    driver.write_bytes(b"original driver")
    limit = 32 if mutation == "grow-over" else 128
    monkeypatch.setattr(perlasm, "_MAX_DRIVER_BYTES", limit)
    original_open = perlasm.open_regular_gated
    streams = []
    count = 0

    @contextmanager
    def mutate_after_read(path, **kwargs):
        nonlocal count
        with original_open(path, **kwargs) as stream:
            streams.append(stream)
            read = stream.read
            changed = False

            def read_and_change(size):
                nonlocal changed, count
                chunk = read(size)
                count += len(chunk)
                if chunk and not changed:
                    changed = True
                    if mutation == "rewrite":
                        before = driver.stat()
                        driver.write_bytes(b"changed! driver")
                        os.utime(driver, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000))
                    else:
                        with driver.open("ab") as output:
                            output.write(b"x" * (64 if mutation == "grow-over" else 4))
                return chunk

            with monkeypatch.context() as fault:
                fault.setattr(stream, "read", read_and_change)
                yield stream

    monkeypatch.setattr(perlasm, "open_regular_gated", mutate_after_read)
    with pytest.raises(ValueError, match="budget|changed"):
        perlasm._resolve_driver_sha(gen, tmp_path)
    assert count <= limit + 1
    assert streams and all(stream.closed for stream in streams)


_ASM = b".text\n.global demo_kernel\n.type demo_kernel,%function\ndemo_kernel:\n ret\n.size demo_kernel,.-demo_kernel\n"


def _span_case(root, monkeypatch, *, newline=b"\n", mutation=None):
    source = root / "generator.pl"
    raw = (_PREAMBLE + b"my $code = <<'EOF';\n" + _ASM + b"EOF\n").replace(b"\n", newline)
    source.write_bytes(raw)
    gen = perlasm.PerlasmGenerator(source, source.name, "arm-xlate", hashlib.sha256(raw).hexdigest())
    emitted = root / "emitted.S"
    emitted.write_bytes(_ASM)
    record = perlasm._build_file_record(gen, "elf", "fixture", emitted)
    assert record and record["items"]
    result = perlasm.PerlasmResult(generators=[gen], file_records=[record])
    inventory = {"files": [{"path": source.name, "language": "perl", "items": []}],
                 "total_files": 1, "total_items": 0, "total_functions": 0, "total_sloc": 0}

    def completed_pass(*args, **kwargs):
        if mutation == "oversize":
            source.write_bytes(raw + b"x" * len(raw))
        elif mutation == "changed":
            source.write_bytes(raw.replace(b"demo_kernel", b"evil_kernel"))
        elif mutation == "fifo":
            source.unlink()
            os.mkfifo(source)
        elif mutation == "symlink":
            outside = root / "external.pl"
            outside.write_bytes(raw)
            source.unlink()
            source.symlink_to(outside)
        return result

    monkeypatch.setattr(perlasm, "_MAX_PL_BYTES", len(raw))
    monkeypatch.setattr(perlasm, "run_perlasm_pass", completed_pass)
    perlasm.enrich_inventory_with_perlasm(inventory, root, cache_dir=root / "cache")
    return inventory, result


@pytest.mark.parametrize("mutation", ["oversize", "changed", "fifo", "symlink"])
def test_span_mapping_refuses_unbounded_or_changed_source(tmp_path, monkeypatch, mutation):
    inventory, result = _span_case(tmp_path, monkeypatch, mutation=mutation)
    assert inventory["files"][0]["items"] == []
    assert result.gaps and "source-span mapping unavailable" in result.gaps[0]


def test_span_mapping_preserves_crlf_line_model(tmp_path, monkeypatch):
    inventory, result = _span_case(tmp_path, monkeypatch, newline=b"\r\n")
    assert not result.gaps
    assert [item["name"] for item in inventory["files"][0]["items"]] == ["demo_kernel"]


def test_exact_generator_budget_is_accepted(tmp_path, monkeypatch):
    gen = _generator(tmp_path)
    monkeypatch.setattr(perlasm, "_MAX_PL_BYTES", len(_PREAMBLE))
    assert perlasm.detect_perlasm_generators(tmp_path) == [gen]
