"""Generated assembly stays bounded from publication through inventory."""

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.inventory import perlasm


import core.inventory.perlasm as _os_fault_consumer0
import core.atomic_fs as _os_fault_consumer1
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def generation(tmp_path, monkeypatch):
    import core.sandbox.context as context

    target = tmp_path / "repo"
    target.mkdir()
    source = target / "generator.pl"
    source.write_text("fixture")
    gen = perlasm.PerlasmGenerator(source, "generator.pl", "arm-xlate", "a" * 64)
    cache = tmp_path / "cache"
    state = {"output": b".text\nfixture:\n ret\n", "calls": 0}

    def run(argv, **kwargs):
        state["calls"] += 1
        state["generated"] = Path(argv[3])
        Path(argv[3]).write_bytes(state["output"])
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr(context, "run_untrusted", run)
    return target, gen, cache, state


def test_oversize_generated_output_is_not_cached(generation, monkeypatch):
    target, gen, cache, state = generation
    monkeypatch.setattr(perlasm, "_MAX_ASM_BYTES", 32)
    state["output"] = b"x" * 33
    cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
    assert cached is None and gap is not None
    assert not list(cache.iterdir())


def test_inventory_refuses_oversize_instead_of_truncating(generation, monkeypatch):
    target, gen, cache, state = generation
    cached = target / "cached.S"
    cached.write_bytes(b"x" * 33)
    monkeypatch.setattr(perlasm, "_MAX_ASM_BYTES", 32)
    assert perlasm._build_file_record(gen, "elf", "fixture", cached) is None


def test_cancelled_cache_copy_reclaims_temporary(generation, monkeypatch):
    target, gen, cache, state = generation

    def cancel(*args):
        raise KeyboardInterrupt("cancelled copy")

    patch_module_attribute(monkeypatch, _os_fault_consumer0, "os", "read", cancel)
    with pytest.raises(KeyboardInterrupt, match="cancelled copy"):
        perlasm.generate_asm(gen, "elf", target, cache)
    assert not list(cache.iterdir())


@pytest.mark.parametrize("shape", ["empty", "oversize", "symlink", "fifo"])
def test_invalid_cache_hit_is_regenerated(generation, monkeypatch, shape):
    target, gen, cache, state = generation
    monkeypatch.setattr(perlasm, "_MAX_ASM_BYTES", 32)
    cache.mkdir()
    slot = cache / (perlasm._cache_key(gen, "elf", target) + ".S")
    outside = target / "outside"
    outside.write_bytes(b"outside")
    if shape == "symlink":
        slot.symlink_to(outside)
    elif shape == "fifo":
        os.mkfifo(slot)
    else:
        slot.write_bytes(b"" if shape == "empty" else b"x" * 33)
    cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
    assert cached == slot and gap is None
    assert state["calls"] == 1
    assert not slot.is_symlink()
    assert slot.read_bytes() == state["output"]
    assert outside.read_bytes() == b"outside"
    assert list(cache.iterdir()) == [slot]


@pytest.mark.parametrize("shape", ["empty", "symlink", "fifo"])
def test_inventory_refuses_invalid_cached_artifact(generation, shape):
    target, gen, cache, state = generation
    artifact = target / "cached.S"
    if shape == "symlink":
        outside = target / "outside.S"
        outside.write_bytes(state["output"])
        artifact.symlink_to(outside)
    elif shape == "fifo":
        os.mkfifo(artifact)
    else:
        artifact.touch()
    assert perlasm._build_file_record(gen, "elf", "fixture", artifact) is None


@pytest.mark.parametrize("size", [1, 32])
def test_exact_output_bound_is_accepted_without_truncation(generation, monkeypatch, size):
    target, gen, cache, state = generation
    monkeypatch.setattr(perlasm, "_MAX_ASM_BYTES", 32)
    state["output"] = b"x" * size
    cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
    assert gap is None
    assert cached.read_bytes() == state["output"]
    record = perlasm._build_file_record(gen, "elf", "fixture", cached)
    assert record["sha256"] == hashlib.sha256(state["output"]).hexdigest()


@pytest.mark.parametrize("over_budget", [False, True])
def test_growth_during_copy_never_publishes_changed_output(generation, monkeypatch, over_budget):
    target, gen, cache, state = generation
    limit = 32 if over_budget else 128
    monkeypatch.setattr(perlasm, "_MAX_ASM_BYTES", limit)
    read = os.read
    grown = False
    consumed = 0

    def grow_after_read(fd, size):
        nonlocal grown, consumed
        chunk = read(fd, size)
        consumed += len(chunk)
        if chunk and not grown:
            grown = True
            with state["generated"].open("ab") as output:
                output.write(b"x" * (64 if over_budget else 4))
        return chunk

    patch_module_attribute(monkeypatch, _os_fault_consumer0, "os", "read", grow_after_read)
    cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
    assert cached is None and gap is not None
    assert grown and consumed <= limit + 1
    assert not list(cache.iterdir())


@pytest.mark.parametrize("cancel", [False, True])
def test_partial_copy_failure_reclaims_temp_and_source_fd(generation, monkeypatch, cancel):
    target, gen, cache, state = generation
    read = os.read
    seen = []

    def fail_second_read(fd, size):
        seen.append(fd)
        if len(seen) > 1:
            if cancel:
                raise KeyboardInterrupt("partial copy cancelled")
            raise OSError("partial copy failed")
        return read(fd, min(size, 4))

    patch_module_attribute(monkeypatch, _os_fault_consumer0, "os", "read", fail_second_read)
    if cancel:
        with pytest.raises(KeyboardInterrupt, match="partial copy cancelled"):
            perlasm.generate_asm(gen, "elf", target, cache)
    else:
        cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
        assert cached is None and "partial copy failed" in gap
    assert not list(cache.iterdir())
    assert seen
    with pytest.raises(OSError):
        os.fstat(seen[0])


@pytest.mark.parametrize("cancel", [False, True])
def test_failed_replacement_keeps_previous_entry(generation, monkeypatch, cancel):
    target, gen, cache, state = generation
    monkeypatch.setattr(perlasm, "_MAX_ASM_BYTES", 32)
    cache.mkdir()
    slot = cache / (perlasm._cache_key(gen, "elf", target) + ".S")
    previous = b"p" * 33
    slot.write_bytes(previous)

    def fail_replace(*args):
        if cancel:
            raise KeyboardInterrupt("replacement cancelled")
        raise OSError("replacement failed")

    patch_module_attribute(monkeypatch, _os_fault_consumer1, "os", "replace", fail_replace)
    if cancel:
        with pytest.raises(KeyboardInterrupt, match="replacement cancelled"):
            perlasm.generate_asm(gen, "elf", target, cache)
    else:
        cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
        assert cached is None and "replacement failed" in gap
    assert slot.read_bytes() == previous
    assert list(cache.iterdir()) == [slot]


def test_no_progress_write_leaves_no_partial_cache(generation, monkeypatch):
    target, gen, cache, state = generation
    patch_module_attribute(monkeypatch, _os_fault_consumer1, "os", "write", lambda *args: 0)
    cached, gap = perlasm.generate_asm(gen, "elf", target, cache)
    assert cached is None and "short write" in gap
    assert not list(cache.iterdir())
