"""Exact detector file setups retire pathnames after first-write refusals."""

import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import pytest

CASES = [
    {
        "class": "TestDetect",
        "method": "test_elf_binary_detection",
        "method_sha256": "062a2eedce34f92cb3bddd49f19ba625964ad6f360c6051b4c713a5ae2612c60",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_big_endian_elf_machine_read_in_file_byte_order",
        "method_sha256": "e0650d10f009686828105b6fc7ef02491054beb22519b134e36a9bffe380ef75",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_little_endian_elf_machine_unchanged",
        "method_sha256": "36502a3c89a4785301c9edb7774fe32fdf55704ccc93d3b1157c3b344570a5f9",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_macho_binary_detection",
        "method_sha256": "28c9f9c02770246b58c36932a8d8eb3ac90a0b4777569e78ceefb39cfad14887",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_macho_non_executable_on_darwin_gets_chmod_blocker",
        "method_sha256": "38338b048c0723e5cb47b708184922fa34e4ef3a8786f61e7b9d6ef7ef8edc76",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_macho_executable_on_darwin_has_no_blockers",
        "method_sha256": "695387ac1646883ecd5b18e90c69cf513e9386c2f4350a3c42bd8026a93fe1d0",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_all_fat_macho_variants_are_detected",
        "method_sha256": "4b1e6a46ba5ee4868bf7be33edc5b7719e3511f6e7f988e3d11cbed040557cfc",
        "write_sites": 1,
        "looped_first_iteration_only": True,
    },
    {
        "class": "TestDetect",
        "method": "test_java_class_magic_is_not_mislabelled_as_fat_macho",
        "method_sha256": "c6464909f5231bc81c813a03a46187dc1711fcc82d8d7ca80797576e5990c5ca",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_pe_executable_detection",
        "method_sha256": "31adc734d11cc7a683930f17d07141b40f971148ac8c0b01d2ad29d7bcbfd9c6",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_pe_dll_detection",
        "method_sha256": "a88b594ebd8dd1e67e993d0e64b492bd2627e4da0f0886a0314ba3dbe529cc76",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_pe_sys_detection_provides_kernel_fuzzing_hints",
        "method_sha256": "b5e51557debcc2baf6117ce45dfca7acb7009da5915d33e35aa58e304d30f882",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_linux_kernel_module_is_not_treated_as_a_user_mode_campaign",
        "method_sha256": "8ba7c848a4708e3f1c4cc1b39adc351bf0d61fc538fc7e14fef1876893ae8065",
        "write_sites": 2,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_c_source_file_detected",
        "method_sha256": "f5d2b80cecfc555baca997a97af56aaf61f191b17cb8b997bef570941c99d172",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_cpp_header_detected",
        "method_sha256": "b48315e4b132a5fc03f69d22690829f41f583eba24bef4d96668fc50544c6dfb",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
    {
        "class": "TestDetect",
        "method": "test_unknown_file_format",
        "method_sha256": "1c435e2e2e35797c0298ab97a3c4ae0ac7e3377bf1ec9f699d03ccb807dc243f",
        "write_sites": 1,
        "looped_first_iteration_only": False,
    },
]


@pytest.mark.parametrize("mode", ["error", "interrupt"])
@pytest.mark.parametrize(
    "case", CASES, ids=lambda row: row["class"] + "." + row["method"]
)
def test_first_write_refusal_retires_detector_file(case, mode, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "packages/fuzzing/tests/test_target_detector.py"
    )
    text = source.read_text()
    cls = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.ClassDef) and n.name == case["class"]
    )
    method = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == case["method"]
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, method).encode()).hexdigest()
        == case["method_sha256"]
    )
    assert not method.decorator_list
    files, writes, denied = [], [], []
    failure = (
        KeyboardInterrupt("owned detector setup interruption")
        if mode == "interrupt"
        else OSError(errno.ENOSPC, "owned detector setup write refusal")
    )

    class Handle:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.name = stream.name

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *exc):
            return self.stream.__exit__(*exc)

        def write(self, value):
            writes.append(True)
            raise failure

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def named(*args, **kwargs):
        assert kwargs.get("delete") is False and "dir" not in kwargs
        stream = tempfile.NamedTemporaryFile(*args, dir=tmp_path, **kwargs)
        handle = Handle(stream)
        files.append(handle)
        return handle

    def tripwire(*args, **kwargs):
        denied.append(True)
        raise AssertionError("unreviewed mock/harness construction")

    namespace = {
        "Path": Path,
        "tempfile": SimpleNamespace(NamedTemporaryFile=named),
        "detect": tripwire,
        "TargetInfo": tripwire,
        "mock_module_attribute": tripwire,
        "_mock_owner": tripwire,
        "platform": SimpleNamespace(system=tripwire),
    }
    import struct

    namespace["struct"] = struct
    dependency_names = {"ELF_MAGIC", "MACHO_64_LE_MAGIC", "PE_MAGIC"}
    dependencies = [
        n
        for n in ast.parse(text).body
        if (
            isinstance(n, ast.FunctionDef)
            and n.name in {"_fat_macho_fixture", "_pe_fixture"}
        )
        or (
            isinstance(n, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id in dependency_names for t in n.targets
            )
        )
    ]
    assert len(dependencies) == 5
    assert (
        hashlib.sha256(
            "\n".join(ast.get_source_segment(text, n) for n in dependencies).encode()
        ).hexdigest()
        == "2fc7f243ddf6853f0506f1382781f30234d9f09aa1eb1e1ff682b52828c4dfa9"
    )
    exec(
        compile(ast.Module(body=dependencies, type_ignores=[]), str(source), "exec"),
        namespace,
    )
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    owner = unittest.TestCase()
    try:
        with pytest.raises(type(failure)) as caught:
            assert owner._outcome is None
            namespace[method.name](owner)
        assert caught.value is failure
        assert owner.doCleanups()
        assert writes == [True] and len(files) == 1 and not denied
        handle = files[0]
        assert handle.stream.closed
        with pytest.raises(OSError) as closed:
            os.fstat(handle.fd)
        assert closed.value.errno == errno.EBADF
        assert not Path(handle.name).exists(), "detector file survived unittest cleanup"
        observation = {
            "case": case["class"] + "." + case["method"],
            "exception_identity": True,
            "write_refused": True,
            "stream_closed": True,
            "descriptor_consumed": True,
            "pathname_removed_after_unittest_cleanup": True,
            "mode": mode,
            "forbidden": denied,
            "scope": "injected first-write refusal only; loop first iteration only, no detector/native/ENOSPC claim",
        }
        (tmp_path / "OBSERVATION.json").write_text(
            json.dumps(observation, indent=2) + "\n"
        )
    finally:
        owner.doCleanups()
        for handle in files:
            handle.stream.close()
            Path(handle.name).unlink(missing_ok=True)
