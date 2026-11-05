"""Fresh-process hashing and help must not require unrelated configuration."""

import os
from pathlib import Path
import subprocess
import sys
import textwrap

import pytest

# Preserve dependency routing for the child-only imports.
import core.hash  # noqa: F401
import core.concepts.model  # noqa: F401

ROOT = Path(__file__).resolve().parents[3]


def _python(source, tmp_path, *args):
    home = tmp_path / "home"
    home.mkdir()
    env = dict(
        os.environ, HOME=str(home), TMPDIR=str(tmp_path), CI="1",
        XDG_CONFIG_HOME=str(home / "config"),
        XDG_CACHE_HOME=str(home / "cache"),
        XDG_DATA_HOME=str(home / "data"),
        RAPTOR_REGISTRY_HOME=str(tmp_path / "registry"),
        RAPTOR_OUT_DIR=str(tmp_path / "out"), _RAPTOR_TRUSTED="1",
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c",
         f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n" + textwrap.dedent(source),
         *map(str, args)],
        cwd=tmp_path, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_pure_hashes_and_explicit_chunk_reads_do_not_load_configuration(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"sample bytes")
    _python("""
        import hashlib
        import io
        import core.hash as hashes
        from core.concepts.model import StudyItem

        data = b"sample bytes"
        expected = hashlib.sha256(data).hexdigest()
        assert hashes.sha256_bytes(data) == expected
        assert hashes.sha256_string(data.decode()) == expected
        raw = "raw-\\udcff"
        assert hashes.sha256_string(raw) == hashlib.sha256(
            raw.encode("utf-8", errors="surrogateescape")).hexdigest()
        assert hashes.sha256_file(sys.argv[1], chunk_size=4096) == expected
        stream = io.BytesIO(b"prefix" + data)
        stream.seek(6)
        assert hashes.sha256_fileobj(stream, chunk_size=4096) == expected
        assert stream.tell() == len(b"prefix" + data)
        assert "RaptorConfig" in dir(hashes)
        try:
            hashes.not_an_export
        except AttributeError:
            pass
        else:
            raise AssertionError("unknown export did not raise")
        assert "core.config" not in sys.modules
        assert "core.logging" not in sys.modules
        assert "core.llm.model_brokers" not in sys.modules
    """, tmp_path, sample)


def test_config_exports_defaults_and_reload_remain_compatible(tmp_path):
    sample = tmp_path / "sample"
    sample.write_bytes(b"sample bytes")
    _python("""
        import hashlib
        import importlib
        import io
        from types import SimpleNamespace
        import core.hash as hashes

        assert "core.config" not in sys.modules
        expected = hashlib.sha256(b"sample bytes").hexdigest()
        assert hashes.sha256_file(sys.argv[1]) == expected
        from core.config import RaptorConfig
        assert "core.llm.model_brokers" in sys.modules
        assert hashes.RaptorConfig is RaptorConfig
        assert vars(hashes)["RaptorConfig"] is RaptorConfig
        namespace = {}
        exec("from core.hash import *", namespace)
        assert set(namespace) - {"__builtins__"} == {
            "BinaryIO", "Path", "RaptorConfig", "get_logger", "hashlib", "logger",
            "sha256_bytes", "sha256_file", "sha256_fileobj", "sha256_string", "sha256_tree",
        }
        assert all(namespace[name] is getattr(hashes, name) for name in hashes.__all__)
        from core.logging import get_logger
        assert hashes.get_logger is get_logger
        assert hashes.logger is get_logger()

        class RecordingStream(io.BytesIO):
            def read(self, size):
                assert size == 12345, size
                return super().read(size)
        # Historical consumers can replace the re-exported configuration alias.
        hashes.RaptorConfig = SimpleNamespace(HASH_CHUNK_SIZE=12345)
        assert hashes.sha256_fileobj(RecordingStream(b"sample bytes")) == expected
        importlib.reload(hashes)
        assert not {"RaptorConfig", "get_logger", "logger"} & vars(hashes).keys()
        assert hashes.RaptorConfig is RaptorConfig
        assert hashes.get_logger is namespace["get_logger"]
        assert hashes.logger is namespace["logger"]

        import core.logging as logging_api
        original_factory = logging_api.get_logger
        replacement = object()
        try:
            logging_api.get_logger = lambda: replacement
            importlib.reload(hashes)
            assert hashes.get_logger is logging_api.get_logger
            assert hashes.logger is replacement
        finally:
            logging_api.get_logger = original_factory
            importlib.reload(hashes)
    """, tmp_path, sample)


@pytest.mark.parametrize("script", ["raptor-study-prep", "raptor-study-loop"])
def test_study_help_does_not_load_configuration(script, tmp_path):
    _python("""
        import runpy
        script = sys.argv[1]
        sys.argv = [script, "--help"]
        try:
            runpy.run_path(script, run_name="__main__")
        except SystemExit as exc:
            assert exc.code == 0, exc.code
        else:
            raise AssertionError("--help did not exit")
        assert "core.config" not in sys.modules
        assert "core.llm.model_brokers" not in sys.modules
    """, tmp_path, ROOT / "libexec" / script)
