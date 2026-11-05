"""Exercise the shipped propagation fixture bodies without changing live loggers."""

import ast
from pathlib import Path
from types import SimpleNamespace

import pytest


FIXTURES = [
    "core/build/tests/test_walk_files.py",
    "core/coverage/tests/test_store_summary.py",
    "core/engagement/tests/test_ledger.py",
    "core/inventory/tests/test_checklist_frame_mac.py",
    "core/llm/tests/test_anthropic_retry_visibility.py",
    "core/llm/tests/test_raptor_config_schema_guard.py",
    "core/orchestration/tests/test_frida_validation_bridge.py",
    "core/project/tests/test_findings_size_gate.py",
    "core/project/tests/test_machine_project_expiry.py",
    "core/sarif/tests/test_import_normalizer.py",
    "packages/codeql/tests/test_abstained_verdicts.py",
    "packages/codeql/tests/test_buildless_mode.py",
    "packages/codeql/tests/test_database_manager.py",
    "packages/codeql/tests/test_language_detector.py",
    "packages/codeql/tests/test_terminal_output_scrub.py",
    "packages/fuzzing/tests/test_afl_runner.py",
    "packages/fuzzing/tests/test_binary_only_mode.py",
    "packages/fuzzing/tests/test_libfuzzer_runner.py",
    "packages/llm_analysis/tests/test_load_attack_path_log_excerpt.py",
    "packages/llm_analysis/tests/test_logger_excerpt_scrub.py",
]
REPO = Path(__file__).resolve().parents[3]


class _SetupFailure(RuntimeError):
    pass


class _Logger:
    def __init__(self, initial, fail_on_enable):
        self._propagate = initial
        self._fail = fail_on_enable

    @property
    def propagate(self):
        return self._propagate

    @propagate.setter
    def propagate(self, value):
        self._propagate = value
        if self._fail:
            self._fail = False
            raise _SetupFailure("setter changed state before failing")


def _fixture(path, logger):
    # Compile only the actual fixture node: importing entire runner test
    # modules would add unrelated tool/SDK requirements to this log-state pin.
    source = (REPO / path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=path)
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_raptor_logger_propagates"
    )
    node.decorator_list = []

    def get_logger(name):
        assert name == "raptor"
        return logger

    namespace = {"logging": SimpleNamespace(getLogger=get_logger)}
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace[node.name]


@pytest.mark.parametrize("path", FIXTURES)
@pytest.mark.parametrize("initial", [False, True])
@pytest.mark.parametrize(
    "mode", ["normal", "body_error", "close", "throw", "setup_failure"]
)
def test_propagation_fixture_restores_caller_state(path, initial, mode):
    logger = _Logger(initial, fail_on_enable=mode == "setup_failure")
    generator = _fixture(path, logger)()
    try:
        if mode == "setup_failure":
            with pytest.raises(_SetupFailure):
                next(generator)
        else:
            next(generator)
            assert logger.propagate is True
            # A test can also change propagation while the fixture is active.
            logger.propagate = not initial
            if mode == "close":
                generator.close()
            elif mode == "throw":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                if mode == "body_error":
                    # Pytest resumes a yield fixture normally after a body
                    # exception; it does not throw that exception into it.
                    with pytest.raises(KeyboardInterrupt):
                        raise KeyboardInterrupt
                with pytest.raises(StopIteration):
                    next(generator)
    finally:
        generator.close()
    assert logger.propagate is initial
