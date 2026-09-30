"""Third-party SDK loggers are capped at WARNING by the logging setup.

The root console handler deliberately surfaces module-level INFO
(see ``RaptorLogger.__init__``), so noisy SDK loggers — botocore's
credential discovery names the resolved IAM role at INFO — would
otherwise interleave infrastructure identifiers into run streams,
where a report quoting log excerpts could carry them out. The setup
must cap those loggers at WARNING without touching RAPTOR's own.
"""

import logging
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import core.logging as core_logging

_REPO_ROOT = Path(__file__).resolve().parents[3]

# Named independently of the production constant so these tests state
# the contract rather than mirroring the implementation.
_SDK_LOGGERS = ("boto3", "botocore", "botocore.credentials", "urllib3")


class _CaptureHandler(logging.Handler):
    """Collects every record that propagates to the logger it's on."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def root_capture():
    """Capture handler on the root logger, with full state restore.

    Saves and restores the root level, root handler list, and the SDK
    logger levels so tests here never leak configuration into the rest
    of the suite. Root level is pinned to INFO — the state
    ``RaptorLogger.__init__`` establishes for run streams — so
    propagation reflects the real run-stream condition regardless of
    test ordering. SDK logger levels are reset to NOTSET so each test
    exercises what the setup call itself applies, not process history.
    """
    root = logging.getLogger()
    saved_root_level = root.level
    saved_root_handlers = list(root.handlers)
    saved_sdk_levels = {
        name: logging.getLogger(name).level for name in _SDK_LOGGERS
    }
    handler = _CaptureHandler()
    root.addHandler(handler)
    root.setLevel(logging.INFO)
    for name in _SDK_LOGGERS:
        logging.getLogger(name).setLevel(logging.NOTSET)
    try:
        yield handler
    finally:
        root.setLevel(saved_root_level)
        root.handlers[:] = saved_root_handlers
        for name, level in saved_sdk_levels.items():
            logging.getLogger(name).setLevel(level)


class TestQuietThirdPartyLoggers:
    """The cap itself — the helper both setup chokepoints call."""

    def test_botocore_info_does_not_reach_stream_handlers(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.quiet_third_party_loggers()
        logging.getLogger("botocore.credentials").info(
            "Found credentials from IAM Role: %s", "fixture-role",
        )
        assert root_capture.records == []

    def test_botocore_warning_still_reaches_stream_handlers(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.quiet_third_party_loggers()
        logging.getLogger("botocore.credentials").warning(
            "Refreshing temporary credentials failed",
        )
        assert [r.getMessage() for r in root_capture.records] == [
            "Refreshing temporary credentials failed",
        ]

    def test_every_named_sdk_logger_is_capped(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.quiet_third_party_loggers()
        for name in _SDK_LOGGERS:
            assert not logging.getLogger(name).isEnabledFor(logging.INFO), (
                f"{name} still admits INFO"
            )
            assert logging.getLogger(name).isEnabledFor(logging.WARNING)

    def test_raptor_loggers_keep_info(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.quiet_third_party_loggers()
        assert logging.getLogger("raptor.core.audit").isEnabledFor(
            logging.INFO,
        )
        # Stdlib-named RAPTOR modules propagate to root and must keep
        # surfacing INFO — that root behaviour is deliberate.
        logging.getLogger("packages.llm_analysis.example").info(
            "module INFO still surfaces",
        )
        assert [r.getMessage() for r in root_capture.records] == [
            "module INFO still surfaces",
        ]


class TestRunStreamSetupAppliesCap:
    """``RaptorLogger`` first initialisation is the run-stream
    chokepoint. The singleton initialises once per process, so the
    first-init guarantee is proven in a fresh interpreter."""

    def test_first_init_caps_sdk_loggers(self, tmp_path: Path) -> None:
        probe = textwrap.dedent("""
            import logging

            import core.logging as core_logging

            core_logging.RaptorLogger()

            records = []

            class Capture(logging.Handler):
                def emit(self, record):
                    records.append(record)

            logging.getLogger().addHandler(Capture(level=logging.DEBUG))
            logging.getLogger("botocore.credentials").info(
                "Found credentials from IAM Role: %s", "fixture-role",
            )
            logging.getLogger("botocore.credentials").warning("warn-probe")
            messages = [r.getMessage() for r in records]
            assert "warn-probe" in messages, messages
            leaked = [m for m in messages if "fixture-role" in m]
            assert not leaked, f"SDK INFO reached the stream: {leaked}"
            print("CAP-HELD")
        """)
        script = tmp_path / "probe_first_init.py"
        script.write_text(probe)
        env = dict(os.environ)
        env["PYTHONPATH"] = str(_REPO_ROOT)
        result = subprocess.run(
            [sys.executable, str(script)],
            cwd=str(_REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "CAP-HELD" in result.stdout


class TestCliSetupAppliesCap:
    """``configure_cli_logging`` is the standalone-CLI chokepoint."""

    def test_cli_setup_caps_sdk_loggers(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.configure_cli_logging(logging.INFO)
        logging.getLogger("botocore.credentials").info(
            "Found credentials from IAM Role: %s", "fixture-role",
        )
        assert root_capture.records == []
