"""Third-party SDK loggers are capped at WARNING by the logging setup.

The root console handler deliberately surfaces module-level INFO
(see ``RaptorLogger.__init__``), so noisy SDK loggers — botocore's
credential discovery names the resolved IAM role at INFO — would
otherwise interleave infrastructure identifiers into run streams,
where a report quoting log excerpts could carry them out. The setup
must cap those loggers at WARNING without touching RAPTOR's own.
"""

import logging
from contextlib import contextmanager
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

import core.logging as core_logging
from core.testing.logging_state import isolated_cli_logging, owned_log_handler

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
    """Own the capture handler without changing levels during fixture setup."""
    root = logging.getLogger()
    with owned_log_handler(root, _CaptureHandler()) as handler:
        yield handler


@contextmanager
def _sdk_logging_baseline():
    """Set the baseline inside the call phase, after pytest capture enters.

    INFO root logging matches the run-stream setup. SDK levels start at
    NOTSET so each test exercises the cap applied by the setup call.
    """
    with isolated_cli_logging(logger_names=_SDK_LOGGERS):
        logging.getLogger().setLevel(logging.INFO)
        for name in _SDK_LOGGERS:
            logging.getLogger(name).setLevel(logging.NOTSET)
        yield


class TestQuietThirdPartyLoggers:
    """The cap itself — the helper both setup chokepoints call."""

    @_sdk_logging_baseline()
    def test_botocore_info_does_not_reach_stream_handlers(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.quiet_third_party_loggers()
        logging.getLogger("botocore.credentials").info(
            "Found credentials from IAM Role: %s", "fixture-role",
        )
        assert root_capture.records == []

    @_sdk_logging_baseline()
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

    @_sdk_logging_baseline()
    def test_every_named_sdk_logger_is_capped(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.quiet_third_party_loggers()
        for name in _SDK_LOGGERS:
            assert not logging.getLogger(name).isEnabledFor(logging.INFO), (
                f"{name} still admits INFO"
            )
            assert logging.getLogger(name).isEnabledFor(logging.WARNING)

    @_sdk_logging_baseline()
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

    @_sdk_logging_baseline()
    def test_cli_setup_caps_sdk_loggers(
        self, root_capture: _CaptureHandler,
    ) -> None:
        core_logging.configure_cli_logging(logging.INFO)
        logging.getLogger("botocore.credentials").info(
            "Found credentials from IAM Role: %s", "fixture-role",
        )
        assert root_capture.records == []
