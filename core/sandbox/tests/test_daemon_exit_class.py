"""One exit-class vocabulary for both daemon verbs.

The probe verb emitted numeric ``signal:{-rc}`` while the
conversation verb emitted named ``signal:SIGSEGV`` plus a
stack_smashing arm the probe lacked — one concept, two vocabularies
in one daemon: a consumer keying on either spelling missed the other
verb's runs, and probe runs never classified stack smashing.
"""

from __future__ import annotations

import re
import signal

from core.sandbox import _daemon as daemon_mod


def test_signal_exits_are_named():
    out = daemon_mod._classify_exit(-signal.SIGSEGV, b"", False)
    assert out == "signal:SIGSEGV"
    assert not re.match(r"signal:\d+$", out)


def test_unknown_signal_number_is_labelled():
    assert daemon_mod._classify_exit(-99, b"", False) == (
        "signal:UNKNOWN(99)")


def test_canary_classifies_stack_smashing_for_every_shape():
    canary = b"... *** stack smashing detected ***: terminated\n"
    for rc, timed_out in ((0, False), (1, False),
                          (-signal.SIGABRT, False), (None, True)):
        assert daemon_mod._classify_exit(rc, canary, timed_out) == (
            "stack_smashing"), (rc, timed_out)


def test_plain_classes():
    assert daemon_mod._classify_exit(0, b"", False) == "clean"
    assert daemon_mod._classify_exit(3, b"", False) == "exit:3"
    assert daemon_mod._classify_exit(None, b"", True) == "timeout"


def test_both_verbs_share_the_classifier():
    # Source pin: neither verb re-implements its own vocabulary.
    from pathlib import Path
    src = Path(daemon_mod.__file__).read_text(encoding="utf-8")
    assert src.count("_classify_exit(") >= 3  # def + two call sites
    assert 'exit_class = f"signal:{-rc}"' not in src
