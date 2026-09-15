"""_validate_flags must not mangle flags whose VALUE contains a space.

Flags reach the compiler as single argv elements via subprocess list
args (no shell), so an embedded space is data. Whitespace-splitting
every flag turned an auto-detected "-Ithird party/inc" into "-Ithird"
plus a bogus positional "party/inc" — both of which passed validation
individually and broke every TU compile. Only known pair flags
("-include header.h") are split, and genuinely malformed flags
(shell metacharacters, unknown flag names) stay rejected.
"""

from __future__ import annotations

from pathlib import Path

from core.build.build_detector import BuildDetector


def _bd() -> BuildDetector:
    return BuildDetector(Path("."))


class TestSpacedValues:
    def test_spaced_include_dir_survives_as_one_token(self):
        assert _bd()._validate_flags(["-Ithird party/inc"]) == [
            "-Ithird party/inc",
        ]

    def test_spaced_define_value_survives(self):
        assert _bd()._validate_flags(["-DGREETING=hello world"]) == [
            "-DGREETING=hello world",
        ]

    def test_positional_pair_value_with_space_survives(self):
        # javac shape: value token follows its pair flag.
        assert _bd()._validate_flags(
            ["-sourcepath", "/repo/my project"],
        ) == ["-sourcepath", "/repo/my project"]


class TestPairFlagsStillSplit:
    def test_include_pair_splits_into_two_argv_tokens(self):
        assert _bd()._validate_flags(["-include stdlib.h"]) == [
            "-include", "stdlib.h",
        ]

    def test_classpath_pair_splits(self):
        assert _bd()._validate_flags(["-cp lib/dep.jar"]) == [
            "-cp", "lib/dep.jar",
        ]


class TestStillRejected:
    def test_metacharacter_flag_rejected(self):
        assert _bd()._validate_flags(["-DEVIL=$(rm -rf /x)"]) == []

    def test_trailing_newline_rejected(self):
        assert _bd()._validate_flags(["-DFOO=1\n"]) == []

    def test_unknown_flag_name_dropped(self):
        assert _bd()._validate_flags(["-fplugin=evil.so"]) == []

    def test_spaced_metacharacter_value_rejected(self):
        # Space is allowed; shell metacharacters in the value are not.
        assert _bd()._validate_flags(["-Ithird party;rm -rf /x"]) == []

    def test_non_string_and_blank_skipped(self):
        assert _bd()._validate_flags([None, "", "   ", "-DOK"]) == ["-DOK"]


class TestPairFlagsValidateAtomically:
    # A pair flag's name must never be emitted without its value: the
    # compiler would consume the NEXT argv element (-d, a source file)
    # as the value, silently corrupting the whole synthesised build.

    def test_rejected_pair_value_drops_the_name_too(self):
        # Path with shell metacharacters fails the token charset — the
        # pair must vanish atomically, not strand "-sourcepath".
        assert _bd()._validate_flags(
            ["-sourcepath", "/repo/$(evil)"],
        ) == []

    def test_rejected_pair_value_in_one_string_drops_both(self):
        assert _bd()._validate_flags(["-include $(evil).h"]) == []

    def test_pair_name_without_value_dropped(self):
        assert _bd()._validate_flags(["-sourcepath"]) == []

    def test_pair_name_followed_by_flag_keeps_the_flag(self):
        # The next token is a flag, not a value: drop the name alone.
        assert _bd()._validate_flags(
            ["-sourcepath", "-DOK"],
        ) == ["-DOK"]

    def test_valid_pair_after_rejected_pair_survives(self):
        assert _bd()._validate_flags(
            ["-sourcepath", "/repo/$(evil)", "-cp", "lib/dep.jar"],
        ) == ["-cp", "lib/dep.jar"]


class TestStandalonePositionalsRejected:
    # A bare token is accepted ONLY as a pair flag's value. Standalone
    # positionals would splice arbitrary extra argv (an attacker-chosen
    # source file from a prompt-injected CC reply) into every compile.

    def test_bare_positional_dropped(self):
        assert _bd()._validate_flags(["evil.c"]) == []

    def test_bare_traversal_positional_dropped(self):
        assert _bd()._validate_flags(["../../other/file.c", "-DOK"]) == [
            "-DOK",
        ]

    def test_pair_value_position_still_accepts_bare_token(self):
        # Both-directions guard: the pair-value lane stays open.
        assert _bd()._validate_flags(
            ["-sourcepath", "/repo/src"],
        ) == ["-sourcepath", "/repo/src"]
