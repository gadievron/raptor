"""Terminal hygiene for untrusted target output."""

from packages.fuzzing.output_hygiene import strip_terminal_controls


class TestStripTerminalControls:
    def test_ansi_escape_neutralised(self):
        # ESC removed leaves the sequence as inert printable text.
        assert strip_terminal_controls("\x1b[31mred\x1b[0m") == "[31mred[0m"

    def test_osc_sequence_neutralised(self):
        out = strip_terminal_controls("\x1b]0;owned\x07title")
        assert "\x1b" not in out
        assert "\x07" not in out

    def test_c1_controls_removed(self):
        assert strip_terminal_controls("a\x9b31mb") == "a31mb"

    def test_carriage_return_removed(self):
        # \r enables line-rewriting forgery in scrollback.
        assert strip_terminal_controls("ok\rall clean") == "okall clean"

    def test_newline_and_tab_preserved(self):
        assert strip_terminal_controls("a\nb\tc") == "a\nb\tc"

    def test_plain_text_untouched(self):
        text = "exec/s: 1234 (100.0%) paths: 7"
        assert strip_terminal_controls(text) == text


class TestCorpusStatsRace:
    def test_get_stats_tolerates_vanishing_seed(self, tmp_path):
        """Seed deleted between the is_file() check and stat() (the
        corpus dir is live during a campaign) must count as size 0,
        not raise FileNotFoundError."""
        from packages.fuzzing.corpus_manager import CorpusManager

        manager = CorpusManager(tmp_path / "corpus")
        (tmp_path / "corpus" / "seed0").write_bytes(b"AAAA")

        class _GhostSeed:
            """Path stand-in that passes the listing filter, then
            loses the race at stat() (plain class — subclassing
            pathlib.Path needs >=3.12)."""

            def is_file(self) -> bool:
                return True

            def stat(self, **kwargs):
                raise FileNotFoundError("ghost")

        ghost = _GhostSeed()
        real = list(manager.list_seeds())

        def fake_list_seeds():
            return [*real, ghost]

        manager.list_seeds = fake_list_seeds  # type: ignore[method-assign]
        stats = manager.get_stats()
        assert stats["num_seeds"] == 2
        assert stats["total_size"] == 4
