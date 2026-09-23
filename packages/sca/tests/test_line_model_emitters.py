r"""SCA line-number emitters count \n, matching the \n-model consumers
(reports, editors, review windows) their emitted coordinates reach.

splitlines() also breaks on \f — plantable inside YAML/TOML/Dockerfile
string content in a scanned repo — which skewed every subsequently
emitted line number.
"""

from __future__ import annotations

from packages.sca._gha_uses import best_effort_line


class TestBestEffortLine:
    def test_line_is_nl_counted_past_a_form_feed(self):
        text = (
            'name: "w\x0c\x0cf"\n'                      # 1
            "jobs:\n"                                   # 2
            "  build:\n"                                # 3
            "    steps:\n"                              # 4
            "      - uses: actions/checkout@v4\n"       # 5
        )
        assert best_effort_line(text, "actions/checkout@v4") == 5

    def test_clean_twin_differential(self):
        text = "steps:\n  - uses: actions/checkout@v4\n"
        assert best_effort_line(text, "actions/checkout@v4") == 2
