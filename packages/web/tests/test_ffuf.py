"""Tests for the narrow ffuf integration."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from packages.web.ffuf import FfufConfig, FfufRunner, parse_wordlist_args


def test_build_command_anchors_relative_template_to_base_url(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    output = tmp_path / "ffuf_results.json"

    runner = FfufRunner("https://example.test/app", tmp_path)
    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, path_template="admin/FUZZ", threads=3, rate=5),
        output,
    )

    assert cmd[:6] == [
        "ffuf",
        "-u",
        "https://example.test/app/admin/FUZZ",
        "-w",
        str(wordlist),
        "-of",
    ]
    assert "-noninteractive" in cmd
    assert cmd[cmd.index("-t") + 1] == "3"
    assert cmd[cmd.index("-rate") + 1] == "5"


def test_build_command_allows_same_origin_absolute_template(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("health\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    url = runner.build_url_template("https://example.test/api/FUZZ")

    assert url == "https://example.test/api/FUZZ"


@pytest.mark.parametrize(
    "template",
    [
        "https://evil.test/FUZZ",
        "//evil.test/FUZZ",
        "https://example.test.evil/FUZZ",
    ],
)
def test_build_url_template_rejects_out_of_scope_templates(tmp_path: Path, template: str):
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="outside configured target scope"):
        runner.build_url_template(template)


def test_build_command_requires_a_fuzz_keyword_somewhere(tmp_path: Path):
    """A config with no substitution point anywhere is a config error;
    a fixed URL is fine as long as the body or a header carries FUZZ."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="no substitution point"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, path_template="admin"),
            tmp_path / "out.json",
        )

    body_cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="api/login",
            method="POST",
            data="FUZZ=1",
        ),
        tmp_path / "out.json",
    )
    assert body_cmd[body_cmd.index("-u") + 1] == "https://example.test/api/login"

    header_cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="api/login",
            headers=("X-Forwarded-For: FUZZ",),
        ),
        tmp_path / "out.json",
    )
    assert header_cmd[header_cmd.index("-H") + 1] == "X-Forwarded-For: FUZZ"


def test_build_command_accepts_cookie_only_fuzz_keyword(tmp_path: Path):
    """ffuf folds -b into the effective Cookie header before its keyword
    check, so session-token fuzzing via cookies is legitimate."""
    wordlist = tmp_path / "tokens.txt"
    wordlist.write_text("aaaa\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="account",
            cookies=("session=FUZZ",),
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-b") + 1] == "session=FUZZ"


def test_build_command_rejects_recursion_with_extra_wordlists(tmp_path: Path):
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "params.txt"
    params.write_text("id\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="recursion supports only the FUZZ keyword"):
        runner.build_command(
            FfufConfig(
                wordlist=words,
                path_template="FUZZ?W2=1",
                extra_wordlists=((params, "W2"),),
                recursion=True,
            ),
            tmp_path / "out.json",
        )


def test_build_command_rejects_extensions_in_vhost_mode(tmp_path: Path):
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="extensions cannot be combined with vhost"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, vhost=True, extensions=(".php",)),
            tmp_path / "out.json",
        )


def test_build_command_emits_method_and_body(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            path_template="api/users",
            method="POST",
            data='{"FUZZ": "1"}',
            headers=("Content-Type: application/json",),
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-X") + 1] == "POST"
    assert cmd[cmd.index("-d") + 1] == '{"FUZZ": "1"}'


def test_build_command_get_method_omits_x_flag(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(FfufConfig(wordlist=wordlist), tmp_path / "out.json")

    assert "-X" not in cmd
    assert "-d" not in cmd


def test_build_command_rejects_unknown_method(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="method must be one of"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, method="TRACE"),
            tmp_path / "out.json",
        )


def test_redact_body_masks_secret_form_fields_only(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    redacted = runner._redact_body("username=admin&password=hunter2&mode=FUZZ")

    assert "hunter2" not in redacted
    assert "password=[REDACTED]" in redacted
    assert "username=admin" in redacted
    assert "mode=FUZZ" in redacted


def test_redact_body_masks_secret_keys_in_json(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    redacted = runner._redact_body(
        '{"username": "FUZZ", "password": "hunter2-super-secret", '
        '"nested": {"api_key": "sk-abc", "note": "ok"}, '
        '"items": [{"token": "t-1"}]}'
    )

    assert "hunter2-super-secret" not in redacted
    assert "sk-abc" not in redacted
    assert "t-1" not in redacted
    assert '"username": "FUZZ"' in redacted
    assert '"note": "ok"' in redacted


def test_redact_body_handles_semicolon_separated_form_fields(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    redacted = runner._redact_body("user=FUZZ;password=hunter2-super-secret")

    assert "hunter2-super-secret" not in redacted
    assert "user=FUZZ" in redacted
    assert "password=[REDACTED]" in redacted


@pytest.mark.parametrize(
    "body",
    [
        '{"password": "hunter2-super-secret" MALFORMED',
        (
            "--boundary\r\n"
            'Content-Disposition: form-data; name="password"\r\n\r\n'
            "hunter2-super-secret\r\n--boundary--"
        ),
    ],
)
def test_redact_body_drops_unparseable_credential_shapes(tmp_path: Path, body: str):
    """Malformed JSON and multipart have no reliable name/value pairing;
    leaking is worse than over-redacting."""
    runner = FfufRunner("https://example.test", tmp_path)

    redacted = runner._redact_body(body)

    assert "hunter2-super-secret" not in redacted
    assert redacted == "[REDACTED-BODY]"


def test_redact_body_passes_through_when_secrets_revealed(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path, reveal_secrets=True)

    body = '{"password": "hunter2"}'
    assert runner._redact_body(body) == body


def test_run_redacts_body_in_logs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    messages: list[str] = []
    monkeypatch.setattr(
        "packages.web.ffuf.logger.info",
        lambda fmt, *args: messages.append(fmt % args if args else fmt),
    )

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(
        FfufConfig(
            wordlist=wordlist,
            path_template="login",
            method="POST",
            data="user=FUZZ&api_key=sk-verysecretvalue123&comment=notsecretname",
        )
    )

    logs = "\n".join(messages)
    # Body VALUES never reach logs — pattern redaction cannot know that a
    # non-secret-named field (comment=...) carries a secret. Field names
    # only.
    assert "sk-verysecretvalue123" not in logs
    assert "notsecretname" not in logs
    assert "body(form fields: user, api_key, comment)" in logs


def test_scanner_cli_wires_ffuf_method_and_data(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-method",
            "POST",
            "--ffuf-data",
            "FUZZ=1",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.method == "POST"
    assert config.data == "FUZZ=1"


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"threads": 0}, "threads must be >= 1"),
        ({"rate": 0}, "rate must be >= 1"),
        ({"timeout": 0}, "timeout must be >= 1"),
        ({"max_runtime": 0}, "max runtime must be >= 1"),
        ({"report_limit": -1}, "report limit must be >= 0"),
        ({"filter_size": -1}, "filter size must be >= 0"),
    ],
)
def test_build_command_rejects_invalid_numeric_options(
    tmp_path: Path,
    config_kwargs: dict[str, int],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")



def test_build_command_always_caps_runtime_with_maxtime(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, max_runtime=120), tmp_path / "out.json"
    )

    assert cmd[cmd.index("-maxtime") + 1] == "120"


def test_build_command_emits_stop_conditions_only_when_enabled(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)
    output = tmp_path / "out.json"

    default_cmd = runner.build_command(FfufConfig(wordlist=wordlist), output)
    assert "-sf" not in default_cmd
    assert "-se" not in default_cmd
    assert "-sa" not in default_cmd

    full_cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            stop_on_403=True,
            stop_on_spurious=True,
            stop_on_all_errors=True,
        ),
        output,
    )
    assert "-sf" in full_cmd
    assert "-se" in full_cmd
    assert "-sa" in full_cmd


def test_build_command_threads_matcher_and_filter_family(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            extensions=(".php", ".bak"),
            filter_words=17,
            filter_lines=3,
            match_regex="AKIA[0-9A-Z]{16}",
            filter_regex="Not Found",
            match_time=">500",
            filter_time="<100",
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-e") + 1] == ".php,.bak"
    assert cmd[cmd.index("-fw") + 1] == "17"
    assert cmd[cmd.index("-fl") + 1] == "3"
    assert cmd[cmd.index("-mr") + 1] == "AKIA[0-9A-Z]{16}"
    assert cmd[cmd.index("-fr") + 1] == "Not Found"
    assert cmd[cmd.index("-mt") + 1] == ">500"
    assert cmd[cmd.index("-ft") + 1] == "<100"


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"extensions": ("php",)}, "leading dot"),
        ({"extensions": (".",)}, "leading dot"),
        ({"extensions": (".php,.bak",)}, "no commas or whitespace"),
        ({"extensions": (".p hp",)}, "no commas or whitespace"),
        ({"filter_words": -1}, "filter words must be >= 0"),
        ({"filter_lines": -1}, "filter lines must be >= 0"),
        ({"match_regex": "a\nb"}, "match regex must not contain newlines"),
        ({"filter_regex": "a\rb"}, "filter regex must not contain newlines"),
        ({"match_time": "500"}, "match time must look like"),
        ({"match_time": ">1x0"}, "match time must look like"),
        ({"filter_time": "=100"}, "filter time must look like"),
    ],
)
def test_build_command_rejects_invalid_matcher_options(
    tmp_path: Path,
    config_kwargs: dict[str, object],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_scanner_cli_wires_ffuf_matcher_family(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-extensions",
            ".php, .bak",
            "--ffuf-filter-words",
            "17",
            "--ffuf-filter-lines",
            "3",
            "--ffuf-match-regex",
            "secret_[a-z]+",
            "--ffuf-filter-regex",
            "Not Found",
            "--ffuf-match-time",
            ">500",
            "--ffuf-filter-time",
            "<100",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.extensions == (".php", ".bak")
    assert config.filter_words == 17
    assert config.filter_lines == 3
    assert config.match_regex == "secret_[a-z]+"
    assert config.filter_regex == "Not Found"
    assert config.match_time == ">500"
    assert config.filter_time == "<100"


def test_build_command_recursion_pairs_job_cap_and_default_rate(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, recursion=True, max_runtime=400),
        tmp_path / "out.json",
    )

    assert "-recursion" in cmd
    assert cmd[cmd.index("-recursion-depth") + 1] == "2"
    assert cmd[cmd.index("-recursion-strategy") + 1] == "default"
    # max(60, 400 // 4) = 100
    assert cmd[cmd.index("-maxtime-job") + 1] == "100"
    assert cmd[cmd.index("-rate") + 1] == "50"


def test_build_command_recursion_respects_explicit_rate_and_job_cap(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            recursion=True,
            recursion_depth=3,
            recursion_strategy="greedy",
            rate=7,
            max_runtime_job=42,
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-recursion-depth") + 1] == "3"
    assert cmd[cmd.index("-recursion-strategy") + 1] == "greedy"
    assert cmd[cmd.index("-maxtime-job") + 1] == "42"
    assert cmd[cmd.index("-rate") + 1] == "7"


def test_build_command_without_recursion_adds_no_recursion_or_rate_flags(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(FfufConfig(wordlist=wordlist), tmp_path / "out.json")

    assert "-recursion" not in cmd
    assert "-maxtime-job" not in cmd
    assert "-rate" not in cmd


def test_build_command_recursion_requires_fuzz_terminated_template(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    # ffuf hard-errors on anything but a FUZZ-terminated URL (strict
    # HasSuffix upstream) — a trailing slash included.
    for template in ("FUZZ.php", "api/FUZZ/"):
        with pytest.raises(
            ValueError, match="recursion requires the URL template to end with FUZZ"
        ):
            runner.build_command(
                FfufConfig(wordlist=wordlist, path_template=template, recursion=True),
                tmp_path / "out.json",
            )

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, path_template="api/FUZZ", recursion=True),
        tmp_path / "out.json",
    )
    assert "-recursion" in cmd


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"recursion_depth": 0}, "recursion depth must be >= 1"),
        ({"recursion_strategy": "wide"}, "recursion strategy must be"),
        ({"max_runtime_job": 0}, "max runtime per job must be >= 1"),
    ],
)
def test_build_command_rejects_invalid_recursion_options(
    tmp_path: Path,
    config_kwargs: dict[str, object],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_scanner_cli_wires_ffuf_recursion(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-recursion",
            "--ffuf-recursion-depth",
            "3",
            "--ffuf-recursion-strategy",
            "greedy",
            "--ffuf-maxtime-job",
            "90",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.recursion is True
    assert config.recursion_depth == 3
    assert config.recursion_strategy == "greedy"
    assert config.max_runtime_job == 90


def test_build_command_multi_wordlist_emits_keyed_lists_and_mode(tmp_path: Path):
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "params.txt"
    params.write_text("id\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=words,
            path_template="FUZZ?W2=1",
            extra_wordlists=((params, "W2"),),
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-w") + 1] == str(words)
    assert f"{params}:W2" in cmd
    # Explicit mode even when defaulted, so the argv self-describes.
    assert cmd[cmd.index("-mode") + 1] == "clusterbomb"
    # Clusterbomb multiplies request counts: guarded default rate.
    assert cmd[cmd.index("-rate") + 1] == "50"


def test_build_command_pitchfork_mode_skips_rate_guard(tmp_path: Path):
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "params.txt"
    params.write_text("id\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=words,
            path_template="FUZZ?W2=1",
            extra_wordlists=((params, "W2"),),
            mode="pitchfork",
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-mode") + 1] == "pitchfork"
    assert "-rate" not in cmd


def test_build_command_rejects_unused_extra_keyword(tmp_path: Path):
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "params.txt"
    params.write_text("id\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="never used: W2"):
        runner.build_command(
            FfufConfig(wordlist=words, extra_wordlists=((params, "W2"),)),
            tmp_path / "out.json",
        )


@pytest.mark.parametrize(
    ("extra_keyword", "mode", "message"),
    [
        ("w2", None, "must be uppercase alphanumeric"),
        ("FUZZ", None, "keywords must be unique"),
        ("FUZZ2", None, "must not contain each other"),
        ("W2", "shotgun", "mode must be one of"),
    ],
)
def test_build_command_rejects_invalid_multi_wordlist_options(
    tmp_path: Path,
    extra_keyword: str,
    mode: str | None,
    message: str,
):
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "params.txt"
    params.write_text("id\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(
            FfufConfig(
                wordlist=words,
                path_template=f"FUZZ?{extra_keyword}=1",
                extra_wordlists=((params, extra_keyword),),
                mode=mode,
            ),
            tmp_path / "out.json",
        )


def test_build_command_rejects_mode_without_extra_wordlists(tmp_path: Path):
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="mode requires additional wordlists"):
        runner.build_command(
            FfufConfig(wordlist=words, mode="pitchfork"),
            tmp_path / "out.json",
        )


def test_run_grants_file_granular_read_scope_to_wordlists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """The read allowlist carries the wordlist FILES, not their parent
    directories — a wordlist under /etc must not make /etc readable —
    and no directory-wide target scope is requested."""
    words = tmp_path / "primary" / "words.txt"
    words.parent.mkdir()
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "extra" / "params.txt"
    params.parent.mkdir()
    params.write_text("id\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(
        FfufConfig(
            wordlist=words,
            path_template="FUZZ?W2=1",
            extra_wordlists=((params, "W2"),),
        )
    )

    assert captured["kwargs"]["readable_paths"] == [
        str(words.resolve()),
        str(params.resolve()),
    ]
    assert captured["kwargs"].get("target") is None
    assert captured["kwargs"]["output"] == str(tmp_path)


def test_run_resolves_symlinked_wordlists_for_argv_and_scope(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Same rule as the binary realpath fix: the bind and read rule are
    created for the path the child opens, so a symlinked wordlist must
    resolve in BOTH the argv -w value and the read allowlist."""
    real = tmp_path / "store" / "words.txt"
    real.parent.mkdir()
    real.write_text("admin\n", encoding="utf-8")
    link = tmp_path / "lists" / "words.txt"
    link.parent.mkdir()
    link.symlink_to(real)
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=link))

    resolved = str(real.resolve())
    assert captured["cmd"][captured["cmd"].index("-w") + 1] == resolved
    assert captured["kwargs"]["readable_paths"] == [resolved]


def test_parse_wordlist_args_splits_primary_and_keyed_extras(tmp_path: Path):
    primary, extras = parse_wordlist_args(
        ["/lists/dirs.txt", "/lists/params.txt:W2", "/lists/values.txt:VAL3"]
    )

    assert primary == Path("/lists/dirs.txt")
    assert extras == (
        (Path("/lists/params.txt"), "W2"),
        (Path("/lists/values.txt"), "VAL3"),
    )


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        ([], "at least one ffuf wordlist"),
        (["/lists/dirs.txt:W2"], "implicit FUZZ keyword"),
        (["/lists/dirs.txt", "/lists/params.txt"], "need a :KEYWORD suffix"),
        (["/lists/dirs.txt", "/lists/params.txt:w2"], "need a :KEYWORD suffix"),
    ],
)
def test_parse_wordlist_args_rejects_bad_shapes(raw: list[str], message: str):
    with pytest.raises(ValueError, match=message):
        parse_wordlist_args(raw)


def test_build_command_rejects_wordlist_paths_ffuf_would_misparse(tmp_path: Path):
    """ffuf splits -w on ':' (first occurrence) and ',': a path containing
    either validates locally but is misparsed inside ffuf."""
    weird_dir = tmp_path / "we:ird"
    weird_dir.mkdir()
    colon_list = weird_dir / "l.txt"
    colon_list.write_text("admin\n", encoding="utf-8")
    comma_list = tmp_path / "my,list.txt"
    comma_list.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    for bad in (colon_list, comma_list):
        with pytest.raises(ValueError, match="must not contain"):
            runner.build_command(
                FfufConfig(wordlist=bad), tmp_path / "out.json"
            )


def test_run_warns_when_wordlist_symlink_escapes_its_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    outside = tmp_path / "elsewhere" / "real.txt"
    outside.parent.mkdir()
    outside.write_text("admin\n", encoding="utf-8")
    link = tmp_path / "repo" / "wordlist.txt"
    link.parent.mkdir()
    link.symlink_to(outside)
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    warnings: list[str] = []
    monkeypatch.setattr(
        "packages.web.ffuf.logger.warning",
        lambda fmt, *args: warnings.append(fmt % args if args else fmt),
    )

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=link))

    assert any("resolves OUTSIDE its directory" in w for w in warnings)


def test_scanner_cli_preflight_validates_resolved_wordlist_paths(
    tmp_path: Path,
):
    """A symlink whose TARGET path contains ':' must fail at parse time,
    not in Phase 2b — the preflight has to see the resolved path."""
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    weird_dir = tmp_path / "data:v2"
    weird_dir.mkdir()
    real = weird_dir / "w.txt"
    real.write_text("admin\n", encoding="utf-8")
    link = tmp_path / "clean.txt"
    link.symlink_to(real)

    args = build_arg_parser().parse_args(
        ["--url", "https://example.test", "--ffuf-wordlist", str(link)]
    )
    config = build_ffuf_config(args)

    assert config is not None
    assert config.wordlist == real  # resolved at parse time
    runner = FfufRunner("https://example.test", tmp_path)
    with pytest.raises(ValueError, match="must not contain"):
        runner.build_command(config, tmp_path / "out.json")


def test_scan_survives_late_ffuf_failure(tmp_path: Path):
    """A wordlist deleted between preflight and Phase 2b must degrade to
    an error entry in the report, not abort the scan and discard the
    crawl/fuzz output."""
    from unittest.mock import patch

    from packages.web.scanner import WebScanner

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    # Hermetic stand-in for the ffuf binary: the parse-time preflight
    # checks the BINARY before the wordlist, so on hosts without ffuf
    # this test would die early with "binary not found" instead of
    # reaching the late wordlist failure it exists to pin.
    stub_ffuf = tmp_path / "ffuf-stub"
    stub_ffuf.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    stub_ffuf.chmod(0o755)

    with patch("packages.web.scanner.WebClient"), patch(
        "packages.web.scanner.WebCrawler"
    ):
        scanner = WebScanner(
            "http://example.com",
            None,
            tmp_path,
            ffuf_config=FfufConfig(wordlist=wordlist, binary=str(stub_ffuf)),
        )
        scanner.crawler.crawl.return_value = {
            "stats": {"total_pages": 1, "total_parameters": 0},
            "discovered_parameters": [],
            "pages": [],
        }
        wordlist.unlink()  # the late failure

        report = scanner.scan()

    assert report["ffuf"]["status"] == "error"
    assert "wordlist not found" in report["ffuf"]["reason"]
    assert report["discovery"]["total_pages"] == 1  # crawl output survived


def test_scanner_cli_preflights_ffuf_config_before_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
):
    """A bad ffuf flag combination must die at argument-parse time, not
    in Phase 2b after the crawl/fuzz budget has been spent."""
    import sys as _sys

    from packages.web import scanner

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(
        _sys,
        "argv",
        [
            "scanner.py",
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-mode",
            "pitchfork",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        scanner.main()

    assert excinfo.value.code == 2
    assert "mode requires additional wordlists" in capsys.readouterr().err


def test_scanner_cli_wires_multi_wordlists(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    params = tmp_path / "params.txt"
    params.write_text("id\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(words),
            "--ffuf-wordlist",
            f"{params}:W2",
            "--ffuf-mode",
            "pitchfork",
            "--ffuf-path",
            "FUZZ?W2=1",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.wordlist == words
    assert config.extra_wordlists == ((params, "W2"),)
    assert config.mode == "pitchfork"


def test_build_command_rejects_extra_keyword_in_url_hostname(tmp_path: Path):
    """The origin probe must neutralize EVERY keyword: an extra wordlist
    keyword left in the hostname would otherwise lowercase into the
    target host and pass the compare."""
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    values = tmp_path / "values.txt"
    values.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("https://api2.example.test", tmp_path)

    with pytest.raises(ValueError, match="outside configured target scope"):
        runner.build_command(
            FfufConfig(
                wordlist=words,
                path_template="https://API2.example.test/FUZZ",
                extra_wordlists=((values, "API2"),),
            ),
            tmp_path / "out.json",
        )


def test_build_command_rejects_fuzzed_host_header_outside_vhost_mode(tmp_path: Path):
    """-H 'Host: FUZZ.evil.com' without vhost mode would be wire-identical
    to vhost mode while skipping the target-suffix scope check."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="requires vhost mode"):
        runner.build_command(
            FfufConfig(
                wordlist=wordlist,
                path_template="",
                headers=("Host: FUZZ.evil.com",),
            ),
            tmp_path / "out.json",
        )


def test_build_command_rejects_vhost_keyword_hidden_in_suffix(tmp_path: Path):
    """A keyword lurking inside the template 'suffix' is substituted by
    ffuf at runtime, so the endswith check must run on the neutralized
    template."""
    words = tmp_path / "words.txt"
    words.write_text("admin\n", encoding="utf-8")
    values = tmp_path / "values.txt"
    values.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("https://w2.example.test", tmp_path)

    with pytest.raises(ValueError, match="must stay under the target host"):
        runner.build_command(
            FfufConfig(
                wordlist=words,
                vhost=True,
                vhost_host_template="FUZZ.W2.example.test",
                extra_wordlists=((values, "W2"),),
            ),
            tmp_path / "out.json",
        )


def test_build_command_vhost_carries_explicit_port(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("http://target.example:8080", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, vhost=True),
        tmp_path / "out.json",
    )
    headers = [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-H"]
    assert "Host: FUZZ.target.example:8080" in headers

    # An operator template carrying the base URL's own port is accepted.
    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            vhost=True,
            vhost_host_template="FUZZ.target.example:8080",
        ),
        tmp_path / "out.json",
    )
    headers = [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-H"]
    assert "Host: FUZZ.target.example:8080" in headers


def test_build_url_template_rejects_port_zero_as_origin_match(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="outside configured target scope"):
        runner.build_url_template("https://example.test:0/FUZZ")


def test_build_command_vhost_fuzzes_host_header_against_fixed_url(tmp_path: Path):
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\nstaging\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, vhost=True),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-u") + 1] == "https://example.test/"
    headers = [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-H"]
    assert "Host: FUZZ.example.test" in headers


def test_build_command_vhost_accepts_scoped_custom_template(tmp_path: Path):
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            vhost=True,
            vhost_host_template="FUZZ-api.example.test",
        ),
        tmp_path / "out.json",
    )

    headers = [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-H"]
    assert "Host: FUZZ-api.example.test" in headers


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        (
            {"vhost": True, "vhost_host_template": "FUZZ.evil.test"},
            "must stay under the target host",
        ),
        (
            {"vhost": True, "vhost_host_template": "dev.example.test"},
            "must contain a wordlist keyword",
        ),
        (
            {"vhost": True, "vhost_host_template": "FUZZ.example.test\r\nX: y"},
            "must not contain newlines",
        ),
        (
            {"vhost": True, "path_template": "api/FUZZ"},
            "remove wordlist keywords from the URL template",
        ),
        (
            {"vhost": True, "recursion": True},
            "cannot be combined with recursion",
        ),
        (
            {"vhost": True, "headers": ("Host: pinned.example.test",)},
            "synthesizes the Host header",
        ),
        (
            {"vhost_host_template": "FUZZ.example.test"},
            "requires vhost mode",
        ),
    ],
)
def test_build_command_rejects_invalid_vhost_configs(
    tmp_path: Path,
    config_kwargs: dict[str, object],
    message: str,
):
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(
            FfufConfig(wordlist=wordlist, **config_kwargs),
            tmp_path / "out.json",
        )


def test_run_removes_stale_report_before_spawning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """ffuf only writes its report on graceful exit; a stale file left in
    a reused output dir must not be misattributed to a run that died."""
    import subprocess

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    stale = tmp_path / "ffuf_results.json"
    stale.write_text(
        json.dumps({"results": [{"url": "https://example.test/stale", "status": 200}]}),
        encoding="utf-8",
    )

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist))

    assert result["timed_out"] is True
    assert result["result_count"] == 0
    assert result["results"] == []


def test_run_refuses_to_parse_oversized_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")
    monkeypatch.setattr("packages.web.ffuf._MAX_FFUF_OUTPUT_BYTES", 64)

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps({"results": [{"url": "https://example.test/" + "a" * 200}]}),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist))

    assert result["result_count"] == 0
    assert result["results"] == []
    # Unparsed report may embed credentials in its config block: 0600.
    assert (tmp_path / "ffuf_results.json").stat().st_mode & 0o777 == 0o600


def test_run_scrubs_ffuf_config_block_from_kept_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """ffuf embeds its full resolved config (delivered headers, cookies,
    body verbatim) plus its command line in the raw report at 0644;
    keeping that next to the deleted 0600 TOML would make the at-rest
    guarantee theater."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "commandline": "ffuf -H 'Authorization: Bearer atrest-secret-1'",
                    "config": {"http_headers": {"Authorization": "Bearer atrest-secret-1"}},
                    "results": [{"url": "https://example.test/admin", "status": 200}],
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(
        FfufConfig(wordlist=wordlist, headers=("Authorization: Bearer atrest-secret-1",))
    )

    assert result["result_count"] == 1
    kept = tmp_path / "ffuf_results.json"
    raw = kept.read_text(encoding="utf-8")
    assert "atrest-secret-1" not in raw
    parsed = json.loads(raw)
    assert "config" not in parsed and "commandline" not in parsed
    assert sorted(parsed["redacted_keys"]) == ["commandline", "config"]
    assert parsed["results"]  # results survive intact
    assert kept.stat().st_mode & 0o777 == 0o600


def test_run_keeps_report_config_block_with_reveal_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps({"config": {"k": "v"}, "results": []}), encoding="utf-8"
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path, reveal_secrets=True)
    runner.run(FfufConfig(wordlist=wordlist))

    parsed = json.loads((tmp_path / "ffuf_results.json").read_text(encoding="utf-8"))
    assert parsed["config"] == {"k": "v"}


def test_run_redacts_ffuf_banner_values_in_stderr(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """ffuf's startup banner echoes delivered headers and body to stderr
    even in noninteractive mode; names stay, values go."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    banner = (
        " :: Method           : POST\n"
        " :: Header           : Authorization: Bearer BANNERSECRET999\n"
        " :: Header           : X-Custom-Thing: CUSTOMSECRET666\n"
        " :: Data             : user=FUZZ&comment=PLAINSECRET888\n"
    )

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr=banner)

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(
        FfufConfig(
            wordlist=wordlist,
            path_template="login",
            method="POST",
            data="user=FUZZ&comment=PLAINSECRET888",
            headers=(
                "Authorization: Bearer BANNERSECRET999",
                "X-Custom-Thing: CUSTOMSECRET666",
            ),
        )
    )

    stderr = result["stderr"]
    assert "BANNERSECRET999" not in stderr
    assert "CUSTOMSECRET666" not in stderr
    assert "PLAINSECRET888" not in stderr
    assert "Authorization: [REDACTED]" in stderr
    assert "X-Custom-Thing: [REDACTED]" in stderr
    assert ":: Method           : POST" in stderr  # non-value lines untouched


def test_summarize_result_sanitizes_hostile_report_fields(tmp_path: Path):
    """Report fields echo attacker-influenced response data: newlines are
    log/report injection, huge strings bypass report_limit (a count cap),
    and non-int numerics are type confusion for downstream consumers."""
    runner = FfufRunner("https://example.test", tmp_path)

    summary = runner._summarize_result(
        {
            "url": "https://example.test/x\nINJECTED-LOG-LINE " + "a" * 5000,
            "status": "200",
            "length": {"nested": "object"},
            "words": 3,
            "lines": True,
            "host": "dev.example.test\r\nX-Smuggled: yes",
        }
    )

    assert "\n" not in summary["url"]
    assert "\r" not in summary["host"]
    assert len(summary["url"]) <= 2048
    assert summary["status"] is None
    assert summary["length"] is None
    assert summary["words"] == 3
    assert summary["lines"] is None
    assert "INJECTED-LOG-LINE" in summary["url"]  # content kept, newline gone


def test_summarize_result_carries_vhost_host_field(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    summary = runner._summarize_result(
        {"url": "https://example.test/", "status": 200, "host": "dev.example.test"}
    )
    assert summary["host"] == "dev.example.test"

    plain = runner._summarize_result({"url": "https://example.test/a", "status": 200})
    assert "host" not in plain


def test_summarize_result_carries_input_map(tmp_path: Path):
    """Raw-request runs fuzz positions the URL never echoes (JSON body
    fields, header values); the per-result input map is then the only
    record of which wordlist entry matched. FFUFHASH is bookkeeping,
    not an input, and values are hostile-response-adjacent so they get
    the same sanitization as every other echoed field."""
    runner = FfufRunner("https://example.test", tmp_path)

    summary = runner._summarize_result({
        "url": "https://example.test/api",
        "status": 200,
        "input": {
            "FUZZ": "' OR 1=1--\r\nX-Smuggled: yes",
            "FFUFHASH": "a1b2c3",
        },
    })
    assert summary["input"] == {"FUZZ": "' OR 1=1--  X-Smuggled: yes"}

    plain = runner._summarize_result({"url": "https://example.test/a", "status": 200})
    assert "input" not in plain

    hashonly = runner._summarize_result({
        "url": "https://example.test/a", "status": 200,
        "input": {"FFUFHASH": "a1b2c3"},
    })
    assert "input" not in hashonly


def test_scanner_cli_wires_ffuf_vhost(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-vhost",
            "--ffuf-vhost-host-template",
            "FUZZ.example.test",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.vhost is True
    assert config.vhost_host_template == "FUZZ.example.test"


def test_build_config_file_content_covers_credential_options(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    content = runner.build_config_file_content(
        FfufConfig(
            wordlist=wordlist,
            headers=('X-Quote: va"lue', "Authorization: Bearer tok"),
            cookies=("session=abc",),
            data="user=FUZZ&password=hunter2",
        )
    )

    assert content is not None
    assert content.startswith("[http]\n")
    # json.dumps escaping doubles as TOML basic-string escaping.
    assert '"X-Quote: va\\"lue",' in content
    assert '"Authorization: Bearer tok",' in content
    assert '"session=abc",' in content
    assert 'data = "user=FUZZ&password=hunter2"' in content

    assert (
        runner.build_config_file_content(FfufConfig(wordlist=wordlist)) is None
    )


@pytest.mark.parametrize(
    "value",
    [
        "plain ascii",
        'quotes " and \\ backslashes \\" mixed',
        "unicode café ünïcode",
        "astral 😀 emoji and \U00010000 plane-1",
        "toml-syntax [http]\\nheaders = ]",
        "equals=and&ersands;semis",
    ],
)
def test_toml_basic_string_round_trips_through_reference_parser(value: str):
    """The emitted TOML must decode back to the EXACT input — go-toml
    silently corrupts what the reference parser rejects, so byte-true
    round-trip through tomllib is the safety property."""
    import tomllib

    from packages.web.ffuf import toml_basic_string

    doc = tomllib.loads(f"v = {toml_basic_string(value)}")
    assert doc["v"] == value


def test_toml_basic_string_rejects_lone_surrogates():
    from packages.web.ffuf import toml_basic_string

    with pytest.raises(ValueError, match="unpaired surrogate"):
        toml_basic_string("bad \udcff byte")


def test_build_config_file_content_astral_values_round_trip(tmp_path: Path):
    import tomllib

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    content = runner.build_config_file_content(
        FfufConfig(wordlist=wordlist, data="note=tok😀en&user=FUZZ")
    )

    assert content is not None
    assert tomllib.loads(content)["http"]["data"] == "note=tok😀en&user=FUZZ"


def test_build_command_rejects_control_characters_in_headers_and_cookies(
    tmp_path: Path,
):
    """Go's net/http refuses to SEND control-char headers, so ffuf exits 0
    with zero requests — a run that reads as 'no findings'."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    for kwargs in (
        {"headers": ("X-Bad: to\x7fken",)},
        {"headers": ("X-Bad: to\x1bken",)},
        {"cookies": ("session=to\x00ken",)},
    ):
        with pytest.raises(ValueError, match="control characters"):
            runner.build_command(
                FfufConfig(wordlist=wordlist, **kwargs), tmp_path / "out.json"
            )


def test_build_config_file_content_includes_vhost_header(tmp_path: Path):
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text("dev\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    content = runner.build_config_file_content(
        FfufConfig(wordlist=wordlist, vhost=True)
    )

    assert content is not None
    assert '"Host: FUZZ.example.test",' in content


def test_run_delivers_credentials_via_config_file_not_argv(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Argv is /proc-readable by any same-UID process; credential-bearing
    options must ride ffuf's -config TOML (0600) instead, and the file
    must not outlive the run."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        config_path = Path(cmd[cmd.index("-config") + 1])
        seen["config_mode"] = config_path.stat().st_mode & 0o777
        seen["config_content"] = config_path.read_text(encoding="utf-8")
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    secret_header = "Authorization: Bearer " + "a" * 32
    secret_cookie = "session=" + "b" * 32
    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(
        FfufConfig(
            wordlist=wordlist,
            headers=(secret_header,),
            cookies=(secret_cookie,),
            data="user=FUZZ&api_key=sk-livesecret",
        )
    )

    assert "-H" not in seen["cmd"]
    assert "-b" not in seen["cmd"]
    assert "-d" not in seen["cmd"]
    assert seen["config_mode"] == 0o600
    assert secret_header in seen["config_content"]
    assert secret_cookie in seen["config_content"]
    assert "sk-livesecret" in seen["config_content"]
    # Credentials must not persist at rest after the run.
    assert not (tmp_path / "ffuf_config.toml").exists()


def test_run_refuses_preplanted_symlink_at_config_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """out_dir is the sandbox's writable scope: a hostile child from a
    previous run can leave ffuf_config.toml as a symlink. The credential
    write must refuse to follow it instead of exfiltrating through it."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    exfil = tmp_path / "EXFIL"
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "ffuf_config.toml").symlink_to(exfil)

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", out_dir)
    runner.run(FfufConfig(wordlist=wordlist, cookies=("session=super-secret",)))

    assert not exfil.exists()

    # A pre-existing regular file must not keep its old (0644) mode either.
    stale = out_dir / "ffuf_config.toml"
    stale.write_text("old", encoding="utf-8")
    stale.chmod(0o644)
    seen: dict = {}

    def fake_run_capture(cmd, **kwargs):
        config_path = Path(cmd[cmd.index("-config") + 1])
        seen["mode"] = config_path.stat().st_mode & 0o777
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run_capture)
    runner.run(FfufConfig(wordlist=wordlist, cookies=("session=super-secret",)))
    assert seen["mode"] == 0o600


def test_run_keeps_config_file_only_with_reveal_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path, reveal_secrets=True)
    runner.run(FfufConfig(wordlist=wordlist, cookies=("session=abc",)))

    assert (tmp_path / "ffuf_config.toml").exists()


def test_run_removes_config_file_on_backstop_timeout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    import subprocess

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"])

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, cookies=("session=abc",)))

    assert result["timed_out"] is True
    assert not (tmp_path / "ffuf_config.toml").exists()


def test_run_grants_grace_beyond_ffuf_maxtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """The subprocess timeout must exceed -maxtime so ffuf's own clean
    shutdown (which flushes the JSON report) always wins the race."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, max_runtime=200))

    assert captured["cmd"][captured["cmd"].index("-maxtime") + 1] == "200"
    # grace = min(30, max(5, 200 // 10)) = 20
    assert captured["kwargs"]["timeout"] == 220
    assert result["timed_out"] is False
    assert result["returncode"] == 0


def test_run_survives_backstop_timeout_and_keeps_partial_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """A wedged ffuf killed by the backstop must degrade to a partial
    summary instead of aborting the whole scan with TimeoutExpired."""
    import subprocess

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps({"results": [{"url": "https://example.test/admin", "status": 200}]}),
            encoding="utf-8",
        )
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=kwargs["timeout"], stderr=b"wedged")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist))

    assert result["timed_out"] is True
    assert result["returncode"] is None
    assert result["result_count"] == 1
    assert result["stderr"] == "wedged"


def test_run_warns_once_on_extreme_thread_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """The warning lives in run(), not build_command, so the CLI
    preflight's validation pass doesn't duplicate it."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    warnings: list[str] = []
    monkeypatch.setattr(
        "packages.web.ffuf.logger.warning",
        lambda fmt, *args: warnings.append(fmt % args if args else fmt),
    )
    runner = FfufRunner("https://example.test", tmp_path)

    runner.build_command(
        FfufConfig(wordlist=wordlist, threads=10000), tmp_path / "o.json"
    )
    assert warnings == []  # preflight path: no duplicate warning

    runner.run(FfufConfig(wordlist=wordlist, threads=64))
    assert warnings == []

    runner.run(FfufConfig(wordlist=wordlist, threads=10000))
    assert sum("unusually high" in w for w in warnings) == 1


def test_build_command_threads_authenticated_ffuf_options(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    output = tmp_path / "ffuf_results.json"
    bearer = "Authorization: Bearer " + "a" * 32

    runner = FfufRunner("https://example.test", tmp_path)
    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            headers=(bearer, "X-Tenant: test"),
            cookies=("session=" + "b" * 32, "pref=dark"),
        ),
        output,
    )

    assert cmd[cmd.index("-H") + 1] == bearer
    assert [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-H"] == [
        bearer,
        "X-Tenant: test",
    ]
    assert [cmd[idx + 1] for idx, value in enumerate(cmd) if value == "-b"] == [
        "session=" + "b" * 32,
        "pref=dark",
    ]


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"headers": ("X-Test: ok\nInjected: yes",)}, "headers must not contain newlines"),
        ({"headers": ("X-Test: ok\rInjected: yes",)}, "headers must not contain newlines"),
        ({"headers": ("Bearer abc123",)}, "headers must be in 'Name: value' form"),
        ({"headers": (": abc123",)}, "headers must be in 'Name: value' form"),
        ({"cookies": ("session=ok\nother=yes",)}, "cookies must not contain newlines"),
        ({"cookies": ("session=ok\rother=yes",)}, "cookies must not contain newlines"),
    ],
)
def test_build_command_rejects_header_cookie_newlines(
    tmp_path: Path,
    config_kwargs: dict[str, tuple[str, ...]],
    message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json")


def test_run_redacts_authenticated_ffuf_options_from_logs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    bearer = "Authorization: Bearer " + "a" * 32
    cookie = "session=" + "b" * 32

    messages: list[str] = []
    monkeypatch.setattr(
        "packages.web.ffuf.logger.info",
        lambda fmt, *args: messages.append(fmt % args if args else fmt),
    )

    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=wordlist, headers=(bearer,), cookies=(cookie,)))

    logs = "\n".join(messages)
    # Names-and-shapes only: header/cookie NAMES appear, values never do.
    assert "Authorization" in logs
    assert "cookie(session)" in logs
    assert "a" * 32 not in logs
    assert "b" * 32 not in logs


@pytest.mark.parametrize(
    "header",
    [
        "Authorization: Token abc123",
        "Authorization: ApiKey short",
        'Authorization: Digest username="u", nonce="n"',
        "Proxy-Authorization: Negotiate abc",
    ],
)
def test_redacts_authorization_headers_without_relying_on_token_shape(
    tmp_path: Path,
    header: str,
):
    runner = FfufRunner("https://example.test", tmp_path)

    assert runner._redact_header_value(header) == f"{header.split(':', 1)[0]}: [REDACTED]"


def test_cookie_redaction_preserves_separator_spacing(tmp_path: Path):
    runner = FfufRunner("https://example.test", tmp_path)

    assert (
        runner._redact_cookie_value("session=abc123; pref=dark")
        == "session=[REDACTED]; pref=[REDACTED]"
    )


def test_run_requires_explicit_ffuf_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: None)

    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(FileNotFoundError, match="ffuf binary not found"):
        runner.run(FfufConfig(wordlist=wordlist))


def test_run_uses_subprocess_argv_and_summarizes_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        captured["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {
                            "url": "https://example.test/admin?" + "tok" + "en=abc123",
                            "status": 200,
                            "length": 42,
                            "words": 3,
                            "lines": 1,
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr=None)

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, path_template="FUZZ"))

    # cmd[0] is the resolved real path (exec-via-realpath), not the
    # operator-facing name.
    assert captured["cmd"][0] == "/usr/bin/ffuf"
    assert captured["kwargs"]["capture_output"] is True
    assert captured["kwargs"]["text"] is True
    assert captured["kwargs"]["proxy_hosts"] == ["example.test"]
    assert captured["kwargs"]["caller_label"] == "web-ffuf"
    assert result["returncode"] == 0
    assert result["stderr"] == ""
    assert result["result_count"] == 1
    assert result["reported_result_count"] == 1
    assert result["omitted_result_count"] == 0
    assert result["results"] == [
        {
            "url": "https://example.test/admin?" + "tok" + "en=[REDACTED]",
            "status": 200,
            "length": 42,
            "words": 3,
            "lines": 1,
        }
    ]


def test_run_limits_embedded_report_results_but_keeps_raw_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf")

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps(
                {
                    "results": [
                        {"url": f"https://example.test/{idx}", "status": 200}
                        for idx in range(3)
                    ]
                }
            ),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, report_limit=2))

    assert result["result_count"] == 3
    assert result["reported_result_count"] == 2
    assert result["omitted_result_count"] == 1
    assert [entry["url"] for entry in result["results"]] == [
        "https://example.test/0",
        "https://example.test/1",
    ]


def test_scanner_cli_wires_all_ffuf_options(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    auth_header = "Authorization: Bearer " + "a" * 32
    session_cookie = "session=" + "b" * 32
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-path",
            "admin/FUZZ",
            "--ffuf-bin",
            "custom-ffuf",
            "--ffuf-threads",
            "7",
            "--ffuf-rate",
            "11",
            "--ffuf-timeout",
            "12",
            "--ffuf-report-limit",
            "13",
            "--ffuf-max-runtime",
            "14",
            "--ffuf-no-auto-calibration",
            "--ffuf-match-status",
            "200,401",
            "--ffuf-filter-status",
            "403,404",
            "--ffuf-filter-size",
            "1234",
            "--ffuf-header",
            auth_header,
            "--ffuf-header",
            "X-Tenant: test",
            "--ffuf-cookie",
            session_cookie,
            "--ffuf-cookie",
            "pref=dark",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.wordlist == wordlist
    assert config.path_template == "admin/FUZZ"
    assert config.binary == "custom-ffuf"
    assert config.threads == 7
    assert config.rate == 11
    assert config.timeout == 12
    assert config.report_limit == 13
    assert config.max_runtime == 14
    assert config.auto_calibration is False
    assert config.match_status == "200,401"
    assert config.filter_status == "403,404"
    assert config.filter_size == 1234
    assert config.headers == (auth_header, "X-Tenant: test")
    assert config.cookies == (session_cookie, "pref=dark")


def test_scanner_cli_wires_ffuf_stop_conditions(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-stop-on-403",
            "--ffuf-stop-on-spurious-errors",
            "--ffuf-stop-on-all-errors",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.stop_on_403 is True
    assert config.stop_on_spurious is True
    assert config.stop_on_all_errors is True

    defaults = build_ffuf_config(
        build_arg_parser().parse_args(
            ["--url", "https://example.test", "--ffuf-wordlist", str(wordlist)]
        )
    )
    assert defaults is not None
    assert defaults.stop_on_403 is False
    assert defaults.stop_on_spurious is False
    assert defaults.stop_on_all_errors is False


def test_scanner_cli_can_omit_optional_ffuf_match_and_filter_status(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    args = build_arg_parser().parse_args(
        [
            "--url",
            "https://example.test",
            "--ffuf-wordlist",
            str(wordlist),
            "--ffuf-match-status",
            "",
            "--ffuf-filter-status",
            "",
        ]
    )

    config = build_ffuf_config(args)

    assert config is not None
    assert config.match_status is None
    assert config.filter_status is None


def test_run_execs_realpath_and_binds_resolved_tool_dir(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Symlinked installs (go install / package manager shims): the
    mount-ns visibility check realpaths cmd[0], so the exec must use
    the REAL binary path and tool_paths must carry the RESOLVED
    parent — otherwise the run silently drops to Landlock-only."""
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    real = tmp_path / "opt" / "ffuf" / "ffuf"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\n")
    link = tmp_path / "bin" / "ffuf"
    link.parent.mkdir()
    link.symlink_to(real)
    monkeypatch.setattr(
        "packages.web.ffuf.shutil.which", lambda _binary: str(link))

    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["cmd"] = list(cmd)
        seen["kwargs"] = dict(kwargs)
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=wordlist))

    assert seen["cmd"][0] == str(real.resolve())
    assert seen["kwargs"]["tool_paths"] == [str(real.resolve().parent)]


def test_run_refuses_oversize_results_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A results file over the byte budget is refused before the read
    — the run degrades to zero results like any unparseable output."""
    import os

    from packages.web import ffuf as ffuf_mod

    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    monkeypatch.setattr(
        "packages.web.ffuf.shutil.which", lambda _binary: "/usr/bin/ffuf",
    )

    def fake_run(cmd, **kwargs):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(
            json.dumps({"results": [{"url": "https://example.test/a",
                                     "status": 200}]}),
            encoding="utf-8",
        )
        # Sparse-extend past the cap: the stat gate fires before any
        # read, so no data is materialised.
        os.truncate(output_path, ffuf_mod._MAX_FFUF_OUTPUT_BYTES + 1)
        return SimpleNamespace(returncode=0, stderr=None)

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)

    runner = FfufRunner("https://example.test", tmp_path)
    result = runner.run(FfufConfig(wordlist=wordlist, path_template="FUZZ"))
    assert result["returncode"] == 0
    assert result["result_count"] == 0
    assert result["results"] == []


def test_build_command_raw_request_mode(tmp_path: Path):
    """-request replaces the URL template; the file's Host is the scope
    anchor and the keyword may live anywhere in the request."""
    wordlist = tmp_path / "params.txt"
    wordlist.write_text("id\n", encoding="utf-8")
    request = tmp_path / "req.txt"
    request.write_text(
        "POST /api/orders HTTP/1.1\n"
        "Host: example.test\n"
        "Content-Type: application/json\n"
        "\n"
        '{"note": "FUZZ"}\n',
        encoding="utf-8",
    )
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(wordlist=wordlist, request_file=request),
        tmp_path / "out.json",
    )

    assert "-u" not in cmd
    assert cmd[cmd.index("-request") + 1] == str(request)
    assert cmd[cmd.index("-request-proto") + 1] == "https"


@pytest.mark.parametrize(
    ("request_text", "config_kwargs", "message"),
    [
        ("GET /x HTTP/1.1\nHost: evil.test\n\nFUZZ", {},
         "outside the configured target scope"),
        ("GET /x HTTP/1.1\nX-A: b\n\nFUZZ", {},
         "exactly one Host header"),
        ("GET /x HTTP/1.1\nHost: example.test\n\nplain", {},
         "no substitution point"),
        ("GET /x HTTP/1.1\nHost: example.test\n\nFUZZ",
         {"method": "POST"}, "carries its own method"),
        ("GET /x HTTP/1.1\nHost: example.test\n\nFUZZ",
         {"path_template": "api/FUZZ"}, "drop the path template"),
        ("GET /x HTTP/1.1\nHost: example.test\n\nFUZZ",
         {"vhost": True}, "cannot be combined with vhost"),
        ("GET /x HTTP/1.1\nHost: example.test\n\nFUZZ",
         {"recursion": True}, "requires a URL template"),
        # The four wire-proven scope bypasses (review PoCs A-D): ffuf's
        # parseRawRequest diverges from a naive first-host-line scan.
        ("GET http://evil.test/FUZZ HTTP/1.1\nHost: example.test\n\n", {},
         "path-only request line"),
        ("GET /x HTTP/1.1\nHost: example.test\nHost: evil.test\n\nFUZZ",
         {}, "exactly one Host header"),
        ("GET /x HTTP/1.1\nX-A: b\n Host: evil.test\nHost: example.test\n\nFUZZ",
         {}, "folded"),
        ("GET /x HTTP/1.1\nhost: example.test\n\nFUZZ", {},
         "exact-case 'Host'"),
        # PoC E: bare host must not widen scope to the scheme-default
        # port when the base URL pins a different one.
        ("GET /x HTTP/1.1\nHost: example.test\n\nFUZZ",
         {"__base__": "https://example.test:8443"},
         "outside the configured target scope"),
        # PoC F/G: header section must be blank-line terminated; a Host
        # in the body (or on a final unterminated line) is invisible to
        # ffuf.
        ("GET /x HTTP/1.1\nX-A: b\n\nHost: example.test FUZZ", {},
         "exactly one Host header"),
        ("GET /x HTTP/1.1\nHost: example.test", {},
         "blank line"),
    ],
)
def test_raw_request_mode_rejections(
    tmp_path: Path, request_text: str, config_kwargs: dict, message: str,
):
    wordlist = tmp_path / "params.txt"
    wordlist.write_text("id\n", encoding="utf-8")
    request = tmp_path / "req.txt"
    request.write_text(request_text, encoding="utf-8")
    base_url = config_kwargs.pop("__base__", "https://example.test")
    runner = FfufRunner(base_url, tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(
            FfufConfig(wordlist=wordlist, request_file=request, **config_kwargs),
            tmp_path / "out.json",
        )


def test_raw_request_host_keyword_is_neutralized_in_scope_check(tmp_path: Path):
    """A keyword in the request file's Host would be substituted at
    runtime — the scope compare must see the neutralized form."""
    wordlist = tmp_path / "params.txt"
    wordlist.write_text("id\n", encoding="utf-8")
    request = tmp_path / "req.txt"
    request.write_text(
        "GET /x HTTP/1.1\nHost: FUZZ.example.test\n\nbody",
        encoding="utf-8",
    )
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match="outside the configured target scope"):
        runner.build_command(
            FfufConfig(wordlist=wordlist, request_file=request),
            tmp_path / "out.json",
        )


def test_run_grants_read_scope_to_request_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    wordlist = tmp_path / "params.txt"
    wordlist.write_text("id\n", encoding="utf-8")
    request = tmp_path / "req.txt"
    request.write_text(
        "GET /x HTTP/1.1\nHost: example.test\n\nFUZZ", encoding="utf-8",
    )
    monkeypatch.setattr("packages.web.ffuf.shutil.which", lambda _b: "/usr/bin/ffuf")
    seen: dict = {}

    def fake_run(cmd, **kwargs):
        seen["kwargs"] = kwargs
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps({"results": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="")

    monkeypatch.setattr("packages.web.ffuf.run_untrusted_networked", fake_run)
    runner = FfufRunner("https://example.test", tmp_path)
    runner.run(FfufConfig(wordlist=wordlist, request_file=request))

    assert str(request.resolve()) in seen["kwargs"]["readable_paths"]


def test_build_command_calibration_knobs_and_encoders(tmp_path: Path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    cmd = runner.build_command(
        FfufConfig(
            wordlist=wordlist,
            calibration_strategy="advanced",
            calibration_per_host=True,
            encoders=("FUZZ:urlencode b64encode",),
        ),
        tmp_path / "out.json",
    )

    assert cmd[cmd.index("-acs") + 1] == "advanced"
    assert "-ach" in cmd
    assert cmd[cmd.index("-enc") + 1] == "FUZZ:urlencode b64encode"


@pytest.mark.parametrize(
    ("config_kwargs", "message"),
    [
        ({"calibration_strategy": "wild"}, "must be 'basic' or 'advanced'"),
        ({"calibration_strategy": "basic", "auto_calibration": False},
         "requires auto-calibration"),
        ({"calibration_per_host": True, "auto_calibration": False},
         "requires auto-calibration"),
        ({"encoders": ("urlencode",)}, "encoder spec must look like"),
        ({"encoders": ("FUZZ:",)}, "encoder spec must look like"),
        ({"encoders": ("W9:urlencode",)}, "unknown keyword"),
    ],
)
def test_calibration_and_encoder_rejections(
    tmp_path: Path, config_kwargs: dict, message: str,
):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("admin\n", encoding="utf-8")
    runner = FfufRunner("https://example.test", tmp_path)

    with pytest.raises(ValueError, match=message):
        runner.build_command(
            FfufConfig(wordlist=wordlist, **config_kwargs), tmp_path / "out.json",
        )


def test_scanner_cli_wires_engine2_flags(tmp_path: Path):
    from packages.web.scanner import build_arg_parser, build_ffuf_config

    wordlist = tmp_path / "w.txt"
    wordlist.write_text("id\n", encoding="utf-8")
    request = tmp_path / "req.txt"
    request.write_text("GET / HTTP/1.1\nHost: x\n\nFUZZ", encoding="utf-8")
    args = build_arg_parser().parse_args([
        "--url", "https://example.test",
        "--ffuf-wordlist", str(wordlist),
        "--ffuf-calibration-strategy", "advanced",
        "--ffuf-per-host-calibration",
        "--ffuf-encoder", "FUZZ:urlencode",
    ])

    config = build_ffuf_config(args)

    assert config is not None
    assert config.calibration_strategy == "advanced"
    assert config.calibration_per_host is True
    assert config.encoders == ("FUZZ:urlencode",)
