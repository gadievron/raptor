"""Fixture tests for the sensitive_data_leak rule.

The negatives pin the substring-match regression: the identifier
pattern matched 'priv' (and 'pass'/'key'/... ) anywhere in the name,
so freeing a driver private-data pointer (`kfree(priv);` — the
standard driver teardown idiom) or any benign carrier of an embedded
word (bypass, monkey, keyboard) minted a CWE-244 secret-leak finding.
Components are now anchored to the start of the name or of an
underscore-separated part, bare `priv` no longer matches, and a small
deny-set drops full English words like keyboard/passthrough.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = (
    Path(__file__).resolve().parents[1] / "rules" / "sensitive_data_leak.cocci"
)

pytestmark = pytest.mark.skipif(
    shutil.which("spatch") is None, reason="coccinelle not installed",
)


def _run_rule(tmp_path: Path, source: str) -> list[dict]:
    return run_rule(tmp_path, source, _RULE)


class TestPositives:
    def test_secret_names_freed_uncleared_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bad(char *password, char *session_token, char *aes_key,
                     char *privkey, char *user_pass)
            {
                free(password);
                free(session_token);
                free(aes_key);
                free(privkey);
                free(user_pass);
            }
        """)
        assert len(results) == 5
        assert all(r["rule"] == "sensitive_data_leak" for r in results)

    def test_kfree_of_secret_fires(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void bad(char *master_secret)
            {
                kfree(master_secret);
            }
        """)
        assert len(results) == 1


class TestNegatives:
    def test_driver_priv_pointer_does_not_fire(self, tmp_path):
        # 'priv' is the standard private-context pointer name across
        # driver code — private DATA, not private KEY.
        results = _run_rule(tmp_path, """\
            void teardown(struct net_device *dev)
            {
                struct drv_priv *priv = netdev_priv(dev);
                kfree(priv);
            }
        """)
        assert results == []

    def test_embedded_word_carriers_do_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void other(char *bypass_flag, char *monkey, char *keyboard,
                       char *passthrough)
            {
                free(bypass_flag);
                free(monkey);
                free(keyboard);
                free(passthrough);
            }
        """)
        assert results == []

    def test_cleared_before_free_does_not_fire(self, tmp_path):
        results = _run_rule(tmp_path, """\
            void good(char *password)
            {
                memset(password, 0, 32);
                free(password);
            }
        """)
        assert results == []

    def test_benign_word_compounds_do_not_fire(self, tmp_path):
        # The benign set must absorb per-component: keyboard_state and
        # usb_keyboard carry the benign word, not a secret — an
        # exact-match set only covered the bare spelling.
        results = _run_rule(tmp_path, """\
            void teardown(char *keyboard_state, char *usb_keyboard,
                          char *keyframes)
            {
                kfree(keyboard_state);
                kfree(usb_keyboard);
                kfree(keyframes);
            }
        """)
        assert results == []

    def test_secret_component_beside_benign_still_fires(self, tmp_path):
        # Recall guards: a real secret component is not laundered by a
        # benign neighbour, and the explicit privkey spelling never
        # consults the benign set.
        results = _run_rule(tmp_path, """\
            void bad(char *keyboard_master_key, char *privkey)
            {
                kfree(keyboard_master_key);
                kfree(privkey);
            }
        """)
        assert sorted(r["line"] for r in results) == [3, 4]


@pytest.mark.parametrize("buffer", ["password", "ctx->password", "item.password"], ids=["local", "pointer-field", "value-field"])
def test_clear_requests_respect_argument_roles_and_paths(tmp_path, buffer):
    cases = [
        ("", True),
        ("memset(B, 0, 32);", False),
        ("memset(B, 65, 32);", True),
        ("memset(B, 0, 0);", True),
        ("memset(B, 0, 0UL);", True),
        ("memset_explicit(B, 0, 32);", False),
        ("memset_explicit(B, 65, 32);", True),
        ("memset_s(B, 32, 0, 32);", False),
        ("memset_s(B, 32, 65, 32);", True),
        ("memset_s(B, 0, 0, 32);", True),
        ("memset_s(B, 32, 0, 0);", True),
        ("explicit_bzero(B, 32);", False),
        ("explicit_bzero(B, 0);", True),
        ("memzero_explicit(B, 32);", False),
        ("memzero_explicit(B, 0);", True),
        ("OPENSSL_cleanse(B, 32);", False),
        ("OPENSSL_cleanse(B, 0);", True),
        ("sodium_memzero(B, 32);", False),
        ("sodium_memzero(B, 0);", True),
        ("if (stop) explicit_bzero(B, 32);", True),
        ("if (stop) explicit_bzero(B, 32); else explicit_bzero(B, 32);", False),
        ("explicit_bzero(B, 32); B[0] = 65;", True),
        ("explicit_bzero(B, 32); B[0] = 0;", False),
        ("explicit_bzero(B, 32); B[0] = 65; explicit_bzero(B, 32);", False),
        ("explicit_bzero(B, 32); memcpy(B, other, 32);", True),
        ("explicit_bzero(B, 32); memcpy(B, other, 0);", False),
        ("explicit_bzero(other, 32);", True),
        ("B = NULL;", False),
        ("explicit_bzero(B, 32); B = other;", True),
    ]
    lines=["struct vault { char *password; };"]
    expected=set()
    for index, (before, reports) in enumerate(cases):
        lines += [f"void case_{index}(char *password, struct vault *ctx, struct vault item, char *other, int stop) {{",
                  before.replace("B", buffer), f"free({buffer});", "}"]
        if reports:
            expected.add(len(lines)-1)
    if buffer == "ctx->password":
        lines += ["void rebind(struct vault *ctx, struct vault *next) {",
                  "explicit_bzero(ctx->password, 32);", "ctx = next;",
                  "free(ctx->password);", "}"]
        expected.add(len(lines)-1)
    elif buffer == "item.password":
        lines += ["void rebind(struct vault item, struct vault next) {",
                  "explicit_bzero(item.password, 32);", "item = next;",
                  "free(item.password);", "}"]
        expected.add(len(lines)-1)
    lines += ["void clearing_release(char *password) {", "kfree_sensitive(password);", "}"]
    rows=_run_rule(tmp_path, "\n".join(lines)+"\n")
    actual={row["line"] for row in rows}
    assert actual==expected, {"missing": expected-actual, "unexpected": actual-expected}
    assert len(rows)==len(expected)
    assert all(row["message"].startswith("Candidate:") for row in rows)


@pytest.mark.integration
def test_clearing_checks_share_production_invocation(tmp_path, monkeypatch):
    from packages.coccinelle import runner

    source=tmp_path / "batch.c"
    source.write_text(
        'void bare(char *password) { free(password); }\n'
        'void intrinsic(char *password) { kfree_sensitive(password); }\n'
        'void explicit_clear(char *password) { explicit_bzero(password, 32); free(password); }\n'
        'void refill(char *password) { explicit_bzero(password, 32); password[0] = 65; free(password); }\n'
        'void ordinary_clear(char *password) { memset(password, 0, 32); free(password); }\n'
        'void empty_clear(char *password) { memset(password, 0, 0); free(password); }\n',
    )
    original=runner._confined_default_runner
    invocations=[]

    def observe(*args, **kwargs):
        execute=original(*args, **kwargs)

        def invoke(argv, **options):
            invocations.append(tuple(argv))
            return execute(argv, **options)

        return invoke

    monkeypatch.setattr(runner, "_confined_default_runner", observe)
    results=runner.run_rules_batched(
        source, [_RULE, _RULE.with_name("dead_memset_free.cocci")],
        allow_scripting=True, no_includes=True, timeout=60,
    )
    assert set(results)=={"sensitive_data_leak", "dead_memset_free"}
    assert all(result.returncode == 0 and not result.errors for result in results.values()), results
    assert len(results["sensitive_data_leak"].matches)==3
    assert len(results["dead_memset_free"].matches)==1
    assert len(invocations)==1, invocations


@pytest.mark.integration
@pytest.mark.parametrize("other_hit", [False, True], ids=["file-empty", "other-function-hit"])
def test_partial_data_silence_is_inconclusive(tmp_path, other_hit):
    from core.audit.sweep import run_coccinelle_file_sweep, scope_coccinelle_result

    prefix = ''
    source = prefix + 'void partial(const char *secret) { char *payload = malloc(32); memcpy(payload, secret, 32); free(payload); }' + "\n"
    line = 1 + prefix.count("\n")
    if other_hit:
        source += 'void other(const char *secret) { char *password = malloc(32); memcpy(password, secret, 32); free(password); }' + "\n"
    (tmp_path / "partial.c").write_text(source)
    result = run_coccinelle_file_sweep(
        target_path=tmp_path, file_path="partial.c", cocci_rule=str(_RULE), language="c",
    )
    assert not result.errors, result.errors
    assert result.outcome == ("confirmed" if other_hit else "inconclusive")
    assert len(result.matches) == int(other_hit)
    if other_hit:
        assert result.matches[0]["line"] > line
        assert result.matches[0]["rule"] == 'sensitive_data_leak'
    assert result.details["confirm_only"]
    scoped = scope_coccinelle_result(
        result, target_path=tmp_path, function_name="partial",
        line_start=line, line_end=line, language="c",
    )
    assert scoped.outcome == "inconclusive"
    assert not scoped.matches
    assert scoped.details["confirm_only"]
    assert len(result.matches) == int(other_hit)
