"""Policy closure for the output-encoding families (CWE-116, CWE-93).

Pins the whole contract in one place: the classes are tool-verifiable
(never parked in CWE_NOT_TOOL_VERIFIABLE) but only sub-shape-narrow —
so dispatch routes per-language curated rules, the SMT verb and the
sanitizer-aware flow lane are registered detection-role, and silence
NEVER clears (both classes stay out of the tool_coverage
silence→clean map, immune to the sarif-cache alias).

Hermetic — no LLM, no semgrep binary, no JVM (the flow-lane tests use
the canned-server pattern from test_joern_verify).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import core.audit.joern_verify as joern_verify
from core.audit.cwe_dispatch import (
    CWE_NOT_TOOL_VERIFIABLE,
    CWE_TO_TOOL_DISPATCH,
    infer_cwe_from_hypothesis,
    joern_applicable,
    lookup,
    not_tool_verifiable_reason,
    resolve_semgrep_rule_for_cwe,
)
from core.audit.joern_verify import (
    DETECTION_STAMPS,
    FLOW_CWES,
    FLOW_ENCODING_STAMP,
    FLOW_STAMP,
    flow_chain_entry,
    flow_sanitizer_names,
    run_flow_reachability_check,
)
from core.audit.orchestrator import _cwe_fallback_chain
from core.audit.tool_coverage import _CWE_TOOL_MAP, is_class_covered
from packages.joern.models import JoernResult
from packages.joern.runner import _parse_output

_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "engine" / "semgrep" / "rules"
)

_ENCODING_CWES = ("CWE-93", "CWE-116")

# Fixed sentinel nonce (the test_joern_verify convention).
NONCE = "0123456789abcdef"


def _n(raw: str) -> str:
    return re.sub(
        r"(RAPTOR_(?:GD|FLOW)_[A-Z_]+:)", rf"\g<1>{NONCE}:", raw,
    )


@pytest.fixture(autouse=True)
def _fixed_nonce(monkeypatch):
    monkeypatch.setattr(joern_verify, "_mint_nonce", lambda: NONCE)


class FakeServer:
    def __init__(self, raw_output: str = ""):
        self.raw_output = _n(raw_output)

    def query(self, cpgql, *, timeout=None, check_length=True, **kw):
        flows, parse_errors = _parse_output(self.raw_output)
        return JoernResult(
            query=cpgql,
            flows=flows,
            raw_output=self.raw_output,
            errors=parse_errors,
        )


class TestPolicyPark:
    @pytest.mark.parametrize("cwe", _ENCODING_CWES)
    def test_never_in_the_not_verifiable_park(self, cwe: str):
        # The classes ARE tool-verifiable (narrowly) — parking them
        # would kill the dispatch entries and the synthesis lane both.
        assert cwe not in CWE_NOT_TOOL_VERIFIABLE
        assert not_tool_verifiable_reason(cwe) == ""

    @pytest.mark.parametrize("cwe", _ENCODING_CWES)
    def test_dispatch_entry_present(self, cwe: str):
        assert lookup(cwe) is not None


class TestPerLanguageRouting:
    def test_c_and_cpp_route_to_the_c_rules(self):
        for ext in ("main.c", "main.cpp"):
            r116 = resolve_semgrep_rule_for_cwe("CWE-116", ext)
            assert r116 and r116.endswith("c/quoted-string-escape.yaml")
            r93 = resolve_semgrep_rule_for_cwe("CWE-93", ext)
            assert r93 and r93.endswith("c/crlf-protocol-line.yaml")

    def test_php_legs_unchanged(self):
        r116 = resolve_semgrep_rule_for_cwe("CWE-116", "index.php")
        assert r116 and r116.endswith("php/attr-encoding.yaml")
        r93 = resolve_semgrep_rule_for_cwe("CWE-93", "index.php")
        assert r93 and r93.endswith("php/crlf-injection.yaml")

    def test_unmapped_languages_get_no_leg(self):
        for path in ("app.py", "lib.js", "pkg/mod.go", ""):
            assert resolve_semgrep_rule_for_cwe("CWE-116", path) is None
            assert resolve_semgrep_rule_for_cwe("CWE-93", path) is None

    def test_every_by_lang_reference_exists_on_disk(self):
        for cwe, entry in CWE_TO_TOOL_DISPATCH.items():
            for lang, name in (entry.get("semgrep_by_lang") or {}).items():
                assert (_RULES_DIR / name).is_file(), (
                    f"{cwe} routes {lang} to missing rule {name}"
                )

    def test_c_chain_shape(self):
        chain = _cwe_fallback_chain("CWE-116", "", "main.c")
        by_type = {e["type"]: e for e in chain}
        assert by_type["semgrep"]["config"]["rule"].endswith(
            "c/quoted-string-escape.yaml",
        )
        # Curated rules carry their own precision — no "keyword" key
        # (the dynamic-rule gates stay off).
        assert "keyword" not in by_type["semgrep"]["config"]
        assert "joern" in by_type
        assert by_type["joern_flow"]["config"]["sanitizer_classes"] == [
            "xss",
        ]
        chain93 = _cwe_fallback_chain("CWE-93", "", "main.c")
        semgrep93 = [e for e in chain93 if e["type"] == "semgrep"]
        assert len(semgrep93) == 1
        assert semgrep93[0]["config"]["rule"].endswith(
            "c/crlf-protocol-line.yaml",
        )

    def test_hypothesis_phrasings_reach_cwe116(self):
        for h in (
            "missing escaping of the backslash in the emitter",
            "improper output encoding of the header value",
            "the function escapes only the double quote",
        ):
            assert infer_cwe_from_hypothesis(h) == "CWE-116"

    def test_injection_phrasings_keep_their_rows(self):
        # First-match-wins: the appended encoding row must not steal
        # earlier families.
        assert infer_cwe_from_hypothesis(
            "command injection due to missing escaping",
        ) == "CWE-78"
        assert infer_cwe_from_hypothesis(
            "crlf injection into the smtp stream",
        ) == "CWE-93"


class TestSilenceNeverClears:
    ALL_TOOLS = {
        "prefilter": True, "semgrep": True, "codeql": True,
        "joern": True, "coccinelle": True, "smt": True,
    }

    @pytest.mark.parametrize("cwe", _ENCODING_CWES)
    def test_not_in_the_coverage_map(self, cwe: str):
        # The receipt-keyed coverage refactor is the only honest path
        # to silence→clean for narrow rules; until it exists these
        # classes must classify dark on silence.
        assert cwe not in _CWE_TOOL_MAP

    @pytest.mark.parametrize("cwe", _ENCODING_CWES)
    def test_silence_stays_dark_for_every_ran_channel(self, cwe: str):
        for ran in ({"semgrep"}, {"joern"}, {"joern_flow"},
                    {"smt"}, {"sarif_cache"}):
            assert is_class_covered(
                cwe, "", "", self.ALL_TOOLS, ran_tools=ran,
            ) is False


class TestVerbRegistryClosure:
    def test_verb_registered_with_shim_on_disk(self):
        from core.audit import sweep as sweep_mod

        shim_name = sweep_mod._SMT_VERBS["check-encoding-residual"]
        raptor_dir = Path(sweep_mod.__file__).resolve().parents[2]
        assert (raptor_dir / "libexec" / shim_name).is_file()

    def test_verb_is_detection_role(self):
        from core.audit.sweep import (
            get_smt_verb_role,
            is_detection_rule_id,
            is_vacuous_smt_verb,
        )

        assert get_smt_verb_role("check-encoding-residual") == "detection"
        assert is_detection_rule_id("smt:check-encoding-residual")
        # Fully constrained intrinsic: SAT is meaningful without
        # guards, so the vacuity clamp must not fire.
        assert not is_vacuous_smt_verb("check-encoding-residual")


class TestJoernLanguageGate:
    """CWE-116's joern legs are language-gated to c/cpp: the seed
    sinks are libc emitters and the lane's fixtures are C. The PHP
    chain shape must stay exactly as it was before the C legs
    existed."""

    def test_php_chain_stays_semgrep_only(self):
        chain = _cwe_fallback_chain("CWE-116", "", "index.php")
        assert [e["type"] for e in chain] == ["semgrep"]

    def test_non_c_targets_get_no_joern_legs(self):
        for path in ("app.py", "lib.js", "index.php"):
            assert not joern_applicable("CWE-116", path)
            assert flow_chain_entry("CWE-116", path) is None

    def test_blind_dispatch_fails_closed(self):
        # No file context: a leg whose fixtures cover only c/cpp must
        # not dispatch blind.
        assert not joern_applicable("CWE-116")
        assert flow_chain_entry("CWE-116") is None

    def test_ungated_families_keep_blind_behaviour(self):
        # Entries without joern_langs behave as before regardless of
        # file context.
        assert joern_applicable("CWE-79")
        assert joern_applicable("CWE-79", "index.php")
        assert flow_chain_entry("CWE-79") is not None


class TestFlowEncodingLane:
    def test_cwe116_in_flow_cwes_with_sanitizer_classes(self):
        assert "CWE-116" in FLOW_CWES
        assert joern_applicable("CWE-116", "main.c")
        entry = flow_chain_entry("CWE-116", "main.c")
        assert entry is not None
        assert entry["config"]["sanitizer_classes"] == ["xss"]

    def test_other_flow_families_carry_no_sanitizer_classes(self):
        for cwe in ("CWE-79", "CWE-89", "CWE-22"):
            entry = flow_chain_entry(cwe)
            assert entry is not None
            assert "sanitizer_classes" not in entry["config"]

    def test_encoding_stamp_is_detection_grade(self):
        assert FLOW_ENCODING_STAMP in DETECTION_STAMPS
        assert joern_verify.is_detection_rule_id(FLOW_ENCODING_STAMP)
        # The plain endpoint-bound flow stamp keeps verification role.
        assert not joern_verify.is_detection_rule_id(FLOW_STAMP)

    def test_lane_arming_invariant_every_class_has_seeds(self):
        """flow_sanitizer_names must never resolve empty for an armed
        lane — an empty resolution would stamp the confirm with the
        verification-grade FLOW_STAMP instead of the detection-grade
        FLOW_ENCODING_STAMP. Seeds guarantee non-empty resolution for
        every armed class regardless of catalog language or IRIS
        availability."""
        from core.audit.joern_verify import (
            _FLOW_SANITIZER_CLASSES,
            _SANITIZER_NAME_SEEDS,
        )

        for cwe, classes in _FLOW_SANITIZER_CLASSES.items():
            for cls in classes:
                assert _SANITIZER_NAME_SEEDS.get(cls), (
                    f"{cwe} arms the flow lane with class {cls!r} "
                    "but that class has no seeds — resolution could "
                    "be empty and the lane would silently disarm"
                )
            # No catalog language, no IRIS specs: seeds alone must
            # keep the lane armed on a C target.
            assert flow_sanitizer_names(classes, "a.c", None)

    def test_iris_reader_is_per_entry_tolerant(self, tmp_path):
        # One junk entry must not drop the valid ones, and both role
        # spellings are accepted.
        import json as _json

        (tmp_path / "iris-taint-specs.json").write_text(_json.dumps([
            {"role": "sanitiser", "function": "escape_html_attr"},
            "junk-string-entry",
            {"role": "sanitizer", "function": "us_spelled_escape"},
            {"role": "sanitiser"},
            {"role": "sanitiser", "function": "bad name()"},
            42,
        ]))
        names = flow_sanitizer_names(["xss"], "a.c", tmp_path)
        assert "escape_html_attr" in names
        assert "us_spelled_escape" in names
        assert all("(" not in n for n in names)

    def test_sanitizer_names_union_catalog_iris_seeds(self, tmp_path):
        from core.audit.iris_specs import TaintSpec, specs_to_json

        (tmp_path / "iris-taint-specs.json").write_text(specs_to_json([
            TaintSpec(function="escape_html_attr", file="a.c",
                      role="sanitiser"),
            TaintSpec(function="read_input", file="a.c", role="source"),
            # Junk names must never enter the matcher.
            TaintSpec(function="bad name()", file="a.c",
                      role="sanitiser"),
        ]))
        names = flow_sanitizer_names(["xss"], "a.py", tmp_path)
        assert "escape_html_attr" in names       # IRIS, learned
        assert "html.escape" in names            # catalog (python)
        assert "htmlspecialchars" in names       # seed
        assert "read_input" not in names         # wrong role
        assert all("(" not in n for n in names)  # junk filtered
        # No classes → the plain flow lane, untouched.
        assert flow_sanitizer_names([], "a.py", tmp_path) == ()

    def _run_flow(self, tmp_path, raw, **kw):
        return run_flow_reachability_check(
            target_path=tmp_path,
            file_path="src/a.c",
            function_name="emit",
            source_id="val",
            sink_call="fwrite",
            server=FakeServer(raw),
            **kw,
        )

    @staticmethod
    def _flow_json(*codes: str) -> str:
        steps = ",".join(
            f'{{"line":{i},"code":"{c}","function":"emit",'
            f'"file":"a.c"}}'
            for i, c in enumerate(codes, start=1)
        )
        return f"JOERN_FLOW:[{steps}]"

    def test_unsanitized_flow_confirms_with_encoding_stamp(
        self, tmp_path,
    ):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\n"
            + self._flow_json("char *val", "fwrite(val)")
            + "\nRAPTOR_FLOW_COUNT:1\n"
        )
        r = self._run_flow(
            tmp_path, raw, sanitizer_names=("htmlspecialchars",),
        )
        assert r.outcome == "confirmed"
        assert r.rule_id == FLOW_ENCODING_STAMP
        assert r.details["sanitized_flow_count"] == 0

    def test_all_flows_sanitized_is_inconclusive_both_ways(
        self, tmp_path,
    ):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\n"
            + self._flow_json(
                "char *val", "htmlspecialchars(val)", "fwrite(val)",
            )
            + "\nRAPTOR_FLOW_COUNT:1\n"
        )
        r = self._run_flow(
            tmp_path, raw, sanitizer_names=("htmlspecialchars",),
        )
        # Not confirmed (premise failed) and not refuted (a name
        # match proves nothing about encoding correctness).
        assert r.outcome == "inconclusive"
        assert r.details["sanitized_flow_count"] == 1

    def test_without_sanitizer_names_behaviour_is_unchanged(
        self, tmp_path,
    ):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\n"
            + self._flow_json(
                "char *val", "htmlspecialchars(val)", "fwrite(val)",
            )
            + "\nRAPTOR_FLOW_COUNT:1\n"
        )
        r = self._run_flow(tmp_path, raw)
        assert r.outcome == "confirmed"
        assert r.rule_id == FLOW_STAMP

    def test_zero_flow_refutation_lane_unchanged_under_lane(
        self, tmp_path,
    ):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:2\n"
            "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:0\n"
            "RAPTOR_FLOW_DEEP:0\n"
        )
        r = self._run_flow(
            tmp_path, raw, sanitizer_names=("htmlspecialchars",),
        )
        assert r.outcome == "refuted"


class TestCliDispatchability:
    """The sweep CLI must accept and dispatch the verb end-to-end —
    a registry entry the argparse layer rejects is dead code (the
    --smt-verb choices now derive from the registry)."""

    def test_sweep_cli_dispatches_encoding_residual(self, tmp_path):
        import os
        import subprocess
        import sys

        target = tmp_path / "tgt"
        target.mkdir()
        (target / "a.c").write_text("int f(void) { return 0; }\n")
        out = tmp_path / "out"
        out.mkdir()
        repo = Path(__file__).resolve().parents[3]
        env = dict(os.environ)
        env["_RAPTOR_TRUSTED"] = "1"
        proc = subprocess.run(
            [sys.executable, str(repo / "libexec" / "raptor-audit"),
             "sweep", "--tool", "smt",
             "--smt-verb", "check-encoding-residual",
             "--smt-args",
             '{"transfer": {"escaped": ["\\""]}, '
             '"grammar": "quoted-string"}',
             "--file", "a.c", "--function", "f",
             "--target", str(target), "--out", str(out)],
            capture_output=True, text=True, timeout=300, check=False,
            env=env,
        )
        assert proc.returncode == 0, proc.stderr[:800]
        # Dispatchability is the pin — the verdict depends on z3
        # availability (confirmed with z3, inconclusive without).
        assert "with smt:check-encoding-residual" in proc.stdout

    def test_choices_cover_every_registered_verb(self):
        # The CLI derives its --smt-verb choices from the registry;
        # this pins the derivation source stays importable and total.
        from core.audit.sweep import _SMT_VERBS

        assert "check-encoding-residual" in _SMT_VERBS


class TestSmtArgsSerialization:
    """List smt_args keys serialise per their shim contract: repeated
    flags by default (--guard/--operand), ONE JSON array for keys in
    _SMT_JSON_ARRAY_ARGS (--forbidden). A repeated --forbidden would
    hand argparse only the last element — silently narrowing the
    forbidden set toward refutation."""

    _STUB = '''#!/usr/bin/env python3
import json, sys
print(json.dumps({"feasible": None, "argv": sys.argv[1:]}))
'''

    def _run(self, monkeypatch, tmp_path, smt_args):
        from core.audit import sweep as sweep_mod
        from core.audit.sweep import run_smt_sweep

        shim = tmp_path / "raptor-smt-check-encoding-residual"
        shim.write_text(self._STUB)
        monkeypatch.setattr(sweep_mod, "_SMT_SHIM_DIR", tmp_path)
        result = run_smt_sweep(
            file_path="a.c", function_name="f",
            verb="check-encoding-residual", smt_args=smt_args,
        )
        assert result.outcome == "inconclusive", result.errors
        import json as _json

        return _json.loads(result.raw_output)["argv"]

    def test_forbidden_list_passes_as_one_json_array(
        self, monkeypatch, tmp_path,
    ):
        import json as _json

        argv = self._run(monkeypatch, tmp_path, {
            "transfer": {"escaped": ['"']},
            "forbidden": ["\r", 0],
        })
        assert argv.count("--forbidden") == 1
        payload = argv[argv.index("--forbidden") + 1]
        assert _json.loads(payload) == ["\r", 0]
        # The transfer dict rides as one JSON object.
        assert _json.loads(argv[argv.index("--transfer") + 1]) == {
            "escaped": ['"'],
        }

    def test_other_lists_keep_repeated_flag_contract(
        self, monkeypatch, tmp_path,
    ):
        argv = self._run(monkeypatch, tmp_path, {
            "transfer": {"escaped": []},
            "guard": ["a > 0", "b > 0"],
        })
        assert argv.count("--guard") == 2


class TestEvidenceGradeMirror:
    """The string-heuristic fallback in evidence_grade must mirror the
    channel classifiers for the new stamps — exercised with the
    classifier import stubbed out, the exact path a host without the
    channel modules takes."""

    def _mirror(self, monkeypatch, stamp: str) -> bool:
        import core.audit.evidence_grade as eg

        monkeypatch.setattr(
            eg, "_channel_detection_classifier", lambda ns: None,
        )
        return eg._is_detection_variant(stamp)

    def test_flow_encoding_stamp_detection_in_mirror(self, monkeypatch):
        assert self._mirror(monkeypatch, "joern:flow-encoding")
        assert not self._mirror(monkeypatch, "joern:flow")

    def test_encoding_residual_detection_in_mirror(self, monkeypatch):
        assert self._mirror(monkeypatch, "smt:check-encoding-residual")
        # The :witness escape is withheld for this verb — its model
        # ranges over an unverified transfer description.
        assert self._mirror(
            monkeypatch, "smt:check-encoding-residual:witness",
        )
        # Other verbs keep the :witness receipt and their roles.
        assert not self._mirror(monkeypatch, "smt:check-toctou:witness")
        assert self._mirror(monkeypatch, "smt:check-toctou")
