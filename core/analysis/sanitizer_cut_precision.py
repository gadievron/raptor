"""Zero-false-suppress precision harness for the sanitizer-cut gate.

The suppression doctrine (:mod:`core.analysis.reach_witness`, binary-
oracle precedent): a witness kind may hard-suppress a finding ONLY
after a labelled corpus shows zero false-suppress for it. This module
is the sanitizer-cut counterpart of
:mod:`core.analysis.binary_oracle_precision`: it runs the value-bound
gate (the full production path — ``resolve_finding`` →
``evaluate_finding``, inter-procedural bindings included) over a
labelled fixture corpus and reports whether any fixture labelled
``must_not_suppress`` received the ``suppress`` verdict.

The gate metric is **false suppressions** — a fixture that carries a
real (or unprovable) flaw yet gets verdict ``suppress``. The corpus is
deliberately adversarial: wrong-class sanitizers, sanitizers on N-1 of
N paths, sanitization after the sink, straight-line and loop rebinds,
wrong-variable cleaning, unrelated-constant sanitization, a
catalog-empty class, and an unsupported language. ``candidate_only`` /
``no_suppress`` / ``unresolved`` all PASS for a must-not-suppress
fixture — only ``suppress`` fails the gate.

``may_suppress`` fixtures measure utility (how many genuinely-safe
shapes the gate actually suppresses); a miss there is reported but is
NOT a gate failure — soundness first.

Until a run of this harness is clean across every covered sink class
AND its report is recorded alongside the flip, the
``sanitizer_dominated`` entry in :mod:`core.analysis.reach_witness`
stays ``earns_suppression=False`` and the live producer
(:func:`core.dataflow.smt_barrier._record_value_bound_audit`) writes
record-only evidence (``dropped: false``).

Run via ``libexec/raptor-sanitizer-cut-precision``.
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.json import dumps_display

LABEL_MUST_NOT_SUPPRESS = "must_not_suppress"
LABEL_MAY_SUPPRESS = "may_suppress"

_VERDICT_SUPPRESS = "suppress"


@dataclass(frozen=True)
class CutFixture:
    """One labelled corpus entry. ``shape`` names the adversarial (or
    safe) pattern the fixture exercises so the per-class report rows
    are self-describing. All sources are hand-built public CWE example
    patterns — no undisclosed vulnerabilities (repo corpus doctrine).
    """
    name: str
    sink_class: str
    cwe: str
    language: str
    shape: str
    label: str
    source: str
    source_line: int
    sink_line: int
    suffix: str = ".py"
    # Sidecar files written beside the fixture source (relative path →
    # content) — the config-resolution battery ships .properties files
    # the resolver must locate under the fixture's directory.
    aux_files: dict[str, str] = field(default_factory=dict)
    # Cross-file batteries (b37): root the fixture in its own
    # subdirectory and pass it as the finding's repo_root, so the
    # cross-file resolver sees exactly the fixture's aux .java files —
    # never a sibling fixture's (the shared work dir would otherwise
    # cross-contaminate class resolution).
    use_repo_root: bool = False


@dataclass
class FixtureMeasurement:
    name: str
    sink_class: str
    shape: str
    label: str
    verdict: str

    @property
    def false_suppress(self) -> bool:
        return (self.label == LABEL_MUST_NOT_SUPPRESS
                and self.verdict == _VERDICT_SUPPRESS)

    @property
    def missed_suppress(self) -> bool:
        return (self.label == LABEL_MAY_SUPPRESS
                and self.verdict != _VERDICT_SUPPRESS)


@dataclass
class PrecisionReport:
    """Corpus-level result, binary_oracle_precision report style."""
    corpus_name: str
    n_fixtures: int
    measurements: list[FixtureMeasurement] = field(default_factory=list)
    verdict_counts: dict[str, int] = field(default_factory=dict)
    false_suppressions: list[str] = field(default_factory=list)
    missed_suppressions: list[str] = field(default_factory=list)
    # cross_tab[sink_class][label][verdict] = count
    cross_tab: dict[str, dict[str, dict[str, int]]] = field(
        default_factory=dict)
    n_must_not: int = 0
    # 3/n rule-of-three 95% upper bound on the false-suppress rate,
    # meaningful only when false_suppressions is empty.
    rule_of_three_95_ub: float | None = None
    toolchain: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus_name,
            "n_fixtures": self.n_fixtures,
            "n_must_not_suppress": self.n_must_not,
            "verdict_counts": self.verdict_counts,
            "false_suppressions": self.false_suppressions,
            "missed_suppressions": self.missed_suppressions,
            "cross_tab": self.cross_tab,
            "rule_of_three_95_upper_bound_false_suppress_rate":
                self.rule_of_three_95_ub,
            "toolchain": self.toolchain,
            "measurements": [
                {
                    "name": m.name,
                    "sink_class": m.sink_class,
                    "shape": m.shape,
                    "label": m.label,
                    "verdict": m.verdict,
                }
                for m in self.measurements
            ],
        }


def _fx(name, sink_class, cwe, shape, label, source, src_ln, sink_ln,
        language: str="python", suffix: str=".py", aux_files=None,
        use_repo_root: bool=False) -> CutFixture:
    return CutFixture(
        name=name, sink_class=sink_class, cwe=cwe, language=language,
        shape=shape, label=label, source=source,
        source_line=src_ln, sink_line=sink_ln, suffix=suffix,
        aux_files=aux_files or {}, use_repo_root=use_repo_root,
    )


def _class_fixtures(sink_class, cwe, sanitizer, wrong_sanitizer,
                    sink) -> list[CutFixture]:
    """The per-class fixture template: safe shapes + the adversarial
    battery, instantiated with the class's catalog sanitizer, a
    catalog sanitizer of a DIFFERENT class (the wrong-class case),
    and the class's sink call."""
    c = sink_class
    return [
        _fx(f"{c}_straight_line", c, cwe, "straight_line",
            LABEL_MAY_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {sanitizer}(x)\n"
            f"    {sink}(y)\n", 1, 3),
        _fx(f"{c}_symmetric_branches", c, cwe, "symmetric_branches",
            LABEL_MAY_SUPPRESS,
            f"def handle(x, flag):\n"
            f"    if flag:\n"
            f"        y = {sanitizer}(x)\n"
            f"    else:\n"
            f"        y = {sanitizer}(x)\n"
            f"    {sink}(y)\n", 1, 6),
        _fx(f"{c}_partial_path", c, cwe, "sanitizer_on_n_minus_1_paths",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x, flag):\n"
            f"    if flag:\n"
            f"        y = {sanitizer}(x)\n"
            f"    else:\n"
            f"        y = x\n"
            f"    {sink}(y)\n", 1, 6),
        _fx(f"{c}_wrong_class", c, cwe, "wrong_class_sanitizer",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {wrong_sanitizer}(x)\n"
            f"    {sink}(y)\n", 1, 3),
        _fx(f"{c}_after_sink", c, cwe, "sanitizer_after_sink",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    {sink}(x)\n"
            f"    y = {sanitizer}(x)\n", 1, 2),
        _fx(f"{c}_straight_rebind", c, cwe, "sanitized_then_rebound",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {sanitizer}(x)\n"
            f"    y = x\n"
            f"    {sink}(y)\n", 1, 4),
        _fx(f"{c}_loop_rebind", c, cwe, "sanitized_then_loop_rebound",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(items, x):\n"
            f"    y = {sanitizer}(x)\n"
            f"    for i in items:\n"
            f"        y = i\n"
            f"    {sink}(y)\n", 1, 5),
        _fx(f"{c}_wrong_variable", c, cwe, "wrong_variable_sanitized",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(user, other):\n"
            f"    safe = {sanitizer}(other)\n"
            f"    {sink}(user)\n", 1, 3),
        _fx(f"{c}_unrelated_constant", c, cwe, "sanitizes_constant_only",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    y = {sanitizer}('const')\n"
            f"    {sink}(x)\n", 1, 3),
        _fx(f"{c}_no_exit_validator", c, cwe, "validator_without_exit",
            LABEL_MUST_NOT_SUPPRESS,
            f"def handle(x):\n"
            f"    if not x.isalnum():\n"
            f"        log('bad')\n"
            f"    {sink}(x)\n", 1, 4),
    ]


def _java_fixtures() -> list[CutFixture]:
    """The Java adversarial battery (b13 leg) — b11's shapes
    re-instantiated in Java plus the Java-specific hazards: the
    wrong-class URLEncoder case (a URL encoder before an HTML sink
    must never suppress), reference-aliasing escapes (array store,
    field store), the chained ESAPI singleton idiom, and the
    lambda-refusal case (the builder must refuse, not mis-model).
    """
    imp = "import org.owasp.encoder.Encode;\n"
    cls = "public class T {\n"
    end = "}\n"

    def meth(body: str, params: str = "String x, java.io.PrintWriter out",
             throws: str = "") -> str:
        return (f"{cls}    public void handle({params}){throws} {{\n"
                f"{body}    }}\n{end}")

    j = []
    j.append(_fx(
        "java_xss_straight_line", "xss", "CWE-79", "straight_line",
        LABEL_MAY_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        out.println(y);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_symmetric_branches", "xss", "CWE-79",
        "symmetric_branches", LABEL_MAY_SUPPRESS,
        imp + meth("        String y;\n"
                   "        if (x.length() > 3) { y = Encode.forHtml(x); }\n"
                   "        else { y = Encode.forHtmlContent(x); }\n"
                   "        out.println(y);\n",
                   params="String x, java.io.PrintWriter out"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_partial_path", "xss", "CWE-79",
        "sanitizer_on_n_minus_1_paths", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y;\n"
                   "        if (x.length() > 3) { y = Encode.forHtml(x); }\n"
                   "        else { y = x; }\n"
                   "        out.println(y);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_wrong_class_urlencoder", "xss", "CWE-79",
        "wrong_class_sanitizer", LABEL_MUST_NOT_SUPPRESS,
        "import java.net.URLEncoder;\n"
        + meth("        String y = URLEncoder.encode(x, \"UTF-8\");\n"
               "        out.println(y);\n",
               throws=" throws Exception"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_after_sink", "xss", "CWE-79", "sanitizer_after_sink",
        LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        out.println(x);\n"
                   "        String y = Encode.forHtml(x);\n"),
        3, 4, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_straight_rebind", "xss", "CWE-79",
        "sanitized_then_rebound", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        y = x;\n"
                   "        out.println(y);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_loop_rebind", "xss", "CWE-79",
        "sanitized_then_loop_rebound", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        for (String i : items) { y = i; }\n"
                   "        out.println(y);\n",
                   params="String x, String[] items, "
                          "java.io.PrintWriter out"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_wrong_variable", "xss", "CWE-79",
        "wrong_variable_sanitized", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String safe = Encode.forHtml(other);\n"
                   "        out.println(user);\n",
                   params="String user, String other, "
                          "java.io.PrintWriter out"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_constant_only", "xss", "CWE-79",
        "sanitizes_constant_only", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(\"const\");\n"
                   "        out.println(x);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_no_exit_validator", "xss", "CWE-79",
        "validator_without_exit", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        if (x.contains(\"<\")) { "
                   "System.err.println(\"bad\"); }\n"
                   "        out.println(x);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        # b19 note: the original body's array was LOCAL, fresh, and
        # never read — element tracking proves it irrelevant to the
        # sanitized scalar sink, so the old body became legitimately
        # suppressible (the b19 exemption). The alias line below makes
        # the array genuinely untracked, preserving this fixture's
        # guard role: an escaping array on the path must keep the
        # may_escape downgrade.
        "java_xss_array_store_escape", "xss", "CWE-79",
        "array_element_aliasing", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        String[] b = a;\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        b[0] = x;\n"
                   "        String y = Encode.forHtml(x);\n"
                   "        out.println(y);\n"),
        3, 9, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_esapi_chain", "xss", "CWE-79", "esapi_singleton_chain",
        LABEL_MAY_SUPPRESS,
        "import org.owasp.esapi.ESAPI;\n"
        + meth("        String y = ESAPI.encoder().encodeForHTML(x);\n"
               "        out.println(y);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_instance_encoder_untyped", "xss", "CWE-79",
        "instance_call_no_type_inference", LABEL_MUST_NOT_SUPPRESS,
        # ``enc`` is untyped from the gate's perspective — could be
        # anything with an encodeForHTML method. Must not resolve to
        # the ESAPI catalog entry.
        meth("        String y = enc.encodeForHTML(x);\n"
             "        out.println(y);\n",
             params="String x, Object enc, java.io.PrintWriter out"),
        2, 4, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_lambda_refusal", "xss", "CWE-79",
        "lambda_forces_refusal", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        Runnable r = () -> out.println(x);\n"
                   "        String y = Encode.forHtml(x);\n"
                   "        out.println(y);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_xss_try_catch_safe", "xss", "CWE-79", "try_catch_safe",
        LABEL_MAY_SUPPRESS,
        imp + meth("        try {\n"
                   "            String y = Encode.forHtml(x);\n"
                   "            out.println(y);\n"
                   "        } catch (Exception e) { "
                   "out.println(\"err\"); }\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_sqli_catalog_empty", "sqli", "CWE-89",
        "catalog_empty_class", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        stmt.execute(y);\n",
                   params="String x, java.sql.Statement stmt",
                   throws=" throws Exception"),
        3, 5, language="java", suffix=".java"))
    return j


def _java_wrapper_fixtures() -> list[CutFixture]:
    """b19 wrapper-summary battery. Adversarial shapes first — every
    way a helper can LOOK like a sanitizer without being one must
    refuse: a non-sanitizing body, a two-level wrapper (depth cap), a
    branchy body, an overridable instance method (dynamic dispatch),
    recursion, same-arity overloads, and a mixed clean+dirty parameter
    signature. Safe shapes: the direct wrapper and the
    local-chain body."""
    imp = "import org.owasp.encoder.Encode;\n"

    def cls(helpers: str, body: str,
            params: str = "String x, java.io.PrintWriter out") -> str:
        return ("public class T {\n"
                f"{helpers}"
                f"    public void handle({params}) {{\n"
                f"{body}    }}\n"
                "}\n")

    j = []
    j.append(_fx(
        "java_wrap_nonsanitizing", "xss", "CWE-79",
        "wrapper_without_sanitizer", LABEL_MUST_NOT_SUPPRESS,
        cls("    private static String clean(String s) {\n"
            "        return s.trim();\n"
            "    }\n",
            "        String y = clean(x);\n"
            "        out.println(y);\n"),
        5, 7, language="java", suffix=".java"))
    j.append(_fx(
        # b19 pinned depth-2 as a refusal; b21's composition proves
        # exactly this shape, so the clean two-level wrapper GRADUATES
        # to may_suppress. The standing depth cap pin is
        # java_xss_depth3_refusal_pin in the b21 battery.
        "java_wrap_two_level", "xss", "CWE-79",
        "wrapper_depth_two", LABEL_MAY_SUPPRESS,
        imp + cls(
            "    private static String inner(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private static String outer(String s) "
            "{ return inner(s); }\n",
            "        String y = outer(x);\n"
            "        out.println(y);\n"),
        5, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_branchy", "xss", "CWE-79",
        "wrapper_sanitizes_one_branch", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String s) {\n"
            "        if (s.length() > 3) { return Encode.forHtml(s); }\n"
            "        return s;\n"
            "    }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        7, 9, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_overridable", "xss", "CWE-79",
        "wrapper_dynamic_dispatch", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    public String h(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_recursive", "xss", "CWE-79",
        "wrapper_recursion", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String s) "
            "{ return h(Encode.forHtml(s)); }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_overloaded", "xss", "CWE-79",
        "wrapper_overload_ambiguity", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String s) "
            "{ return Encode.forHtml(s); }\n"
            "    private static String h(Object s) "
            "{ return s.toString(); }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        5, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_mixed_params", "xss", "CWE-79",
        "wrapper_clean_and_dirty_params", LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String a, String b) {\n"
            "        return Encode.forHtml(a) + b;\n"
            "    }\n",
            "        String y = h(x, x);\n"
            "        out.println(y);\n"),
        6, 8, language="java", suffix=".java"))
    j.append(_fx(
        # U09-F21 twin: the SAME parameter both sanitized and raw in
        # one return expression — the wrapper must never read clean.
        "java_wrap_mixed_same_param", "xss", "CWE-79",
        "wrapper_mixed_sanitized_and_raw_same_param",
        LABEL_MUST_NOT_SUPPRESS,
        imp + cls(
            "    private static String h(String a) {\n"
            "        return Encode.forHtml(a) + a;\n"
            "    }\n",
            "        String y = h(x);\n"
            "        out.println(y);\n"),
        6, 8, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_direct", "xss", "CWE-79",
        "wrapper_direct_sanitizer", LABEL_MAY_SUPPRESS,
        imp + cls(
            "    private static String esc(String s) "
            "{ return Encode.forHtml(s); }\n",
            "        String y = esc(x);\n"
            "        out.println(y);\n"),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_wrap_local_chain", "xss", "CWE-79",
        "wrapper_local_chain", LABEL_MAY_SUPPRESS,
        imp + cls(
            "    private static String esc(String s) {\n"
            "        String t = Encode.forHtml(s);\n"
            "        return t;\n"
            "    }\n",
            "        String y = esc(x);\n"
            "        out.println(y);\n"),
        7, 9, language="java", suffix=".java"))
    return j


def _java_array_fixtures() -> list[CutFixture]:
    """b19 element-sensitivity battery. Adversarial shapes first —
    every way per-element reasoning can be broken must refuse: element
    rebind with taint, element mismatch trusted via base-name kills,
    reference aliasing (both directions), the array passed to a
    helper, a field array, a non-constant index poisoning the array,
    a compound element write, an enhanced-for element read, a tainted
    write below the sink, and a whole-array sink pass. Safe shapes:
    the direct element read, the one-scalar-hop copy, and the
    incidental-tracked-array exemption."""
    imp = "import org.owasp.encoder.Encode;\n"

    def meth(body: str,
             params: str = "String x, java.io.PrintWriter out") -> str:
        return ("public class T {\n"
                f"    public void handle({params}) {{\n"
                f"{body}    }}\n"
                "}\n")

    j = []
    j.append(_fx(
        "java_arr_element_rebind", "xss", "CWE-79",
        "element_rebound_with_taint", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[0] = x;\n"
                   "        out.println(a[0]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        # The base-name reaching-defs inversion: a[1]'s write kills
        # a[0]'s in the base-name lattice, so trusting RD here would
        # read "only the sanitizer reaches" while the sink consumes
        # the TAINTED element. Flow-insensitive exclusivity refuses.
        "java_arr_element_mismatch", "xss", "CWE-79",
        "element_mismatch_rd_inversion", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[1] = x;\n"
                   "        out.println(a[1]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_alias_out", "xss", "CWE-79",
        "array_alias_out", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        String[] b = a;\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        b[0] = x;\n"
                   "        out.println(a[0]);\n"),
        3, 8, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_helper_escape", "xss", "CWE-79",
        "array_passed_to_helper", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        fill(a, x);\n"
                   "        out.println(a[0]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_field_array", "xss", "CWE-79",
        "field_array_not_local", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        this.a[0] = Encode.forHtml(x);\n"
                   "        out.println(this.a[0]);\n"),
        3, 5, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_nonconst_index", "xss", "CWE-79",
        "nonconstant_index_poisons", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[i] = x;\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        out.println(a[0]);\n",
                   params="String x, int i, java.io.PrintWriter out"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_compound_write", "xss", "CWE-79",
        "compound_element_write", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[0] += x;\n"
                   "        out.println(a[0]);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_enhanced_for_read", "xss", "CWE-79",
        "enhanced_for_element_read", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[1] = x;\n"
                   "        for (String s : a) { out.println(s); }\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_taint_below_sink", "xss", "CWE-79",
        "tainted_write_below_sink", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        out.println(a[0]);\n"
                   "        a[0] = x;\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_whole_array_sink", "xss", "CWE-79",
        "whole_array_sink_pass", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        a[1] = x;\n"
                   "        out.println(a);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        # Exemption blocker: an UNTRACKED (field) array access on the
        # path must keep the may_escape downgrade even though the
        # scalar binding held.
        "java_arr_untracked_on_path", "xss", "CWE-79",
        "untracked_array_blocks_exemption", LABEL_MUST_NOT_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        this.cache[0] = y;\n"
                   "        out.println(y);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_element_direct", "xss", "CWE-79",
        "element_direct_read", LABEL_MAY_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        out.println(a[0]);\n"),
        3, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_scalar_hop", "xss", "CWE-79",
        "element_scalar_hop", LABEL_MAY_SUPPRESS,
        imp + meth("        String[] a = new String[2];\n"
                   "        a[0] = Encode.forHtml(x);\n"
                   "        String bar = a[0];\n"
                   "        out.println(bar);\n"),
        3, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_arr_incidental_exempt", "xss", "CWE-79",
        "tracked_array_exemption", LABEL_MAY_SUPPRESS,
        imp + meth("        String y = Encode.forHtml(x);\n"
                   "        String[] a = new String[1];\n"
                   "        a[0] = y;\n"
                   "        out.println(y);\n"),
        3, 7, language="java", suffix=".java"))
    return j


def _java_switch_fixtures() -> list[CutFixture]:
    """Switch battery: constant-resolved selection may suppress; every
    variation where the model could hide a live path — non-constant
    discriminant, the fold selecting the tainted branch, fall-through
    from the safe case into a re-taint (the missing-break hazard), an
    unresolvable constant-variable label — must not."""
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    def sw(num_line: str, *, drop_break: bool = False) -> str:
        case_stmts = ['switch (num) {', '  case 106:', '    bar = "safe";']
        if not drop_break:
            case_stmts.append('    break;')
        case_stmts += ['  default:', '    bar = param;', '    break;', '}']
        return body('String param = request.getParameter("q");',
                    num_line, 'String bar;', *case_stmts,
                    'out.println(bar);')

    j = []
    j.append(_fx(
        "java_switch_constant_safe", "xss", "CWE-79",
        "switch_constant_selected_safe", LABEL_MAY_SUPPRESS,
        sw('int num = 106;'), 4, 15, language="java", suffix=".java"))
    j.append(_fx(
        "java_switch_nonconstant", "xss", "CWE-79",
        "switch_nonconstant_discriminant", LABEL_MUST_NOT_SUPPRESS,
        sw('int num = request.getIntHeader("n");'), 4, 15,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_switch_selects_tainted", "xss", "CWE-79",
        "switch_constant_selects_tainted", LABEL_MUST_NOT_SUPPRESS,
        sw('int num = 105;'), 4, 15, language="java", suffix=".java"))
    j.append(_fx(
        "java_switch_fallthrough_retaint", "xss", "CWE-79",
        "switch_fallthrough_retaint", LABEL_MUST_NOT_SUPPRESS,
        sw('int num = 106;', drop_break=True), 4, 14,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_switch_charat_selected_safe", "xss", "CWE-79",
        "switch_charat_selected_safe", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String guess = "ABC";',
             "char target = guess.charAt(1);",
             'String bar;',
             'switch (target) {', "  case 'A':", '    bar = param;',
             '    break;', "  case 'B':", '    bar = "bob";',
             '    break;', '  default:', '    bar = param;',
             '    break;', '}',
             'out.println(bar);'), 4, 19,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_switch_charat_selected_tainted", "xss", "CWE-79",
        "switch_charat_selected_tainted", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String guess = "ABC";',
             "char target = guess.charAt(0);",
             'String bar;',
             'switch (target) {', "  case 'A':", '    bar = param;',
             '    break;', "  case 'B':", '    bar = "bob";',
             '    break;', '  default:', '    bar = param;',
             '    break;', '}',
             'out.println(bar);'), 4, 19,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_switch_identifier_label", "xss", "CWE-79",
        "switch_identifier_label", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'final int SAFE = 106;', 'int num = 106;', 'String bar;',
             'switch (num) {', '  case SAFE:', '    bar = "safe";',
             '    break;', '  default:', '    bar = param;',
             '    break;', '}',
             'out.println(bar);'), 4, 16,
        language="java", suffix=".java"))
    return j


def _java_valueset_fixtures() -> list[CutFixture]:
    """Constant-table battery: a provably-unmodified literal table read
    by a constant index may suppress; stores, aliases (assignment or
    call argument), tainted elements, out-of-bounds and non-constant
    indexes must not."""
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    j = []
    j.append(_fx(
        "java_table_constant_read", "xss", "CWE-79",
        "table_constant_read", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String[] values = {"safe0", "safe1"};',
             'String bar = values[1];',
             'out.println(bar);'), 4, 7,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_element_store", "xss", "CWE-79",
        "table_element_store", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String[] values = {"safe0", "safe1"};',
             'values[1] = param;',
             'String bar = values[1];',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_alias_store", "xss", "CWE-79",
        "table_alias_store", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String[] values = {"safe0", "safe1"};',
             'String[] other = values;',
             'other[1] = param;',
             'String bar = values[1];',
             'out.println(bar);'), 4, 9,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_alias_call", "xss", "CWE-79",
        "table_alias_call_argument", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String[] values = {"safe0", "safe1"};',
             'java.util.Arrays.fill(values, param);',
             'String bar = values[1];',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_tainted_element", "xss", "CWE-79",
        "table_tainted_element", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String[] values = {param, "safe1"};',
             'String bar = values[0];',
             'out.println(bar);'), 4, 7,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_nonconstant_index", "xss", "CWE-79",
        "table_nonconstant_index", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int k = request.getIntHeader("n");',
             'String[] values = {"safe0", "safe1"};',
             'String bar = values[k];',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_out_of_bounds", "xss", "CWE-79",
        "table_out_of_bounds_index", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String[] values = {"safe0"};',
             'String bar = values[3];',
             'out.println(bar);'), 4, 7,
        language="java", suffix=".java"))
    j.append(_fx(
        "java_table_switch_discriminant", "xss", "CWE-79",
        "table_switch_discriminant", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int[] keys = {105, 106};',
             'String bar;',
             'switch (keys[1]) {', '  case 106:', '    bar = "safe";',
             '    break;', '  default:', '    bar = param;',
             '    break;', '}',
             'out.println(bar);'), 4, 15,
        language="java", suffix=".java"))
    return j




def _marked(name, sink_class, cwe, shape, label, source,
            src_marker, sink_marker) -> CutFixture:
    """b21 fixture constructor: source/sink lines are computed from
    unique substring markers — a hand-miscounted line number turned a
    corpus run into a false-positive hunt once; never again."""
    lines = source.splitlines()
    src_ln = next(i for i, ln in enumerate(lines, 1) if src_marker in ln)
    sink_ln = next(i for i, ln in enumerate(lines, 1) if sink_marker in ln)
    return _fx(name, sink_class, cwe, shape, label, source,
               src_ln, sink_ln, language="java", suffix=".java")


def _java_b21_fixtures() -> list[CutFixture]:
    """The b21 battery: cross-class/depth-2 wrapper shapes and
    constant-collection membership guards. MUST-NOT entries split into
    genuinely-unsafe shapes and deliberate refusal pins (genuinely safe
    but outside the mechanisms' proof scope — named ``_refusal_pin``,
    following the b13 lambda-pin precedent)."""
    imp = "import org.owasp.encoder.Encode;\n"

    def cls_t(body: str) -> str:
        return imp + "public class T {\n" + body + "}\n"

    handle = ("    public void handle(String x, "
              "java.io.PrintWriter out) {\n")
    j: list[CutFixture] = []

    # ---- Mechanism 1: wrapper summaries v2 ----
    j.append(_marked(
        "java_xss_innerclass_wrapper", "xss", "CWE-79",
        "cross_class_inner_wrapper", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().doSomething(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String doSomething(String p) {\n"
              + "            return Encode.forHtml(p);\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_xss_static_helper_class", "xss", "CWE-79",
        "cross_class_static_wrapper", LABEL_MAY_SUPPRESS,
        imp + "final class H {\n"
        + "    static String esc(String s) { return Encode.forHtml(s); }\n"
        + "}\n"
        + "public class T {\n" + handle
        + "        String y = H.esc(x);\n"
        + "        out.println(y);\n    }\n}\n",
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_depth2_wrapper", "xss", "CWE-79",
        "depth2_wrapper_composition", LABEL_MAY_SUPPRESS,
        cls_t("    private String inner(String s) "
              "{ return Encode.forHtml(s); }\n"
              "    private String outerw(String s) "
              "{ return inner(s) + \"!\"; }\n"
              + handle
              + "        String y = outerw(x);\n"
              + "        out.println(y);\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_ctor_taint", "xss", "CWE-79",
        "taint_storing_constructor", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String y = new Holder(x).out();\n"
              + "        out.println(y);\n    }\n"
              + "    private class Holder {\n"
              + "        String v;\n"
              + "        Holder(String s) { v = s; }\n"
              + "        String out() { return v; }\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_override_dispatch", "xss", "CWE-79",
        "subclass_override_dispatch", LABEL_MUST_NOT_SUPPRESS,
        imp + "class Base {\n"
        + "    public String m(String s) { return Encode.forHtml(s); }\n"
        + "}\n"
        + "class Evil extends Base {\n"
        + "    public String m(String s) { return s; }\n"
        + "}\n"
        + "public class T {\n" + handle
        + "        Base b = new Evil();\n"
        + "        String y = b.m(x);\n"
        + "        out.println(y);\n    }\n}\n",
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_cycle_wrappers", "xss", "CWE-79",
        "two_level_wrapper_cycle", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    private String a(String s) { return b(s); }\n"
              "    private String b(String s) { return a(s); }\n"
              + handle
              + "        String y = a(x);\n"
              + "        out.println(y);\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_depth3_refusal_pin", "xss", "CWE-79",
        "depth3_wrapper_refusal_pin", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    private String w1(String s) "
              "{ return Encode.forHtml(s); }\n"
              "    private String w2(String s) { return w1(s); }\n"
              "    private String w3(String s) { return w2(s); }\n"
              + handle
              + "        String y = w3(x);\n"
              + "        out.println(y);\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_passthrough_helper", "xss", "CWE-79",
        "passthrough_wrapper", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String y = new W().doSomething(x);\n"
              + "        out.println(y);\n    }\n"
              + "    private class W {\n"
              + "        public String doSomething(String p) "
              "{ return p; }\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_instance_state_helper", "xss", "CWE-79",
        "field_mediated_wrapper", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String y = new W().doSomething(x);\n"
              + "        out.println(y);\n    }\n"
              + "    private class W {\n"
              + "        String f = \"x\";\n"
              + "        public String doSomething(String p) "
              "{ f = p; return f; }\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_sanitizing_ctor_refusal_pin", "xss", "CWE-79",
        "creation_with_args_refusal_pin", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String y = new W(x).out();\n"
              + "        out.println(y);\n    }\n"
              + "    private class W {\n"
              + "        private final String v;\n"
              + "        W(String s) { v = Encode.forHtml(s); }\n"
              + "        String out() { return v; }\n    }\n"),
        "public void handle", "out.println(y)"))
    j.append(_marked(
        "java_xss_ambiguous_class_name", "xss", "CWE-79",
        "ambiguous_helper_class_name", LABEL_MUST_NOT_SUPPRESS,
        imp + "class Outer {\n"
        + "    static class W {\n"
        + "        static String esc(String s) { return s; }\n    }\n"
        + "}\n"
        + "class W {\n"
        + "    static String esc(String s) { return Encode.forHtml(s); }\n"
        + "}\n"
        + "public class T {\n" + handle
        + "        String y = W.esc(x);\n"
        + "        out.println(y);\n    }\n}\n",
        "public void handle", "out.println(y)"))

    # ---- Mechanism 2: constant-collection membership guards ----
    allowed = ("        java.util.List<String> allowed = "
               "java.util.Arrays.asList(\"home\", \"about\");\n")
    j.append(_marked(
        "java_xss_contains_exit_guard", "xss", "CWE-79",
        "collection_guard_exit_on_fail", LABEL_MAY_SUPPRESS,
        cls_t(handle + allowed
              + "        if (!allowed.contains(x)) { return; }\n"
              + "        out.println(x);\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_sqli_contains_enclosed", "sqli", "CWE-89",
        "collection_guard_enclosed_sink", LABEL_MAY_SUPPRESS,
        "public class T {\n"
        + "    public void handle(String x, java.sql.Statement st)"
        " throws Exception {\n"
        + "        java.util.List<String> allowed = "
        "java.util.Arrays.asList(\"name\", \"email\");\n"
        + "        if (allowed.contains(x)) {\n"
        + "            st.executeQuery(x);\n        }\n    }\n}\n",
        "public void handle", "st.executeQuery(x)"))
    j.append(_marked(
        "java_xss_contains_exclusion", "xss", "CWE-79",
        "collection_guard_exit_on_match_exclusion",
        LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle + allowed
              + "        if (allowed.contains(x)) { return; }\n"
              + "        out.println(x);\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_xss_contains_continue_exclusion", "xss", "CWE-79",
        "collection_guard_continue_exclusion", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(String[] xs, "
              "java.io.PrintWriter out) {\n"
              + "        java.util.List<String> allowed = "
              "java.util.Arrays.asList(\"home\", \"about\");\n"
              + "        for (String x : xs) {\n"
              + "            if (allowed.contains(x)) { continue; }\n"
              + "            out.println(x);\n        }\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_xss_contains_mutated", "xss", "CWE-79",
        "collection_guard_mutable_collection", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle + allowed
              + "        allowed.add(x);\n"
              + "        if (!allowed.contains(x)) { return; }\n"
              + "        out.println(x);\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_xss_contains_nonliteral", "xss", "CWE-79",
        "collection_guard_nonliteral_element", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(String x, String other, "
              "java.io.PrintWriter out) {\n"
              + "        java.util.List<String> allowed = "
              "java.util.Arrays.asList(\"home\", other);\n"
              + "        if (!allowed.contains(x)) { return; }\n"
              + "        out.println(x);\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_xss_contains_other_var", "xss", "CWE-79",
        "collection_guard_different_variable", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(String x, String y, "
              "java.io.PrintWriter out) {\n" + allowed
              + "        if (!allowed.contains(y)) { return; }\n"
              + "        out.println(x);\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_xss_contains_reassigned", "xss", "CWE-79",
        "collection_guard_reassigned_between", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(String x, String t, "
              "java.io.PrintWriter out) {\n" + allowed
              + "        if (!allowed.contains(x)) { return; }\n"
              + "        x = t;\n"
              + "        out.println(x);\n    }\n"),
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_sqli_contains_dangerous_literal", "sqli", "CWE-89",
        "collection_guard_dangerous_literal", LABEL_MUST_NOT_SUPPRESS,
        "public class T {\n"
        + "    public void handle(String x, java.sql.Statement st)"
        " throws Exception {\n"
        + "        java.util.List<String> allowed = "
        "java.util.Arrays.asList(\"o'brien\", \"name\");\n"
        + "        if (!allowed.contains(x)) { return; }\n"
        + "        st.executeQuery(x);\n    }\n}\n",
        "public void handle", "st.executeQuery(x)"))
    j.append(_marked(
        "java_xss_contains_static_field", "xss", "CWE-79",
        "collection_guard_static_final_field", LABEL_MAY_SUPPRESS,
        imp + "public class T {\n"
        + "    private static final java.util.Set<String> ALLOWED =\n"
        + "            new java.util.HashSet<>(java.util.Arrays.asList("
        "\"home\", \"about\"));\n"
        + handle
        + "        if (!ALLOWED.contains(x)) { return; }\n"
        + "        out.println(x);\n    }\n}\n",
        "public void handle", "out.println(x)"))
    j.append(_marked(
        "java_xss_contains_nonfinal_field", "xss", "CWE-79",
        "collection_guard_nonfinal_field", LABEL_MUST_NOT_SUPPRESS,
        imp + "public class T {\n"
        + "    static java.util.Set<String> ALLOWED =\n"
        + "            new java.util.HashSet<>(java.util.Arrays.asList("
        "\"home\", \"about\"));\n"
        + handle
        + "        if (!ALLOWED.contains(x)) { return; }\n"
        + "        out.println(x);\n    }\n}\n",
        "public void handle", "out.println(x)"))
    return j


def _java_b40_fixtures() -> list[CutFixture]:
    """Dead-branch if-pruning + finite value-set battery (b40).

    Both payoff directions ride the constant machinery, so every
    fixture's must-not twin exercises the damage direction: a LIVE
    tainted branch selected by the fold, an unfoldable / TAINT_FREE
    condition that must keep every edge, a dangerous constant inside
    an otherwise-finite set, and the tainted fall-through of a
    missing else."""
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    j = []
    # -- if-pruning: dead tainted branch → only the constant reaches.
    j.append(_fx(
        "java_if_deadbranch_folds", "xss", "CWE-79",
        "if_deadbranch_folds", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = "safe";',
             'if ((7 * 42) - num > 200) { bar = param; }',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    # -- recall safety: the fold selects the TAINTED branch — live.
    j.append(_fx(
        "java_if_livebranch_taint", "xss", "CWE-79",
        "if_livebranch_taint", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = "safe";',
             'if ((7 * 42) - num < 200) { bar = param; }',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    # -- unfoldable condition: both branches live, taint reaches.
    j.append(_fx(
        "java_if_unfoldable_kept", "xss", "CWE-79",
        "if_unfoldable_kept", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = "safe";',
             'if (param.length() > 3) { bar = param; }',
             'out.println(bar);'), 4, 7,
        language="java", suffix=".java"))
    # -- TAINT_FREE condition has no VALUE: must not prune.
    j.append(_fx(
        "java_if_taintfree_cond_unpruned", "xss", "CWE-79",
        "if_taintfree_cond", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String mode = System.getProperty("mode");',
             'String bar = "safe";',
             'if (mode == null) { bar = param; }',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    # -- finite value-set: the equals-chain, all members clear xss.
    j.append(_fx(
        "java_equals_chain_constants", "xss", "CWE-79",
        "equals_chain_constants", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.equals("a")) { bar = "v1"; }',
             'else if (param.equals("b")) { bar = "v2"; }',
             'else { bar = "d"; }',
             'out.println(bar);'), 4, 9,
        language="java", suffix=".java"))
    # -- one member carries a danger char: must not suppress.
    j.append(_fx(
        "java_equals_chain_danger_member", "xss", "CWE-79",
        "equals_chain_danger", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.equals("a")) { bar = "v1"; }',
             'else { bar = "<b>x</b>"; }',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    # -- one branch assigns the tainted value: must not suppress.
    j.append(_fx(
        "java_equals_chain_nonconst", "xss", "CWE-79",
        "equals_chain_nonconst", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.equals("a")) { bar = "v1"; }',
             'else { bar = param; }',
             'out.println(bar);'), 4, 8,
        language="java", suffix=".java"))
    # -- missing else over a tainted pre-init: the fall-through
    #    definition reaches — must not suppress.
    j.append(_fx(
        "java_equals_chain_fallthrough_taint", "xss", "CWE-79",
        "equals_chain_fallthrough", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = param;',
             'if (param.equals("a")) { bar = "v1"; }',
             'out.println(bar);'), 4, 7,
        language="java", suffix=".java"))
    return j


def build_corpus() -> list[CutFixture]:
    """The labelled corpus: the adversarial battery instantiated per
    covered python sink class, plus interproc, catalog-empty-class,
    unsupported-language singletons, and the Java battery (b13 leg).

    Sanitizer names come from the catalog
    (:func:`core.dataflow.sanitizer_catalog.sanitizer_callables_for_cwe`)
    — a test pins that each per-class sanitizer used here is really in
    the catalog for its class and the wrong-class one is NOT.
    """
    fixtures: list[CutFixture] = []
    fixtures += _class_fixtures(
        "xss", "CWE-79", "html.escape", "shlex.quote", "render")
    fixtures += _class_fixtures(
        "cmdi", "CWE-78", "shlex.quote", "html.escape", "os.system")
    fixtures += _class_fixtures(
        "pathtrav", "CWE-22", "werkzeug.utils.secure_filename",
        "html.escape", "open")
    fixtures.append(_fx(
        "xss_helper_interproc", "xss", "CWE-79", "sanitizer_in_helper",
        LABEL_MAY_SUPPRESS,
        "def _clean(s):\n"
        "    return html.escape(s)\n"
        "def handle(x):\n"
        "    y = _clean(x)\n"
        "    render(y)\n", 3, 5))
    # Same-param mixed-expression battery (U09-F21 regression): a
    # helper whose return mixes the sanitized and the RAW value of the
    # SAME parameter in one expression, plus the branch-join variant of
    # the same collapse. The taint-summary merge used to union the raw
    # pass-through atom into the sanitized chain, destroying the
    # direct-return sentinel and minting a clean-sanitizer wrapper
    # from a helper that provably passes the raw value through.
    fixtures.append(_fx(
        "xss_helper_mixed_same_param", "xss", "CWE-79",
        "wrapper_mixed_sanitized_and_raw_same_param",
        LABEL_MUST_NOT_SUPPRESS,
        "def _mix(s):\n"
        "    return html.escape(s) + s\n"
        "def handle(x):\n"
        "    y = _mix(x)\n"
        "    render(y)\n", 3, 5))
    fixtures.append(_fx(
        "xss_helper_branch_join_bypass", "xss", "CWE-79",
        "wrapper_sanitizes_one_branch_same_var",
        LABEL_MUST_NOT_SUPPRESS,
        "def _maybe(s):\n"
        "    if len(s) > 3:\n"
        "        s = html.escape(s)\n"
        "    return s\n"
        "def handle(x):\n"
        "    y = _maybe(x)\n"
        "    render(y)\n", 5, 7))
    # Catalog-empty class: python has no sqli sanitizer entries, so
    # nothing may EVER suppress a CWE-89 python finding — including a
    # plausible-looking wrong-class escape.
    fixtures.append(_fx(
        "sqli_catalog_empty", "sqli", "CWE-89", "catalog_empty_class",
        LABEL_MUST_NOT_SUPPRESS,
        "def q(v):\n"
        "    v2 = html.escape(v)\n"
        "    cursor.execute(v2)\n", 1, 3))
    # C leg: the resolver's C intra-proc path (or, on builds without
    # it, an unresolved refusal) must never read an unsanitized
    # system(cmd) as suppressible.
    fixtures.append(_fx(
        "c_unsanitized_system", "cmdi", "CWE-78", "c_language",
        LABEL_MUST_NOT_SUPPRESS,
        "void run(char *cmd) {\n"
        "    system(cmd);\n"
        "}\n", 1, 2, language="c", suffix=".c"))
    fixtures += _java_fixtures()
    fixtures += _java_b21_fixtures()
    fixtures += _java_switch_fixtures()
    fixtures += _java_valueset_fixtures()
    fixtures += _java_constant_fixtures()
    fixtures += _java_b40_fixtures()
    fixtures += _java_wrapper_fixtures()
    fixtures += _java_array_fixtures()
    fixtures += _java_config_fixtures()
    fixtures += _java_b27_fixtures()
    fixtures += _java_b28_collection_fixtures()
    fixtures += _java_b33_sink_shape_fixtures()
    fixtures += _java_b34_positional_fixtures()
    fixtures += _java_b37_fixtures()
    fixtures += _java_b36_fixtures()
    fixtures += _java_b41_fixtures()
    fixtures += _java_b42_fixtures()
    return fixtures


def _java_b41_fixtures() -> list[CutFixture]:
    """The b41 battery: multi-deep-name sink binding, value-carrying
    pick preference, and multi-line statement retargeting.

    The load-bearing must-not is the b34 incident shape restated on
    the newly opened deep-name surface: ``println(pre + bar)`` with
    the picked name catalog-sanitized while the sibling carries taint
    through a same-file helper the local taint front cannot see. The
    resolution extension may only ever hand the gate MORE visible
    shapes — it must never let this one suppress."""
    imp = ("import org.owasp.encoder.Encode;\n"
           "import javax.servlet.http.HttpServletRequest;\n")

    def cls_t(body: str) -> str:
        return imp + "public class T {\n" + body + "}\n"

    handle = ("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) {\n"
              "        String x = request.getParameter(\"q\");\n")
    j: list[CutFixture] = []

    # ---- must-not-suppress ----
    # Deep-multi surface, helper-fed sibling taint (b34 incident shape).
    j.append(_marked(
        "java_b41_concat_sibling_helper_taint", "xss", "CWE-79",
        "deep_multi_sibling_helper_taint", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = Encode.forHtml(x);\n"
              + "        String pre = fetch(request);\n"
              + "        out.println(pre + bar);\n    }\n"
              + "    private static String fetch("
              "HttpServletRequest r) {\n"
              + "        return r.getParameter(\"h\");\n    }\n"),
        "request.getParameter(\"q\")", "out.println(pre + bar)"))
    # Deep-multi surface, sibling tainted in plain sight.
    j.append(_marked(
        "java_b41_concat_sibling_direct_taint", "xss", "CWE-79",
        "deep_multi_sibling_direct_taint", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = Encode.forHtml(x);\n"
              + "        String pre = x;\n"
              + "        out.println(pre + bar);\n    }\n"),
        "request.getParameter(\"q\")", "out.println(pre + bar)"))
    # Multi-line retargeting must not manufacture suppression: the
    # retargeted statement consumes the raw tainted value.
    j.append(_marked(
        "java_b41_multiline_tainted", "xss", "CWE-79",
        "multiline_sink_retarget_tainted", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = x;\n"
              + "        out.println(\n"
              + "                bar); // sink continuation line\n"
              + "    }\n"),
        "request.getParameter(\"q\")", "bar); // sink continuation"))
    # Positional simulation: remove inside a loop body breaks the
    # single-block linearity token — the read must stay governed by
    # every write (the tainted one included).
    j.append(_marked(
        "java_b41_pos_remove_in_loop", "xss", "CWE-79",
        "pos_remove_in_loop", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        java.util.ArrayList<String> l = "
              "new java.util.ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.add(\"moresafe\");\n"
              + "        for (int i = 0; i < 1; i++) {\n"
              + "            l.remove(0);\n"
              + "        }\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "request.getParameter(\"q\")", "out.println(bar)"))
    # Positional simulation: remove(variable) is not simulatable; the
    # leftover scan must untrack the list entirely.
    j.append(_marked(
        "java_b41_pos_remove_variable", "xss", "CWE-79",
        "pos_remove_variable_index", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        java.util.ArrayList<String> l = "
              "new java.util.ArrayList<String>();\n"
              + "        int k = 0;\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.add(\"moresafe\");\n"
              + "        l.remove(k);\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "request.getParameter(\"q\")", "out.println(bar)"))

    # ---- may-suppress: the shapes the extensions unlock ----
    # Deep-multi surface: constant prefix + catalog-sanitized value
    # (the Benchmark's decorated-println shape).
    j.append(_marked(
        "java_b41_concat_const_prefix_sanitized", "xss", "CWE-79",
        "deep_multi_const_prefix", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = Encode.forHtml(x);\n"
              + "        String pre = \"Result: \";\n"
              + "        out.println(pre + bar);\n    }\n"),
        "request.getParameter(\"q\")", "out.println(pre + bar)"))
    # Package-chain argument (Locale-first format): the pick must land
    # on a value-carrying name, not the package root.
    j.append(_marked(
        "java_b41_locale_first_format", "xss", "CWE-79",
        "package_chain_pick", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = Encode.forHtml(x);\n"
              + "        out.format(java.util.Locale.US, "
              "\"%s\", bar);\n    }\n"),
        "request.getParameter(\"q\")", "out.format(java.util.Locale.US"))
    # Multi-line statement: the finding flags the continuation line.
    j.append(_marked(
        "java_b41_multiline_sanitized", "xss", "CWE-79",
        "multiline_sink_retarget", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = Encode.forHtml(x);\n"
              + "        out.println(\n"
              + "                bar); // sink continuation line\n"
              + "    }\n"),
        "request.getParameter(\"q\")", "bar); // sink continuation"))
    return j


def _java_b27_fixtures() -> list[CutFixture]:
    """The b27 battery: conduit summaries — helpers that provably
    return either a compile-time constant or a specific parameter
    UNCHANGED. A conduit call site is value-transparent: the sink's
    taint question passes through to the argument (or vanishes on the
    constant side — constants are taint-free for the taint classes
    this gate serves, the precedent the b17 constant-definers gate
    settled). The adversarial direction is transparency HONESTY: a
    tainted argument must ride through untouched."""
    imp = ("import org.owasp.encoder.Encode;\n"
           "import javax.servlet.http.HttpServletRequest;\n")

    def cls_t(body: str) -> str:
        return imp + "public class T {\n" + body + "}\n"

    handle = ("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) {\n"
              "        String x = request.getParameter(\"q\");\n")
    j: list[CutFixture] = []

    # ---- may-suppress: the shapes the mechanism exists for ----
    j.append(_marked(
        "java_conduit_static_const", "xss", "CWE-79",
        "conduit_static_const", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = C.pick();\n"
              + "        out.println(bar);\n    }\n"
              + "    private static class C {\n"
              + "        static String pick() {\n"
              + "            return \"safe\";\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_folded_ternary_const", "xss", "CWE-79",
        "conduit_folded_ternary_const", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p) {\n"
              + "            int n = 42;\n"
              + "            return (7 * 42) - n > 200 ? \"safe\" : p;\n"
              + "        }\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_param_sanitized", "xss", "CWE-79",
        "conduit_param_sanitized_transparency", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String clean = Encode.forHtml(x);\n"
              + "        String bar = new W().pass(clean);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pass(String p) {\n"
              + "            return p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_join_sanitized", "xss", "CWE-79",
        "conduit_join_sanitized_param", LABEL_MAY_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String clean = Encode.forHtml(x);\n"
              + "        String bar = new W().pick(clean, mode);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p, int m) {\n"
              + "            return m > 0 ? \"safe\" : p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_const_literal_arg", "xss", "CWE-79",
        "conduit_param_constant_argument", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pass(\"hello\");\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pass(String p) {\n"
              + "            return p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))

    # ---- must-not-suppress: transparency honesty + refusals ----
    j.append(_marked(
        "java_conduit_tainted_passthrough", "xss", "CWE-79",
        "conduit_tainted_passthrough", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pass(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pass(String p) {\n"
              + "            return p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_join_tainted", "xss", "CWE-79",
        "conduit_join_tainted_param", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String bar = new W().pick(x, mode);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p, int m) {\n"
              + "            return m > 0 ? \"safe\" : p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_transform_concat", "xss", "CWE-79",
        "conduit_param_transformed_concat", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pass(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pass(String p) {\n"
              + "            return \"pre\" + p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_transform_call", "xss", "CWE-79",
        "conduit_param_transformed_call", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pass(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pass(String p) {\n"
              + "            return p.trim();\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_unfoldable_tainted", "xss", "CWE-79",
        "conduit_unfoldable_cond_tainted_param", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String bar = new W().pick(x, mode);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p, int m) {\n"
              + "            return m > 0 ? \"<b>ok</b>\" : p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_multireturn", "xss", "CWE-79",
        "conduit_multi_return_refusal", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p) {\n"
              + "            if (p.isEmpty()) { return \"a\"; }\n"
              + "            return p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_recursion", "xss", "CWE-79",
        "conduit_recursion_refusal", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p) {\n"
              + "            return pick(p);\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_two_param_join", "xss", "CWE-79",
        "conduit_two_param_join_refusal", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, String other, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String bar = new W().pick(x, other, mode);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p, String q, int m) {\n"
              + "            return m > 0 ? q : p;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_anon_subclass", "xss", "CWE-79",
        "conduit_anonymous_subclass_refusal", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W() {\n"
              + "            public String pick(String p) {"
              " return p + \"!\"; }\n"
              + "        }.pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private static class W {\n"
              + "        public String pick(String p) {\n"
              + "            return \"safe\";\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    # ---- the Benchmark's REAL body shapes (declare-uninitialized +
    # reassign; unbraced if/else arms) — measured live as the dominant
    # conduit population; the ternary-only grammar missed all of them.
    j.append(_marked(
        "java_conduit_reassign_folded_const", "xss", "CWE-79",
        "conduit_declare_reassign_folded_const", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p) {\n"
              + "            String bar;\n"
              + "            int num = 106;\n"
              + "            return_helper: ;\n"
              + "            bar = (7 * 18) + num > 200 ?"
              " \"always\" : p;\n"
              + "            return bar;\n        }\n"
              + "    }\n").replace("            return_helper: ;\n", ""),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_ifelse_folded_const", "xss", "CWE-79",
        "conduit_ifelse_folded_const", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p) {\n"
              + "            String bar;\n"
              + "            int num = 86;\n"
              + "            if ((7 * 42) - num > 200) bar = \"always\";\n"
              + "            else bar = p;\n"
              + "            return bar;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_ifelse_join_sanitized", "xss", "CWE-79",
        "conduit_ifelse_join_sanitized_param", LABEL_MAY_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String clean = Encode.forHtml(x);\n"
              + "        String bar = new W().pick(clean, mode);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p, int m) {\n"
              + "            String bar;\n"
              + "            if (m > 0) bar = \"safe\";\n"
              + "            else bar = p;\n"
              + "            return bar;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_ifelse_join_tainted", "xss", "CWE-79",
        "conduit_ifelse_join_tainted_param", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String bar = new W().pick(x, mode);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p, int m) {\n"
              + "            String bar;\n"
              + "            if (m > 0) bar = \"safe\";\n"
              + "            else bar = p;\n"
              + "            return bar;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_partial_if_unassigned", "xss", "CWE-79",
        "conduit_partial_if_unassigned_refusal", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = new W().pick(x);\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick(String p) {\n"
              + "            String bar;\n"
              + "            if (p.isEmpty()) bar = \"safe\";\n"
              + "            return bar;\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_conduit_mixed_defs", "xss", "CWE-79",
        "conduit_mixed_tainted_def", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out, int mode) {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String bar;\n"
              + "        if (mode > 0) {\n"
              + "            bar = new W().pick();\n"
              + "        } else {\n"
              + "            bar = x;\n"
              + "        }\n"
              + "        out.println(bar);\n    }\n"
              + "    private class W {\n"
              + "        public String pick() {\n"
              + "            return \"safe\";\n        }\n"
              + "    }\n"),
        "public void handle", "out.println(bar)"))
    return j


def _java_b42_fixtures() -> list[CutFixture]:
    """b42 battery: the taint-free definer union and returns-taint-free
    helper summaries — the measured blocker classes behind the
    "guard-shaped" census labels (which sampling proved are NOT value
    validators: selection guards pick WHICH tainted value flows, and
    the flow-variant merges disagree on attacker-free values).  The
    four hypothesized value-predicate guard classes (equality /
    prefix / contains / matches on the VALUE) were deliberately NOT
    built: zero population in three corpus samples (Juliet goodB2G,
    OWASP replace_strip, OWASP unclassified); the selection-guard trap
    below is the standing pin for that refusal."""
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) throws Exception {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    fx = []
    # must NOT suppress -------------------------------------------------
    # The trap that motivated refusing the value-predicate classes: a
    # name-equality guard selects WHICH attacker value is read; the
    # value itself stays fully tainted.
    fx.append(_fx(
        "java_b42_selection_guard_trap", "pathtrav", "CWE-22",
        "name_selection_guard_on_tainted_value", LABEL_MUST_NOT_SUPPRESS,
        body('String param = "";',
             'javax.servlet.http.Cookie[] cs = request.getCookies();',
             'for (javax.servlet.http.Cookie c : cs) {',
             '    if (c.getName().equals("target")) {',
             '        param = c.getValue();',
             '    }',
             '}',
             'new java.io.FileInputStream(param);'),
        5, 8, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_union_mixed_taint", "pathtrav", "CWE-22",
        "definer_union_with_tainted_branch", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String data;',
             'if (param.length() > 2) {',
             '    data = param;',
             '} else {',
             '    data = "foo";',
             '}',
             'new java.io.FileInputStream(data);'),
        4, 11, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_param_branch", "cmdi", "CWE-78",
        "helper_returns_parameter_branch", LABEL_MUST_NOT_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private boolean flag = false;\n"
         "    private String pick(String p) {\n"
         "        if (flag) { return p; }\n"
         "        return \"x\";\n"
         "    }\n"
         "    public void handle(HttpServletRequest request) "
         "throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        String data = pick(param);\n"
         "        Runtime.getRuntime().exec(data);\n"
         "    }\n}\n"),
        9, 11, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_field_value", "pathtrav", "CWE-22",
        "helper_returns_field_value", LABEL_MUST_NOT_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private boolean flag = false;\n"
         "    private String stash = \"d\";\n"
         "    private String src() {\n"
         "        String d;\n"
         "        if (flag) { d = stash; } else { d = \"foo\"; }\n"
         "        return d;\n"
         "    }\n"
         "    public void handle(HttpServletRequest request) "
         "throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        String data = src();\n"
         "        new java.io.FileInputStream(data);\n"
         "    }\n}\n"),
        11, 13, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_unknown_call", "pathtrav", "CWE-22",
        "helper_returns_unknown_call", LABEL_MUST_NOT_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private boolean flag = false;\n"
         "    private String src() {\n"
         "        String d;\n"
         "        if (flag) { d = System.console().readLine(); }\n"
         "        else { d = \"foo\"; }\n"
         "        return d;\n"
         "    }\n"
         "    public void handle(HttpServletRequest request) "
         "throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        String data = src();\n"
         "        new java.io.FileInputStream(data);\n"
         "    }\n}\n"),
        11, 13, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_compound_write", "pathtrav", "CWE-22",
        "helper_compound_assignment_poisons", LABEL_MUST_NOT_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private String src(String p) {\n"
         "        String d = \"foo\";\n"
         "        d += p;\n"
         "        return d;\n"
         "    }\n"
         "    public void handle(HttpServletRequest request) "
         "throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        String data = src(param);\n"
         "        new java.io.FileInputStream(data);\n"
         "    }\n}\n"),
        9, 11, language="java", suffix=".java"))
    # The union sentinel must never act as a value: a disagreeing
    # discriminant must not prune the switch, so the tainted default
    # arm keeps its definer and the finding stays live.
    fx.append(_fx(
        "java_b42_union_value_position_trap", "pathtrav", "CWE-22",
        "union_never_prunes_value_consumers", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String s;',
             'if (param.length() > 2) { s = "a"; } else { s = "b"; }',
             'String bar;',
             'switch (s) {',
             '    case "a": bar = "safe"; break;',
             '    default: bar = param; break;',
             '}',
             'new java.io.FileInputStream(bar);'),
        4, 12, language="java", suffix=".java"))
    # may suppress -------------------------------------------------------
    fx.append(_fx(
        "java_b42_union_null_const", "pathtrav", "CWE-22",
        "definer_union_null_and_constant", LABEL_MAY_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String data;',
             'if (param.length() > 2) {',
             '    data = null;',
             '} else {',
             '    data = "foo";',
             '}',
             'new java.io.FileInputStream(data);'),
        4, 11, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_union_two_consts", "cmdi", "CWE-78",
        "definer_union_two_constants", LABEL_MAY_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String data;',
             'if (param.length() > 2) { data = "ls"; }',
             'else { data = "pwd"; }',
             'Runtime.getRuntime().exec(data);'),
        4, 8, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_tf_union", "pathtrav", "CWE-22",
        "helper_all_branches_literal", LABEL_MAY_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private boolean flag = false;\n"
         "    private String src() {\n"
         "        String d;\n"
         "        if (flag) { d = null; } else { d = \"foo\"; }\n"
         "        return d;\n"
         "    }\n"
         "    public void handle(HttpServletRequest request) "
         "throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        String data = src();\n"
         "        new java.io.FileInputStream(data);\n"
         "    }\n}\n"),
        10, 12, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_union_tf_and_const", "pathtrav", "CWE-22",
        # b45 re-pin (threat-model authority, post-b44 stop-ship): the
        # getenv member makes this the Juliet CWE36 Environment shape —
        # environment reads are taint sources, the union must refuse.
        "environment_read_is_source", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String data;',
             'if (param.length() > 2) { data = System.getenv("HOME"); }',
             'else { data = "appdata"; }',
             'new java.io.FileInputStream(data);'),
        4, 8, language="java", suffix=".java"))
    # composed pins (b40 x b42, value discipline): the union and the
    # helper summaries merge VALUE-CARRYING members, and a compile-time
    # constant can violate a value-based finding class on its own — the
    # finite-value-set path's per-element danger check is the shipped
    # bar and the union holds itself to it. A danger-bearing constant
    # member refuses the merge even beside a valueless taint-free
    # member (where the finite-set path could never catch it).
    fx.append(_fx(
        "java_b42_union_danger_member_trap", "xss", "CWE-79",
        "definer_union_danger_bearing_constant", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String data;',
             'if (param.length() > 2) '
             '{ data = System.getProperty("mode"); }',
             'else { data = "<b>x</b>"; }',
             'out.println(data);'),
        4, 8, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_danger_member_trap", "xss", "CWE-79",
        "helper_returns_danger_bearing_constant", LABEL_MUST_NOT_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private boolean flag = false;\n"
         "    private String src() {\n"
         "        String d;\n"
         "        if (flag) { d = null; } else { d = \"<b>x</b>\"; }\n"
         "        return d;\n"
         "    }\n"
         "    public void handle(HttpServletRequest request, "
         "java.io.PrintWriter out) throws Exception {\n"
         "        String param = request.getParameter(\"q\");\n"
         "        String data = src();\n"
         "        out.println(data);\n"
         "    }\n}\n"),
        10, 12, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_helper_clear_member_union", "xss", "CWE-79",
        "helper_union_members_clear_danger", LABEL_MAY_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    private boolean flag = false;\n"
         "    private String src() {\n"
         "        String d;\n"
         "        if (flag) { d = null; } else { d = \"plain\"; }\n"
         "        return d;\n"
         "    }\n"
         "    public void handle(HttpServletRequest request, "
         "java.io.PrintWriter out) throws Exception {\n"
         "        String param = request.getParameter(\"q\");\n"
         "        String data = src();\n"
         "        out.println(data);\n"
         "    }\n}\n"),
        10, 12, language="java", suffix=".java"))
    # composed pins (b40 x b42): the if-pruning refiner and the definer
    # union meet on the same definer set. May-direction: the refiner
    # removes a provably-dead tainted arm, the union claims ONLY the
    # surviving attacker-free definers. Trap-direction: an unfoldable
    # condition keeps the tainted definer live and the union must read
    # the set as mixed — pruning power must never leak into the union
    # through anything but an actually-pruned edge.
    fx.append(_fx(
        "java_b42_pruned_taint_then_union", "xss", "CWE-79",
        "if_pruned_dead_taint_then_definer_union", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = null;',
             'if (param.length() > 3) { bar = "safe"; }',
             'if ((7 * 42) - num > 200) { bar = param; }',
             'out.println(bar);'),
        4, 9, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_unpruned_taint_union_trap", "xss", "CWE-79",
        "unfoldable_if_keeps_taint_union_mixed", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = null;',
             'if (param.length() > 3) { bar = "safe"; }',
             'if (param.length() > 5) { bar = param; }',
             'out.println(bar);'),
        4, 8, language="java", suffix=".java"))
    # composed pins (b41 x b42): the vertex-cut sibling guard folds
    # sibling arguments through definers_all_fold, whose NESTED
    # resolution now carries the union. May-direction: a sibling built
    # from a union-of-constants local folds taint-free and the
    # catalog-sanitized pick suppresses. Trap-direction: one union arm
    # is the raw parameter — the sibling must refuse (downgrade to
    # candidate_only), never suppress.
    sib_hdr = ("import org.owasp.encoder.Encode;\n"
               "import javax.servlet.http.HttpServletRequest;\n"
               "public class T {\n"
               "    public void handle(HttpServletRequest request, "
               "java.io.PrintWriter out) {\n")
    fx.append(_fx(
        "java_b42_sibling_union_tf", "xss", "CWE-79",
        "sibling_folds_via_definer_union", LABEL_MAY_SUPPRESS,
        (sib_hdr
         + '        String x = request.getParameter("q");\n'
         + '        String bar = Encode.forHtml(x);\n'
         + '        String q;\n'
         + '        if (x.length() > 3) { q = "A"; }\n'
         + '        else { q = "B"; }\n'
         + '        String pre = q + ":";\n'
         + '        out.println(pre + bar);\n'
         + "    }\n}\n"),
        5, 11, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b42_sibling_mixed_union_trap", "xss", "CWE-79",
        "sibling_union_arm_tainted", LABEL_MUST_NOT_SUPPRESS,
        (sib_hdr
         + '        String x = request.getParameter("q");\n'
         + '        String bar = Encode.forHtml(x);\n'
         + '        String q;\n'
         + '        if (x.length() > 3) { q = x; }\n'
         + '        else { q = "B"; }\n'
         + '        String pre = q + ":";\n'
         + '        out.println(pre + bar);\n'
         + "    }\n}\n"),
        5, 11, language="java", suffix=".java"))
    return fx


def _java_b36_fixtures() -> list[CutFixture]:
    """b36 battery (merged onto b37's machinery): the JDK-class tier
    and statement-scoped sibling coverage. Deduped against the b37
    battery — non-final, ambiguous-class, static-final-concat,
    taint-free-static-final, and prefix-trap shapes are pinned THERE;
    kept here are only the shapes b37 does not exercise."""
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) throws Exception {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    fx = []
    # must NOT suppress -------------------------------------------------
    fx.append(_fx(
        "java_b36_jdk_char_switch_value", "pathtrav", "CWE-22",
        "jdk_sentinel_in_value_position", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String bar;',
             'char c = java.io.File.separatorChar;',
             'switch (c) {',
             "    case '/': bar = \"safe\"; break;",
             '    default: bar = param; break;',
             '}',
             'new java.io.FileInputStream(bar);'),
        4, 11, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b36_instance_field_chain", "pathtrav", "CWE-22",
        "instance_field_via_local", LABEL_MUST_NOT_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    static class H { String dir = \"d\"; }\n"
         "    public void handle(HttpServletRequest request, "
         "java.io.PrintWriter out) throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        H h = new H();\n"
         "        String f = h.dir + param;\n"
         "        new java.io.FileInputStream(f);\n"
         "    }\n}\n"),
        5, 8, language="java", suffix=".java"))
    # may suppress -------------------------------------------------------
    fx.append(_fx(
        "java_b36_prepcall_jdk_const_siblings", "sqli", "CWE-89",
        "jdk_constant_siblings_multiline_call", LABEL_MAY_SUPPRESS,
        ("import javax.servlet.http.HttpServletRequest;\n"
         "public class T {\n"
         "    public void handle(HttpServletRequest request, "
         "java.io.PrintWriter out) throws Exception {\n"
         "        String param = request.getHeader(\"X\");\n"
         "        String bar = \"bob\";\n"
         "        String sql = \"{call \" + bar + \"}\";\n"
         "        java.sql.Connection con = getC();\n"
         "        con.prepareCall(sql,\n"
         "                java.sql.ResultSet.TYPE_FORWARD_ONLY,\n"
         "                java.sql.ResultSet.CONCUR_READ_ONLY);\n"
         "    }\n"
         "    java.sql.Connection getC() { return null; }\n"
         "}\n"),
        4, 6, language="java", suffix=".java"))
    fx.append(_fx(
        "java_b36_jdk_locale_sibling", "xss", "CWE-79",
        "jdk_locale_printf_sibling", LABEL_MAY_SUPPRESS,
        body('String param = request.getHeader("X");',
             'String bar = "bob";',
             'out.printf(java.util.Locale.US, "%s", bar);'),
        4, 6, language="java", suffix=".java"))
    return fx


def _java_b37_fixtures() -> list[CutFixture]:
    """b37 battery: cross-file static-final / returns-literal
    resolution and the taint-free tier. The prefix trap is the
    load-bearing must-not: a constant or taint-free directory prefix
    concatenated with attacker data does NOT neutralise traversal
    (``../`` escapes any prefix), so const+tainted must never read as
    suppressible."""
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    cfg_aux = (
        "public class Cfg {\n"
        '    public static final String SAFE = "safe-const";\n'
        '    public static String MUTABLE = "reassignable";\n'
        '    public String getTheValue(String p) { return "bar"; }\n'
        '    public String echo(String p) { return p; }\n'
        "}\n"
    )
    tf_aux = (
        "import java.io.File;\n"
        "public class Env {\n"
        "    public static final String USERDIR = "
        'System.getProperty("user.dir") + File.separator;\n'
        "}\n"
    )
    j: list[CutFixture] = []
    j.append(_fx(
        "java_b37_xfile_static_final", "xss", "CWE-79",
        "xfile_static_final_const", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = Cfg.SAFE;',
             'out.println(bar);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Cfg.java": cfg_aux}, use_repo_root=True))
    j.append(_fx(
        "java_b37_xfile_returns_literal", "xss", "CWE-79",
        "xfile_returns_literal_method", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'Cfg scr = new Cfg();',
             'String bar = scr.getTheValue("k");',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java",
        aux_files={"Cfg.java": cfg_aux}, use_repo_root=True))
    # b45 re-pin (threat-model authority, post-b44 stop-ship):
    # environment reads are taint sources under threat-model local —
    # a getProperty-fed sink must never suppress, write proof or not.
    j.append(_fx(
        "java_b37_tf_system_read", "xss", "CWE-79",
        "environment_read_is_source", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String dir = System.getProperty("user.dir");',
             'out.println(dir);'),
        4, 6, language="java", suffix=".java", use_repo_root=True))
    j.append(_fx(
        "java_b37_tf_prop_no_root", "xss", "CWE-79",
        "property_read_without_write_proof_refusal_pin",
        LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String dir = System.getProperty("user.dir");',
             'out.println(dir);'),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_b37_tf_prop_written_key", "xss", "CWE-79",
        "property_key_runtime_written", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String dir = System.getProperty("user.dir");',
             'out.println(dir);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Writer.java": (
            "public class Writer {\n"
            "    void w(String t) { "
            'System.setProperty("user.dir", t); }\n'
            "}\n")}, use_repo_root=True))
    j.append(_fx(
        "java_b37_tf_prop_variable_key_poison", "xss", "CWE-79",
        "property_variable_key_poisons_all", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String dir = System.getProperty("user.dir");',
             'out.println(dir);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Writer.java": (
            "public class Writer {\n"
            "    void w(String k, String t) { "
            "System.setProperty(k, t); }\n"
            "}\n")}, use_repo_root=True))
    # b45 re-pin: a static final initialized from an environment
    # read is environment-influenced — never taint-free (b44 class).
    j.append(_fx(
        "java_b37_tf_static_final", "xss", "CWE-79",
        "environment_derived_static_final", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = Env.USERDIR;',
             'out.println(bar);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Env.java": tf_aux}, use_repo_root=True))
    # ---- b45: environment-taint battery (the b44 counterexample
    # shapes — the corpus class whose absence made the threat-model
    # contradiction structurally invisible until Juliet first contact).
    j.append(_fx(
        "java_b45_env_getenv_file_sink", "pathtrav", "CWE-22",
        "environment_getenv_to_file_sink", LABEL_MUST_NOT_SUPPRESS,
        body('String data = System.getenv("ADD");',
             'java.io.File f = new java.io.File(data);'),
        4, 5, language="java", suffix=".java", use_repo_root=True))
    j.append(_fx(
        "java_b45_env_getenv_xss_sink", "xss", "CWE-79",
        "environment_getenv_to_xss_sink", LABEL_MUST_NOT_SUPPRESS,
        body('String data = System.getenv("ADD");',
             'out.println(data);'),
        4, 5, language="java", suffix=".java", use_repo_root=True))
    j.append(_fx(
        "java_b45_env_getprop_cmdi_sink", "cmdi", "CWE-78",
        "environment_getproperty_to_exec_sink", LABEL_MUST_NOT_SUPPRESS,
        body('String data = System.getProperty("cmd.path");',
             'Runtime.getRuntime().exec(data);'),
        4, 5, language="java", suffix=".java", use_repo_root=True))
    j.append(_fx(
        "java_b37_prefix_trap", "pathtrav", "CWE-22",
        "constant_prefix_tainted_suffix", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String path = Env.USERDIR + param;',
             'java.io.File f = new java.io.File(path);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Env.java": tf_aux}, use_repo_root=True))
    j.append(_fx(
        "java_b37_xfile_non_final", "xss", "CWE-79",
        "xfile_non_final_field", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = Cfg.MUTABLE;',
             'out.println(param + bar);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Cfg.java": cfg_aux}, use_repo_root=True))
    j.append(_fx(
        "java_b37_returns_param_lookalike", "xss", "CWE-79",
        "xfile_returns_param_method", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'Cfg scr = new Cfg();',
             'String bar = scr.echo(param);',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java",
        aux_files={"Cfg.java": cfg_aux}, use_repo_root=True))
    j.append(_fx(
        "java_b37_tf_variable_prop_name", "xss", "CWE-79",
        "variable_property_name", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String v = System.getProperty(param);',
             'out.println(v);'),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_b37_overloaded_method_refusal_pin", "xss", "CWE-79",
        "xfile_overloaded_method_refusal_pin", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = new Ovl().pick("k");',
             'out.println(bar);'),
        4, 6, language="java", suffix=".java",
        aux_files={"Ovl.java": (
            "public class Ovl {\n"
            '    public String pick(String p) { return "a"; }\n'
            '    public String pick(int p) { return "b"; }\n'
            "}\n")}, use_repo_root=True))
    j.append(_fx(
        "java_b37_ambiguous_class_refusal_pin", "xss", "CWE-79",
        "xfile_ambiguous_class_refusal_pin", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = Amb.SAFE;',
             'out.println(bar);'),
        4, 6, language="java", suffix=".java",
        aux_files={
            "a/Amb.java": (
                "public class Amb {\n"
                '    public static final String SAFE = "one";\n}\n'),
            "b/Amb.java": (
                "public class Amb {\n"
                '    public static final String SAFE = "two";\n}\n'),
        }, use_repo_root=True))
    return j


def measure_fixture(fx: CutFixture, work_dir: Path) -> FixtureMeasurement:
    """Run the production gate path over one fixture."""
    from core.dataflow.sanitizer_cut_parity import value_bound_verdict_for

    root = work_dir / fx.name if fx.use_repo_root else work_dir
    root.mkdir(parents=True, exist_ok=True)
    path = root / f"{fx.name}{fx.suffix}"
    path.write_text(fx.source, encoding="utf-8")
    for rel, content in fx.aux_files.items():
        aux = root / rel
        aux.parent.mkdir(parents=True, exist_ok=True)
        aux.write_text(content, encoding="utf-8")
    finding = {
        "cwe": fx.cwe,
        "file_path": str(path),
        "source_line": fx.source_line,
        "sink_line": fx.sink_line,
        "language": fx.language,
    }
    if fx.use_repo_root:
        finding["repo_root"] = str(root)
    verdict = value_bound_verdict_for(finding)
    return FixtureMeasurement(
        name=fx.name, sink_class=fx.sink_class, shape=fx.shape,
        label=fx.label, verdict=verdict,
    )


def _toolchain() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
    }


def _java_constant_fixtures() -> list[CutFixture]:
    """Constant-definers battery: the dead-branch ternary trick may
    suppress; every variation that breaks the constancy proof — a
    live condition, the fold selecting the tainted branch, a compound
    writer, an incidental-constant sibling argument (the sink-arg
    inversion trap), and an array-element rebind — must not.
    """
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    j = []
    j.append(_fx(
        "java_const_dead_branch_ternary", "xss", "CWE-79",
        "constant_dead_branch", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = (7 * 18) + num > 200 ? "safe" : param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_live_condition", "xss", "CWE-79",
        "constant_live_condition", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = request.getIntHeader("n");',
             'String bar = (7 * 18) + num > 200 ? "safe" : param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_fold_selects_tainted", "xss", "CWE-79",
        "constant_false_ternary", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'int num = 106;',
             'String bar = (7 * 18) + num > 2000 ? "safe" : param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_compound_writer", "xss", "CWE-79",
        "constant_compound_writer", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = "safe";',
             'bar += param;',
             'out.println(bar);'),
        4, 7, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_sibling_arg_inversion", "xss", "CWE-79",
        "constant_sibling_inversion", LABEL_MUST_NOT_SUPPRESS,
        body('String zz = request.getParameter("q");',
             'String aa = "constant";',
             'out.printf(aa, zz);'),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_multiple_agreeing_defs", "xss", "CWE-79",
        "constant_agreeing_defs", LABEL_MAY_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.length() > 3) { bar = "safe"; }',
             'else { bar = "safe"; }',
             'out.println(bar);'),
        4, 8, language="java", suffix=".java"))
    j.append(_fx(
        "java_const_disagreeing_defs", "xss", "CWE-79",
        "constant_disagreeing_defs", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar;',
             'if (param.length() > 3) { bar = "safe"; }',
             'else { bar = param; }',
             'out.println(bar);'),
        4, 8, language="java", suffix=".java"))
    return j


def _java_config_fixtures() -> list[CutFixture]:
    """Config-resolution battery: a value read from a bundled
    .properties file through the strict resolver may fold to a
    constant (and suppress via the constant-definers gate); every
    shape that weakens the proof — ambiguous files, a call-site
    default (two possible runtime values, one possibly tainted), a
    System.getProperty receiver, an attacker-chosen key, an escaping
    receiver, a missing key — must not. Each fixture uses a unique
    .properties basename: the harness shares one work dir.
    """
    hdr = ("import javax.servlet.http.HttpServletRequest;\n"
           "public class T {\n"
           "    public void handle(HttpServletRequest request, "
           "java.io.PrintWriter out) {\n")
    end = "    }\n}\n"

    def body(*lines: str) -> str:
        return hdr + "".join(f"        {ln}\n" for ln in lines) + end

    def props_lines(basename: str,
                    getter: str = 'props.getProperty("alg")'):
        return [
            'String param = request.getParameter("q");',
            'java.util.Properties props = new java.util.Properties();',
            'props.load(getClass().getClassLoader()'
            f'.getResourceAsStream("{basename}"));',
            f'String bar = {getter};',
            'out.println(bar);',
        ]

    j = []
    j.append(_fx(
        "java_config_safe_value", "xss", "CWE-79",
        "config_resolved_constant", LABEL_MAY_SUPPRESS,
        body(*props_lines("cfg_safe.properties")),
        4, 8, language="java", suffix=".java",
        aux_files={"cfg_safe.properties": "alg=SHA-256\n"}))
    j.append(_fx(
        "java_config_two_files_ambiguous", "xss", "CWE-79",
        "config_two_files", LABEL_MUST_NOT_SUPPRESS,
        body(*props_lines("cfg_ambig.properties")),
        4, 8, language="java", suffix=".java",
        aux_files={"cfg_ambig.properties": "alg=SHA-256\n",
                   "conf/cfg_ambig.properties": "alg=MD5\n"}))
    j.append(_fx(
        "java_config_tainted_default", "xss", "CWE-79",
        "config_tainted_default", LABEL_MUST_NOT_SUPPRESS,
        body(*props_lines(
            "cfg_dflt.properties",
            getter='props.getProperty("alg", param)')),
        4, 8, language="java", suffix=".java",
        aux_files={"cfg_dflt.properties": "alg=SHA-256\n"}))
    j.append(_fx(
        "java_config_literal_default", "xss", "CWE-79",
        "config_literal_default", LABEL_MUST_NOT_SUPPRESS,
        body(*props_lines(
            "cfg_dflt2.properties",
            getter='props.getProperty("alg", "MD5")')),
        4, 8, language="java", suffix=".java",
        aux_files={"cfg_dflt2.properties": "alg=SHA-256\n"}))
    j.append(_fx(
        "java_config_system_receiver", "xss", "CWE-79",
        "config_system_receiver", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'String bar = System.getProperty("alg");',
             'out.println(bar);'),
        4, 6, language="java", suffix=".java"))
    j.append(_fx(
        "java_config_dynamic_key", "xss", "CWE-79",
        "config_dynamic_key", LABEL_MUST_NOT_SUPPRESS,
        body(*props_lines(
            "cfg_dyn.properties",
            getter='props.getProperty(param)')),
        4, 8, language="java", suffix=".java",
        aux_files={"cfg_dyn.properties": "alg=SHA-256\n"}))
    j.append(_fx(
        "java_config_receiver_escapes", "xss", "CWE-79",
        "config_receiver_escapes", LABEL_MUST_NOT_SUPPRESS,
        body('String param = request.getParameter("q");',
             'java.util.Properties props = new java.util.Properties();',
             'props.load(getClass().getClassLoader()'
             '.getResourceAsStream("cfg_esc.properties"));',
             'reload(props);',
             'String bar = props.getProperty("alg");',
             'out.println(bar);'),
        4, 9, language="java", suffix=".java",
        aux_files={"cfg_esc.properties": "alg=SHA-256\n"}))
    j.append(_fx(
        "java_config_key_missing", "xss", "CWE-79",
        "config_key_missing", LABEL_MUST_NOT_SUPPRESS,
        body(*props_lines("cfg_miss.properties")),
        4, 8, language="java", suffix=".java",
        aux_files={"cfg_miss.properties": "other=SHA-256\n"}))
    return j


def run_corpus(fixtures: list[CutFixture] | None = None,
               corpus_name: str = "adversarial-v1") -> PrecisionReport:
    fixtures = fixtures if fixtures is not None else build_corpus()
    report = PrecisionReport(
        corpus_name=corpus_name,
        n_fixtures=len(fixtures),
        toolchain=_toolchain(),
    )
    with tempfile.TemporaryDirectory(
            prefix="sanitizer-cut-precision-") as tmp:
        work = Path(tmp)
        for fx in fixtures:
            m = measure_fixture(fx, work)
            report.measurements.append(m)
            report.verdict_counts[m.verdict] = (
                report.verdict_counts.get(m.verdict, 0) + 1)
            cls = report.cross_tab.setdefault(m.sink_class, {})
            lbl = cls.setdefault(m.label, {})
            lbl[m.verdict] = lbl.get(m.verdict, 0) + 1
            if m.label == LABEL_MUST_NOT_SUPPRESS:
                report.n_must_not += 1
            if m.false_suppress:
                report.false_suppressions.append(m.name)
            if m.missed_suppress:
                report.missed_suppressions.append(m.name)
    if not report.false_suppressions and report.n_must_not:
        report.rule_of_three_95_ub = 3.0 / report.n_must_not
    return report


def _format_markdown(report: PrecisionReport) -> str:
    lines = [
        "# Sanitizer-cut precision report",
        "",
        f"- corpus: {report.corpus_name}",
        f"- fixtures: {report.n_fixtures} "
        f"({report.n_must_not} must-not-suppress)",
        f"- verdicts: {dumps_display(report.verdict_counts, indent=None, sort_keys=True)}",
        "- toolchain: "
        + ", ".join(f"{k}={v}" for k, v in sorted(report.toolchain.items())),
        "",
    ]
    if report.false_suppressions:
        lines.append(
            f"## GATE FAILED — {len(report.false_suppressions)} "
            "false suppression(s)")
        lines.extend(f"- {name}" for name in report.false_suppressions)
    else:
        lines.append("## Gate clean — zero false suppressions")
        if report.rule_of_three_95_ub is not None:
            lines.append(
                f"- rule-of-three 95% UB on the false-suppress rate: "
                f"{report.rule_of_three_95_ub:.3f} "
                f"(3/{report.n_must_not})")
        lines.append(
            "- NOTE: a clean run is necessary, not sufficient — flipping "
            "``sanitizer_dominated`` to earns_suppression is a reviewed "
            "change that must record this report.")
    lines.append("")
    if report.missed_suppressions:
        lines.append(
            f"## Missed suppressions (utility, not a gate failure): "
            f"{len(report.missed_suppressions)}")
        lines.extend(f"- {name}" for name in report.missed_suppressions)
        lines.append("")
    lines.append("## Per-class cross-tab (label × verdict)")
    for cls in sorted(report.cross_tab):
        lines.append(f"### {cls}")
        for lbl in sorted(report.cross_tab[cls]):
            row = dumps_display(report.cross_tab[cls][lbl], indent=None, sort_keys=True)
            lines.append(f"- {lbl}: {row}")
    lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raptor-sanitizer-cut-precision",
        description=(
            "Measure the sanitizer-cut value-bound gate against the "
            "labelled adversarial corpus. The gate metric is false "
            "suppressions: any must-not-suppress fixture receiving the "
            "suppress verdict fails the run (exit 1). A clean run is "
            "the precondition for the sanitizer_dominated witness ever "
            "earning hard-suppression."
        ),
    )
    p.add_argument("--out", type=Path, default=None,
                   help=("output dir (default: "
                         "out/sanitizer-cut-precision/runs/<ts>)"))
    args = p.parse_args(argv)

    report = run_corpus()

    out = args.out
    if out is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = Path("out") / "sanitizer-cut-precision" / "runs" / ts
    out.mkdir(parents=True, exist_ok=True)
    (out / "report.json").write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8")
    md = _format_markdown(report)
    (out / "report.md").write_text(md, encoding="utf-8")
    sys.stdout.write(md)
    sys.stdout.write(f"\nreports written to {out}\n")
    return 1 if report.false_suppressions else 0


__all__ = [
    "LABEL_MAY_SUPPRESS",
    "LABEL_MUST_NOT_SUPPRESS",
    "CutFixture",
    "FixtureMeasurement",
    "PrecisionReport",
    "build_corpus",
    "main",
    "measure_fixture",
    "run_corpus",
]


def _java_b28_collection_fixtures() -> list[CutFixture]:
    """b28 battery: local map/list round-trips. Adversarial shapes
    first — a keyed store is exactly where key confusion, ordering
    assumptions, or escape blindness would false-suppress, so every
    such shape is pinned before the two safe idioms the mechanism
    exists for (the OWASP-style constant-key read and the
    sanitizer-written key read)."""
    imp = ("import java.util.HashMap;\n"
           "import java.util.Hashtable;\n"
           "import java.util.ArrayList;\n"
           "import org.owasp.encoder.Encode;\n"
           "import javax.servlet.http.HttpServletRequest;\n")

    def cls_t(body: str) -> str:
        return imp + "public class T {\n" + body + "}\n"

    handle = ("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) {\n"
              "        String x = request.getParameter(\"q\");\n")
    j: list[CutFixture] = []

    # ---- must-not-suppress: adversarial shapes ----
    j.append(_marked(
        "java_coll_tainted_put_key", "xss", "CWE-79",
        "coll_tainted_write_on_read_key", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"keyA\", \"a-Value\");\n"
              + "        m.put(\"keyB\", x);\n"
              + "        String bar = (String) m.get(\"keyB\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_concat_after_read", "xss", "CWE-79",
        "coll_const_read_concat_taint", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", \"safe\");\n"
              + "        String bar = ((String) m.get(\"k\")) + x;\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_nonconst_key_poison", "xss", "CWE-79",
        "coll_nonconstant_key_poisons_all", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", Encode.forHtml(x));\n"
              + "        m.put(x, x);\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_aliased_map", "xss", "CWE-79",
        "coll_alias_untracks", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", Encode.forHtml(x));\n"
              + "        java.util.Map<String, Object> m2 = m;\n"
              + "        m2.put(\"k\", x);\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_get_never_put", "xss", "CWE-79",
        "coll_read_of_unwritten_key", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"a\", Encode.forHtml(x));\n"
              + "        String bar = (String) m.get(\"b\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_iteration_escape", "xss", "CWE-79",
        "coll_iteration_escape", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, String> m = new HashMap<>();\n"
              + "        m.put(\"k\", Encode.forHtml(x));\n"
              + "        for (String v : m.values()) { x = v; }\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_helper_returned", "xss", "CWE-79",
        "coll_helper_returned_untracked", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = makeMap(x);\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"
              + "    private HashMap<String, Object> makeMap(String v) {\n"
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", v);\n"
              + "        return m;\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_remove_untracks", "xss", "CWE-79",
        "coll_remove_untracks", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", Encode.forHtml(x));\n"
              + "        m.remove(\"k\");\n"
              + "        m.put(\"k\", x);\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_list_mixed_adds", "xss", "CWE-79",
        # Graduated by b34's positional simulation (b21 precedent):
        # get(0) provably reads the sanitized element in straight-line
        # code — b28's must-not label encoded its one-synthetic-key
        # model's limitation, not a hazard. The inverse twin below
        # (get(1) reads the tainted slot) is the standing pin.
        "list_positional_sanitized_slot", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<>();\n"
              + "        l.add(Encode.forHtml(x));\n"
              + "        l.add(x);\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_list_mixed_adds_tainted_slot", "xss", "CWE-79",
        "list_positional_tainted_slot", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<>();\n"
              + "        l.add(Encode.forHtml(x));\n"
              + "        l.add(x);\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_putall_untracks", "xss", "CWE-79",
        "coll_putall_imports_state", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        HashMap<String, Object> o = new HashMap<>();\n"
              + "        o.put(\"k\", x);\n"
              + "        m.put(\"k\", Encode.forHtml(x));\n"
              + "        m.putAll(o);\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_tainted_sibling_arg", "xss", "CWE-79",
        "coll_sibling_argument_taint", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", \"safe\");\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.printf(bar, x);\n    }\n"),
        "public void handle", "out.printf(bar, x)"))

    # ---- may-suppress: the shapes the mechanism exists for ----
    j.append(_marked(
        "java_coll_const_roundtrip", "xss", "CWE-79",
        "coll_constant_key_roundtrip", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"keyA\", \"a-Value\");\n"
              + "        m.put(\"keyB\", \"safe-const\");\n"
              + "        m.put(\"keyC\", \"another\");\n"
              + "        String bar = (String) m.get(\"keyB\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_sanitizer_roundtrip", "xss", "CWE-79",
        "coll_sanitizer_key_roundtrip", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        HashMap<String, Object> m = new HashMap<>();\n"
              + "        m.put(\"k\", Encode.forHtml(x));\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_coll_hashtable_const", "xss", "CWE-79",
        "coll_hashtable_constant_roundtrip", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        Hashtable<String, Object> m = new Hashtable<>();\n"
              + "        m.put(\"k\", \"const-value\");\n"
              + "        String bar = (String) m.get(\"k\");\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_list_all_sanitizer_adds", "xss", "CWE-79",
        "list_every_add_sanitizer", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<>();\n"
              + "        l.add(Encode.forHtml(x));\n"
              + "        l.add(Encode.forHtml(x));\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    return j


_B33_SAFE_JAVA = (
    "public class T {\n"
    "    public void doPost(HttpServletRequest request) throws Exception {\n"
    "        String param = request.getHeader(\"X\");\n"
    "        String bar = \"safe!\";\n"
    "        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n"
    "        map.put(\"keyA\", \"a_Value\");\n"
    "        map.put(\"keyB\", param);\n"
    "        bar = (String) map.get(\"keyA\");\n"
    "        String sql = \"SELECT * from USERS where USERNAME='\" + bar + \"'\";\n"
    "        java.sql.PreparedStatement statement = connection.prepareStatement(sql);\n"
    "        statement.setString(1, \"foo\");\n"
    "        statement.execute();\n"
    "    }\n"
    "}\n"
)

_B33_DECOY_JAVA = _B33_SAFE_JAVA.replace(
    'bar = (String) map.get(\"keyA\");',
    'bar = (String) map.get(\"keyB\");')


def _java_b33_sink_shape_fixtures() -> list[CutFixture]:
    """b33 battery: assignment-located and zero-argument-receiver sink
    shapes (the OWASP concatenated-sql / execute() finding locations).
    The decoy variants pin that a decoy parameterization (constant
    binds beside a tainted concatenation) never suppresses through the
    forwarded/hopped sink — the classic prepared-statement trap.
    """
    return [
        _fx("sqli_assign_sink_constant_selection_java", "sqli", "CWE-89",
            "assignment_sink_forwarding", LABEL_MAY_SUPPRESS,
            _B33_SAFE_JAVA, 3, 9, language="java", suffix=".java"),
        _fx("sqli_execute_hop_constant_selection_java", "sqli", "CWE-89",
            "receiver_hop_sink", LABEL_MAY_SUPPRESS,
            _B33_SAFE_JAVA, 3, 12, language="java", suffix=".java"),
        _fx("sqli_assign_sink_decoy_parameterized_java", "sqli", "CWE-89",
            "assignment_sink_forwarding", LABEL_MUST_NOT_SUPPRESS,
            _B33_DECOY_JAVA, 3, 9, language="java", suffix=".java"),
        _fx("sqli_execute_hop_decoy_parameterized_java", "sqli", "CWE-89",
            "receiver_hop_sink", LABEL_MUST_NOT_SUPPRESS,
            _B33_DECOY_JAVA, 3, 12, language="java", suffix=".java"),
    ]


def _java_b34_positional_fixtures() -> list[CutFixture]:
    """b34 battery: positional list simulation. The Benchmark's clean
    siblings select a safe element by index after order-shifting ops
    (``remove(0)`` then ``get(1)``); the vulnerable twins read the
    shifted tainted slot (``get(0)``). Adversarial shapes pin every
    refusal: shifted-tainted reads, branch-split ops, non-literal and
    Object-overload removes, out-of-range reads, insert/set shifting
    onto the read slot, loop-carried adds."""
    imp = ("import java.util.ArrayList;\n"
           "import org.owasp.encoder.Encode;\n"
           "import javax.servlet.http.HttpServletRequest;\n")

    def cls_t(body: str) -> str:
        return imp + "public class T {\n" + body + "}\n"

    handle = ("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) {\n"
              "        String x = request.getParameter(\"q\");\n")
    j: list[CutFixture] = []

    # ---- must-not-suppress: adversarial shapes ----
    j.append(_marked(
        "java_pos_remove_shift_tainted", "xss", "CWE-79",
        "pos_remove_shift_tainted_read", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.add(\"moresafe\");\n"
              + "        l.remove(0);\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_branch_split_ops", "xss", "CWE-79",
        "pos_ops_split_across_blocks", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(x);\n"
              + "        if (x != null) {\n"
              + "            l.add(\"safe\");\n"
              + "        }\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_nonliteral_remove", "xss", "CWE-79",
        "pos_nonliteral_remove_index", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        int k = x.length() % 2;\n"
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.remove(k);\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_remove_object_overload", "xss", "CWE-79",
        "pos_remove_object_overload", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.remove(\"safe\");\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_out_of_range_get", "xss", "CWE-79",
        "pos_out_of_range_read", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(x);\n"
              + "        String bar = l.get(3);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_insert_shift_tainted", "xss", "CWE-79",
        "pos_insert_shifts_taint_onto_slot", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(1, x);\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_set_replace_tainted", "xss", "CWE-79",
        "pos_set_replaces_safe_with_taint", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.set(0, x);\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_loop_add", "xss", "CWE-79",
        "pos_loop_carried_adds", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        for (int i = 0; i < 2; i++) {\n"
              + "            l.add(x);\n"
              + "        }\n"
              + "        l.add(\"safe\");\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))

    # ---- may-suppress: the Benchmark clean-sibling shapes ----
    j.append(_marked(
        "java_pos_remove_shift_safe", "xss", "CWE-79",
        "pos_remove_shift_safe_read", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.add(\"moresafe\");\n"
              + "        l.remove(0);\n"
              + "        String bar = l.get(1);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_plain_index_safe", "xss", "CWE-79",
        "pos_plain_safe_index_read", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.add(\"moresafe\");\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_insert_shift_safe", "xss", "CWE-79",
        "pos_insert_shifts_safe_onto_slot", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(x);\n"
              + "        l.add(0, \"safe\");\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    j.append(_marked(
        "java_pos_set_replace_sanitized", "xss", "CWE-79",
        "pos_set_replaces_taint_with_sanitized", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(x);\n"
              + "        l.set(0, Encode.forHtml(x));\n"
              + "        String bar = l.get(0);\n"
              + "        out.println(bar);\n    }\n"),
        "public void handle", "out.println(bar)"))
    # Exec-array direction pins: an array passed WHOLE to the sink
    # unbinds element tracking (b19 rule) — a tainted element must
    # never suppress, and an all-constant array stays candidate-tier
    # (whole-array constant proof is out of scope, honestly).
    j.append(_marked(
        "java_exec_array_tainted_elem", "cmdi", "CWE-78",
        "exec_array_tainted_element_whole_pass", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) throws Exception {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String[] a = {\"sh\", \"-c\", x};\n"
              + "        Runtime r = Runtime.getRuntime();\n"
              + "        r.exec(a);\n"
              + "    }\n"),
        "public void handle", "r.exec(a)"))
    j.append(_marked(
        "java_exec_array_constant_whole", "cmdi", "CWE-78",
        # Graduated by b34's whole-array taint-freedom (was pinned
        # out-of-scope earlier in the same wave; the mechanism now
        # proves it: initializer-only never-escaping array, every
        # element constant).
        "exec_array_constant_whole_pass", LABEL_MAY_SUPPRESS,
        cls_t("    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) throws Exception {\n"
              "        String x = request.getParameter(\"q\");\n"
              + "        String[] a = {\"ls\", \"-la\"};\n"
              + "        Runtime r = Runtime.getRuntime();\n"
              + "        r.exec(a);\n"
              + "    }\n"),
        "public void handle", "r.exec(a)"))
    # Whole-array taint-freedom battery: an initializer-only,
    # never-escaping array passed WHOLE to the sink suppresses only
    # when every element is provably taint-free (constant via the full
    # fold stack — positional list resolution included — or a catalog
    # sanitizer call).
    j.append(_marked(
        "java_wholearr_const_positional", "xss", "CWE-79",
        "wholearr_positional_constant_elements", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        ArrayList<String> l = new ArrayList<String>();\n"
              + "        l.add(\"safe\");\n"
              + "        l.add(x);\n"
              + "        l.add(\"moresafe\");\n"
              + "        l.remove(0);\n"
              + "        String bar = l.get(1);\n"
              + "        Object[] obj = {\"a\", bar};\n"
              + "        out.format(\"%1$s %2$s\", obj);\n    }\n"),
        "public void handle", "out.format"))
    j.append(_marked(
        "java_wholearr_sanitized_elem", "xss", "CWE-79",
        "wholearr_sanitized_element", LABEL_MAY_SUPPRESS,
        cls_t(handle
              + "        Object[] obj = {\"a\", Encode.forHtml(x)};\n"
              + "        out.format(\"%1$s %2$s\", obj);\n    }\n"),
        "public void handle", "out.format"))
    j.append(_marked(
        "java_wholearr_tainted_elem", "xss", "CWE-79",
        "wholearr_tainted_element", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        Object[] obj = {\"a\", x};\n"
              + "        out.format(\"%1$s %2$s\", obj);\n    }\n"),
        "public void handle", "out.format"))
    j.append(_marked(
        "java_wholearr_elem_mutated", "xss", "CWE-79",
        "wholearr_element_mutated_after_init", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        Object[] obj = {\"a\", \"b\"};\n"
              + "        obj[1] = x;\n"
              + "        out.format(\"%1$s %2$s\", obj);\n    }\n"),
        "public void handle", "out.format"))
    j.append(_marked(
        "java_wholearr_aliased", "xss", "CWE-79",
        "wholearr_aliased_reference", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        Object[] obj = {\"a\", \"b\"};\n"
              + "        Object[] p = obj;\n"
              + "        p[1] = x;\n"
              + "        out.format(\"%1$s %2$s\", obj);\n    }\n"),
        "public void handle", "out.format"))
    j.append(_marked(
        "java_wholearr_tainted_scalar_elem", "xss", "CWE-79",
        "wholearr_tainted_scalar_element", LABEL_MUST_NOT_SUPPRESS,
        cls_t(handle
              + "        String bar = x;\n"
              + "        Object[] obj = {\"a\", bar};\n"
              + "        out.format(\"%1$s %2$s\", obj);\n    }\n"),
        "public void handle", "out.format"))
    # Live-damage regression (BenchmarkTest02342 shape): the picked
    # sink argument is a genuinely-constant env array while taint
    # rides the SIBLING argument through a same-file helper — the
    # local taint front cannot see it, so the sibling guard must
    # fold-or-refuse, never assume.
    j.append(_marked(
        "java_wholearr_helper_tainted_sibling", "cmdi", "CWE-78",
        "wholearr_sibling_tainted_via_helper", LABEL_MUST_NOT_SUPPRESS,
        cls_t("    private String grab(HttpServletRequest r, String p) {\n"
              "        return r.getParameter(p);\n    }\n"
              "    public void handle(HttpServletRequest request, "
              "java.io.PrintWriter out) throws Exception {\n"
              "        String param = \"\";\n"
              "        java.util.Enumeration<String> names = "
              "request.getParameterNames();\n"
              "        while (names.hasMoreElements()) {\n"
              "            param = (String) names.nextElement();\n"
              "        }\n"
              "        String bar = grab(request, param);\n"
              "        String[] argsEnv = {\"Foo=bar\"};\n"
              "        Runtime r = Runtime.getRuntime();\n"
              "        r.exec(\"echo \" + bar, argsEnv);\n"
              "    }\n"),
        "public void handle", "r.exec"))
    return j
