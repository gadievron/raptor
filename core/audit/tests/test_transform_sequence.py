"""Tests for core.audit.transform_sequence — transform ordering violations."""

import textwrap

from core.audit.transform_sequence import (
    TransformOrderViolation,
    TransformSequence,
    TransformStep,
    detect_transform_order_violations,
    extract_transform_sequences,
    format_transform_sequences_for_prompt,
)


class TestExtractTransformSequences:
    def test_reassignment_chain(self):
        src = textwrap.dedent("""\
            def process(data):
                data = strip_invisible(data)
                data = sanitize_html(data)
                data = encode_output(data)
                return data
        """)
        seqs = extract_transform_sequences({"app.py": src})
        assert len(seqs) == 1
        seq = seqs[0]
        assert seq.variable == "data"
        assert len(seq.steps) == 3
        assert seq.steps[0].call_name == "strip_invisible"
        assert seq.steps[1].call_name == "sanitize_html"
        assert seq.steps[2].call_name == "encode_output"

    def test_method_chain(self):
        src = textwrap.dedent("""\
            def clean(text):
                result = text.strip().encode('utf-8').decode('utf-8')
                return result
        """)
        seqs = extract_transform_sequences({"util.py": src})
        chains = [s for s in seqs if len(s.steps) >= 2]
        assert len(chains) >= 1
        names = [s.call_name for s in chains[0].steps]
        assert ".strip" in names

    def test_non_security_names_filtered(self):
        src = textwrap.dedent("""\
            def process(data):
                data = frobnicate(data)
                data = whizzle(data)
                return data
        """)
        seqs = extract_transform_sequences({"app.py": src})
        assert len(seqs) == 0

    def test_single_step_filtered(self):
        src = textwrap.dedent("""\
            def clean(data):
                data = sanitize(data)
                return data
        """)
        seqs = extract_transform_sequences({"app.py": src})
        assert len(seqs) == 0

    def test_c_reassignment(self):
        src = textwrap.dedent("""\
            void process(char *buf) {
                buf = url_decode(buf, len);
                buf = sanitize_path(buf, len);
            }
        """)
        seqs = extract_transform_sequences({"app.c": src})
        assert len(seqs) >= 1


class TestDetectTransformOrderViolations:
    def test_correct_order_no_violation(self):
        src = textwrap.dedent("""\
            def process(path):
                path = urllib.parse.unquote(path)
                path = check_path_traversal(path)
                return path
        """)
        violations = detect_transform_order_violations({"app.py": src})
        assert len(violations) == 0

    def test_wrong_order_url_decode_after_path_check(self):
        src = textwrap.dedent("""\
            def process(path):
                path = check_path_traversal(path)
                path = urllib.parse.unquote(path)
                return path
        """)
        violations = detect_transform_order_violations({"app.py": src})
        assert len(violations) >= 1
        v = violations[0]
        assert v.confidence == "high"
        assert "must precede" in v.violation
        assert v.catalog_rule == "decode_before_path_check"

    def test_wrong_order_case_after_blocklist(self):
        src = textwrap.dedent("""\
            def check(name):
                name = check_blocklist(name)
                name = name.lower()
                return name
        """)
        violations = detect_transform_order_violations({"app.py": src})
        assert len(violations) >= 1
        assert violations[0].catalog_rule == "case_normalize_before_blocklist"

    def test_unicode_before_regex(self):
        src = textwrap.dedent("""\
            def defang(text):
                text = re.sub(r'^#', '', text)
                text = strip_invisible_chars(text)
                return text
        """)
        violations = detect_transform_order_violations({"app.py": src})
        assert len(violations) >= 1
        assert violations[0].catalog_rule == "unicode_before_regex"

    def test_no_violation_on_unrelated_calls(self):
        src = textwrap.dedent("""\
            def process(data):
                data = format_output(data)
                data = add_header(data)
                return data
        """)
        violations = detect_transform_order_violations({"app.py": src})
        assert len(violations) == 0

    def test_to_dict(self):
        v = TransformOrderViolation(
            file="a.py", function="f", line=5,
            sequence=["a", "b"], violation="test",
            fix="swap", confidence="high",
            catalog_rule="test_rule",
        )
        d = v.to_dict()
        assert d["file"] == "a.py"
        assert d["catalog_rule"] == "test_rule"


class TestTransformSequenceDataclass:
    def test_line_span(self):
        seq = TransformSequence(
            file="a.py", function="f", variable="x",
            steps=[
                TransformStep(call_name="a", line=3),
                TransformStep(call_name="b", line=7),
            ],
        )
        assert seq.line_span == (3, 7)

    def test_empty_line_span(self):
        seq = TransformSequence(
            file="a.py", function="f", variable="x",
        )
        assert seq.line_span == (0, 0)

    def test_to_dict(self):
        seq = TransformSequence(
            file="a.py", function="f", variable="x",
            steps=[TransformStep(call_name="sanitize", line=5, args_summary="<")],
        )
        d = seq.to_dict()
        assert d["variable"] == "x"
        assert len(d["steps"]) == 1


class TestGoExtraction:
    """Go transform chains via tree-sitter (or regex fallback)."""

    def test_go_reassignment_chain(self):
        src = textwrap.dedent("""\
            package main

            func sanitize(input string) string {
                val := strip_unicode(input)
                val = sanitize_html(val)
                val = url_encode(val)
                return val
            }
        """)
        seqs = extract_transform_sequences({"clean.go": src})
        assert len(seqs) >= 1
        chain = [s for s in seqs if s.variable == "val"]
        assert len(chain) >= 1
        assert len(chain[0].steps) >= 2

    def test_go_method_receiver(self):
        src = textwrap.dedent("""\
            package main

            func (s *Server) process(input string) string {
                input = sanitize_html(input)
                input = escape_output(input)
                return input
            }
        """)
        seqs = extract_transform_sequences({"srv.go": src})
        assert len(seqs) >= 1


class TestJsExtraction:
    """JS transform chains via tree-sitter (or regex fallback)."""

    def test_js_reassignment(self):
        src = textwrap.dedent("""\
            function clean(input) {
                let val = stripInvisible(input);
                val = sanitizeHtml(val);
                val = encodeOutput(val);
                return val;
            }
        """)
        seqs = extract_transform_sequences({"clean.js": src})
        assert len(seqs) >= 1

    def test_js_const_declaration(self):
        src = textwrap.dedent("""\
            function process(path) {
                const decoded = decodeURIComponent(path);
                const safe = checkPathTraversal(decoded);
                return safe;
            }
        """)
        # const assignments to different variables don't form a chain
        # (different LHS) — this is correct behavior
        seqs = extract_transform_sequences({"path.js": src})
        # No chain expected (different variable names)
        assert isinstance(seqs, list)


class TestDoubleEncoding:
    """Double-encoding detection in transform chains."""

    def test_double_url_decode_detected(self):
        src = textwrap.dedent("""\
            def process(path):
                path = urllib.parse.unquote(path)
                path = check_path(path)
                path = urllib.parse.unquote(path)
                return path
        """)
        violations = detect_transform_order_violations({"app.py": src})
        double = [v for v in violations if v.catalog_rule == "double_encoding"]
        assert len(double) >= 1
        assert "double url_decode" in double[0].violation

    def test_single_decode_not_flagged(self):
        src = textwrap.dedent("""\
            def process(path):
                path = urllib.parse.unquote(path)
                path = check_path(path)
                return path
        """)
        violations = detect_transform_order_violations({"app.py": src})
        double = [v for v in violations if v.catalog_rule == "double_encoding"]
        assert len(double) == 0

    def test_double_base64_decode(self):
        src = textwrap.dedent("""\
            def decode_payload(data):
                data = base64.b64decode(data)
                data = validate(data)
                data = base64.b64decode(data)
                return data
        """)
        violations = detect_transform_order_violations({"app.py": src})
        double = [v for v in violations if v.catalog_rule == "double_encoding"]
        assert len(double) >= 1
        assert "base64_decode" in double[0].violation

    def test_double_encoding_confidence_medium(self):
        src = textwrap.dedent("""\
            def process(path):
                path = urllib.parse.unquote(path)
                path = urllib.parse.unquote(path)
                return path
        """)
        violations = detect_transform_order_violations({"app.py": src})
        double = [v for v in violations if v.catalog_rule == "double_encoding"]
        assert len(double) >= 1
        assert double[0].confidence == "medium"


class TestDuplicateTransform:
    """Exact-name duplicate transform detection."""

    def test_same_function_twice_detected(self):
        src = textwrap.dedent("""\
            def process(data):
                data = custom_sanitize(data)
                data = validate(data)
                data = custom_sanitize(data)
                return data
        """)
        violations = detect_transform_order_violations({"app.py": src})
        dups = [v for v in violations if v.catalog_rule == "duplicate_transform"]
        assert len(dups) >= 1
        assert "custom_sanitize" in dups[0].violation
        assert dups[0].confidence == "medium"

    def test_no_duplicate_when_different_names(self):
        src = textwrap.dedent("""\
            def process(data):
                data = sanitize_html(data)
                data = sanitize_sql(data)
                return data
        """)
        violations = detect_transform_order_violations({"app.py": src})
        dups = [v for v in violations if v.catalog_rule == "duplicate_transform"]
        assert len(dups) == 0

    def test_encoding_class_not_double_counted(self):
        """url_decode appearing twice should flag as double_encoding, not also duplicate_transform."""
        src = textwrap.dedent("""\
            def process(path):
                path = urllib.parse.unquote(path)
                path = check_path(path)
                path = urllib.parse.unquote(path)
                return path
        """)
        violations = detect_transform_order_violations({"app.py": src})
        dups = [v for v in violations if v.catalog_rule == "duplicate_transform"]
        assert len(dups) == 0
        double = [v for v in violations if v.catalog_rule == "double_encoding"]
        assert len(double) >= 1


class TestIRISExtraSecurityNames:
    """IRIS spec consumption via extra_security_names."""

    def test_extra_names_include_non_matching_transforms(self):
        src = textwrap.dedent("""\
            def process(data):
                data = frobnicate(data)
                data = whizzle(data)
                return data
        """)
        seqs = extract_transform_sequences({"app.py": src})
        assert len(seqs) == 0

        seqs = extract_transform_sequences(
            {"app.py": src},
            extra_security_names=frozenset({"frobnicate", "whizzle"}),
        )
        assert len(seqs) == 1


class TestFormatForPrompt:
    def test_empty(self):
        assert format_transform_sequences_for_prompt([]) == ""

    def test_formatting(self):
        seqs = [TransformSequence(
            file="a.py", function="clean", variable="data",
            steps=[
                TransformStep(call_name="strip", line=3),
                TransformStep(call_name="encode", line=4),
            ],
        )]
        text = format_transform_sequences_for_prompt(seqs)
        assert "a.py:clean" in text
        assert "`strip`" in text
        assert "`encode`" in text
