"""Tests for core.audit.pattern_completeness — narrow-pattern detection."""

from __future__ import annotations

import textwrap

import pytest

from core.audit.pattern_completeness import (
    PatternGap,
    detect_pattern_gaps,
)


# -------------------------------------------------------------------
# Extension synonym gaps
# -------------------------------------------------------------------

class TestExtensionSynonymGaps:
    """Sub-detector: glob/endswith with one extension but not its synonym."""

    def test_glob_yml_without_yaml_flagged(self):
        source = textwrap.dedent("""\
            def find_configs(root):
                return glob("*.yml")
        """)
        gaps = detect_pattern_gaps({"config_loader.py": source})
        assert len(gaps) == 1
        g = gaps[0]
        assert g.gap_type == "missing_synonym"
        assert g.file == "config_loader.py"
        assert g.function == "find_configs"
        assert ".yaml" in g.suggestion
        assert g.confidence == "high"

    def test_glob_yml_with_yaml_no_flag(self):
        source = textwrap.dedent("""\
            def find_configs(root):
                files = glob("*.yml")
                files += glob("*.yaml")
                return files
        """)
        gaps = detect_pattern_gaps({"config_loader.py": source})
        assert len(gaps) == 0

    def test_endswith_yml_without_yaml_flagged(self):
        source = textwrap.dedent("""\
            def is_config(path):
                return path.endswith(".yml")
        """)
        gaps = detect_pattern_gaps({"util.py": source})
        assert len(gaps) == 1
        assert gaps[0].gap_type == "missing_synonym"
        assert ".yaml" in gaps[0].suggestion

    def test_endswith_yaml_without_yml_flagged(self):
        """The reverse direction is also caught."""
        source = textwrap.dedent("""\
            def is_config(path):
                return path.endswith(".yaml")
        """)
        gaps = detect_pattern_gaps({"util.py": source})
        assert len(gaps) == 1
        assert ".yml" in gaps[0].suggestion

    def test_glob_jpg_without_jpeg_flagged(self):
        source = textwrap.dedent("""\
            def list_images():
                return glob("*.jpg")
        """)
        gaps = detect_pattern_gaps({"images.py": source})
        assert len(gaps) == 1
        assert ".jpeg" in gaps[0].suggestion

    def test_glob_htm_without_html_flagged(self):
        source = textwrap.dedent("""\
            def list_pages():
                return glob("*.htm")
        """)
        gaps = detect_pattern_gaps({"pages.py": source})
        assert len(gaps) == 1
        assert ".html" in gaps[0].suggestion

    def test_glob_recursive_pattern_flagged(self):
        source = textwrap.dedent("""\
            def find_all_yaml():
                return glob("**/*.yml")
        """)
        gaps = detect_pattern_gaps({"search.py": source})
        assert len(gaps) == 1
        assert ".yaml" in gaps[0].suggestion

    def test_non_synonym_extension_no_flag(self):
        source = textwrap.dedent("""\
            def find_python():
                return glob("*.py")
        """)
        gaps = detect_pattern_gaps({"tools.py": source})
        assert len(gaps) == 0

    def test_both_yml_and_yaml_inline_no_flag(self):
        """When .yaml appears as a string anywhere in the file, no flag."""
        source = textwrap.dedent("""\
            SUPPORTED = [".yml", ".yaml"]
            def find_configs(root):
                return glob("*.yml")
        """)
        gaps = detect_pattern_gaps({"loader.py": source})
        assert len(gaps) == 0


# -------------------------------------------------------------------
# Sibling prefix inconsistency
# -------------------------------------------------------------------

class TestSiblingPrefixGaps:
    """Sub-detector: startswith for one form but not the sibling."""

    def test_editable_without_short_form_flagged(self):
        source = textwrap.dedent("""\
            def _is_pip_option(line):
                if line.startswith("--editable"):
                    return True
                return False
        """)
        gaps = detect_pattern_gaps({"requirements.py": source})
        assert len(gaps) == 1
        g = gaps[0]
        assert g.gap_type == "greedy_prefix"
        assert "-e" in g.suggestion
        assert g.file == "requirements.py"

    def test_editable_with_short_form_no_flag(self):
        source = textwrap.dedent("""\
            def parse(line):
                if line.startswith("-e ") or line.startswith("--editable "):
                    return handle_editable(line)
        """)
        gaps = detect_pattern_gaps({"requirements.py": source})
        assert len(gaps) == 0

    def test_short_without_long_flagged(self):
        source = textwrap.dedent("""\
            def parse_args(args):
                if args.startswith("-r"):
                    return load_req(args)
        """)
        gaps = detect_pattern_gaps({"cli.py": source})
        assert len(gaps) == 1
        assert "--requirement" in gaps[0].suggestion

    def test_exclusion_inconsistency_flagged(self):
        """One form excluded, sibling handled — flag."""
        source = textwrap.dedent("""\
            def _is_pip_option(line):
                # skip these options
                if line.startswith("--editable"):
                    return True

            def parse(line):
                if line.startswith("-e "):
                    return handle(line)
        """)
        gaps = detect_pattern_gaps({"req.py": source})
        # Should flag the inconsistency: --editable is in a skip context,
        # -e is in a handler context.
        flagged = [g for g in gaps if g.gap_type == "greedy_prefix"]
        assert len(flagged) >= 1
        skip_gap = [g for g in flagged if "excluded" in g.suggestion
                     or "differently" in g.suggestion]
        assert len(skip_gap) >= 1

    def test_unknown_option_no_flag(self):
        """Options not in the known pairs table are not flagged."""
        source = textwrap.dedent("""\
            def parse(line):
                if line.startswith("--custom-thing"):
                    return True
        """)
        gaps = detect_pattern_gaps({"cli.py": source})
        assert len(gaps) == 0


# -------------------------------------------------------------------
# Regex character class exclusions
# -------------------------------------------------------------------

class TestCharClassExclusions:
    """Sub-detector: negated char class excluding valid domain chars."""

    def test_purl_excluding_at_flagged(self):
        source = textwrap.dedent("""\
            # Parse purl path component
            _PURL_RE = re.compile(r'pkg:[a-z]+/([^@?#]+)')
        """)
        gaps = detect_pattern_gaps({"purl_parser.py": source})
        assert len(gaps) == 1
        g = gaps[0]
        assert g.gap_type == "char_class_exclusion"
        assert "'@'" in g.suggestion
        assert g.confidence in ("high", "medium")

    def test_url_excluding_brackets_flagged(self):
        source = textwrap.dedent("""\
            # Parse URL host
            url_pattern = re.compile(r'https?://([^/:@\\[\\]]+)')
        """)
        # The context contains "url" so domain is detected.
        gaps = detect_pattern_gaps({"url_parse.py": source})
        # Should flag because URL domain chars are being excluded.
        char_gaps = [g for g in gaps if g.gap_type == "char_class_exclusion"]
        assert len(char_gaps) >= 1

    def test_no_domain_hint_no_flag(self):
        """Without domain context, negated classes are not flagged."""
        source = textwrap.dedent("""\
            def tokenize(s):
                return re.split(r'[^a-zA-Z]+', s)
        """)
        gaps = detect_pattern_gaps({"tokenizer.py": source})
        assert len(gaps) == 0

    def test_npm_excluding_at_flagged(self):
        source = textwrap.dedent("""\
            # Parse npm package name
            NPM_RE = re.compile(r'([^@/]+)/([^@]+)')
        """)
        gaps = detect_pattern_gaps({"npm_parse.py": source})
        char_gaps = [g for g in gaps if g.gap_type == "char_class_exclusion"]
        assert len(char_gaps) >= 1
        assert any("'@'" in g.suggestion for g in char_gaps)

    def test_docker_context_excluding_at_flagged(self):
        source = textwrap.dedent("""\
            # Parse docker image reference
            IMAGE_RE = re.compile(r'([^:@]+):([^@]+)')
        """)
        gaps = detect_pattern_gaps({"docker_ref.py": source})
        char_gaps = [g for g in gaps if g.gap_type == "char_class_exclusion"]
        assert len(char_gaps) >= 1


# -------------------------------------------------------------------
# Directory glob completeness
# -------------------------------------------------------------------

class TestDirectoryGlobGaps:
    """Sub-detector: globs in known directory types."""

    def test_workflows_yml_without_yaml_flagged(self):
        source = textwrap.dedent("""\
            def list_workflows():
                return glob(".github/workflows/*.yml")
        """)
        gaps = detect_pattern_gaps({"ci.py": source})
        syn_gaps = [g for g in gaps if g.gap_type == "missing_synonym"]
        # Should flag both the glob synonym AND the directory expectation.
        assert len(syn_gaps) >= 1
        assert any(".yaml" in g.suggestion for g in syn_gaps)

    def test_workflows_both_extensions_no_flag(self):
        source = textwrap.dedent("""\
            def list_workflows():
                a = glob(".github/workflows/*.yml")
                b = glob(".github/workflows/*.yaml")
                return a + b
        """)
        gaps = detect_pattern_gaps({"ci.py": source})
        dir_gaps = [
            g for g in gaps
            if g.gap_type == "missing_synonym"
            and ".github/workflows" in g.suggestion
        ]
        assert len(dir_gaps) == 0


# -------------------------------------------------------------------
# Cross-file detection
# -------------------------------------------------------------------

class TestCrossFile:
    """Verify multi-file source_text dict is handled correctly."""

    def test_multiple_files(self):
        sources = {
            "a.py": 'def f(): return glob("*.yml")\n',
            "b.py": 'def g(): return glob("*.jpg")\n',
        }
        gaps = detect_pattern_gaps(sources)
        files = {g.file for g in gaps}
        assert "a.py" in files
        assert "b.py" in files

    def test_empty_source_text(self):
        gaps = detect_pattern_gaps({})
        assert gaps == []


# -------------------------------------------------------------------
# Data model validation
# -------------------------------------------------------------------

class TestPatternGapValidation:
    """PatternGap dataclass invariants."""

    def test_invalid_gap_type_raises(self):
        with pytest.raises(ValueError, match="gap_type"):
            PatternGap(
                file="x.py",
                function="f",
                line=1,
                pattern="*.foo",
                gap_type="invalid_type",
                suggestion="fix it",
                confidence="low",
            )

    def test_valid_gap_types_accepted(self):
        for gt in ("missing_synonym", "char_class_exclusion",
                    "greedy_prefix", "missing_combination"):
            g = PatternGap(
                file="x.py",
                function="f",
                line=1,
                pattern="*.foo",
                gap_type=gt,
                suggestion="fix",
                confidence="low",
            )
            assert g.gap_type == gt
