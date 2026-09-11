"""File exclusion logic — patterns, binary detection, generated file detection."""

import fnmatch
import os
import re
from pathlib import Path

# Default exclude patterns — comprehensive list for clean inventory
DEFAULT_EXCLUDES = [
    # Test directories and files
    '*_test.*', 'test_*', '*_mock.*', 'mock_*', '*_spec.*',
    '__tests__/', 'tests/', 'test/', 'spec/', 'testing/',
    'fixtures/', '__fixtures__/', 'testdata/', 'test-data/',

    # Dependencies and vendor code
    'node_modules/', 'vendor/', 'third_party/', 'third-party/',
    'external/', 'deps/', 'dependencies/',

    # Python virtual environments and caches
    'venv/', '.venv/', 'env/', '.env/', 'virtualenv/',
    '__pycache__/', '.pytest_cache/', '.tox/', '.eggs/',
    '*.egg-info/', 'site-packages/',

    # Build outputs
    'dist/', 'build/', 'target/', 'out/', 'output/',
    'bin/', 'obj/', 'cmake-build-*/',

    # Version control
    '.git/', '.svn/', '.hg/', '.bzr/',

    # IDE and editor
    '.idea/', '.vscode/', '.vs/', '*.swp', '*.swo',

    # Generated/minified files
    '*.min.js', '*.min.css', '*.bundle.js', '*.bundle.css',
    '*.generated.*', '*.auto.*', '*_generated.*',
    '*_pb2.py', '*_pb2_grpc.py',  # Protobuf
    '*.pb.go', '*.pb.cc',  # Protobuf
    'generated/', 'gen/', 'autogen/',

    # Documentation
    'docs/', 'doc/', 'documentation/',

    # Examples and samples
    'examples/', 'example/', 'samples/', 'sample/', 'demo/',
]

# Subset of DEFAULT_EXCLUDES directory names that also legitimately occur as
# first-party package / source segments — a Spring sample under
# ``org/springframework/samples/…``, example code in ``examples/``, a ``doc``
# package, etc. Pruning these by basename at ANY depth silently drops
# first-party source from the inventory, a false negative for every downstream
# scanner. They are therefore pruned ONLY at the scan-root top level (where
# they're overwhelmingly throwaway demo / docs dirs); nested occurrences are
# kept and analysed. Unambiguous non-source dirs (node_modules, vendor, .git,
# build outputs, venvs, generated/, test dirs) are NOT here and keep pruning at
# any depth. Bare names (no trailing slash) to match a directory basename.
ROOT_ANCHORED_EXCLUDE_DIRS = frozenset({
    'examples', 'example', 'samples', 'sample', 'demo',
    'docs', 'doc', 'documentation',
    # Build-output NAMES that also occur as first-party package
    # segments deep in real trees: a first-party ``env/`` config
    # package, tool trees with ``bin/`` source dirs, ``out/`` and
    # ``obj/`` in generators. At the scan root these are
    # overwhelmingly artifacts; pruning them at ANY depth silently
    # dropped first-party source. NOT anchored: ``build/``,
    # ``target/``, ``dist/`` — nested occurrences are the NORM for
    # Gradle/Maven/Rust/JS build outputs, and admitting them buys
    # noise, not recall. venv/node_modules and friends also stay
    # any-depth (unambiguous).
    'env', 'bin', 'out', 'output', 'obj',
})

# Build-output NAMES whose nested occurrences may be exempted when the
# directory is provably first-party source rather than an artifact tree.
# Nested ``build/``/``target/``/``dist/`` prunes are the right default
# (Gradle/Maven/Rust/JS outputs are the norm), but a repository can ship a
# first-party Python package under one of these names (a ``build`` package
# with ``__init__.py``), and pruning it silently drops real source from
# every downstream scanner. The discriminator is a DIRECT ``__init__.py``
# child: Gradle/Maven/Cargo artifact dirs never carry one, and setuptools
# build trees place package copies under ``build/lib*/pkg/``, never an
# ``__init__.py`` directly in ``build/``. Miss direction is FN-safe both
# ways: a hostile repo planting ``build/__init__.py`` only ADDS files to
# analysis (over-analysis, never suppression); a real artifact tree without
# the marker keeps pruning exactly as before. Root-anchored names
# (``out``/``bin``/…) are handled by ROOT_ANCHORED_EXCLUDE_DIRS and test
# dirs stay excluded unconditionally — exempting ``tests/`` on the package
# marker would readmit every Python test package.
PKG_EXEMPTIBLE_BUILD_DIRS = frozenset({'build', 'target', 'dist'})


def is_first_party_package_dir(abs_dir: Path) -> bool:
    """True when ``abs_dir`` is a Python package (direct ``__init__.py``),
    the first-party marker that exempts a build-output-named directory
    from pruning (see ``PKG_EXEMPTIBLE_BUILD_DIRS``)."""
    try:
        return (abs_dir / '__init__.py').is_file()
    except OSError:
        return False


def _pkg_exempt(
    dir_name: str,
    filepath: str,
    path_parts_lower: list[str],
    target_root: 'Path | str | None',
) -> bool:
    """True when the matched build-output dir segment resolves to a
    first-party package under ``target_root``. The filesystem probe joins
    ORIGINAL-case segments (the lowered parts exist only for pattern
    matching); an unresolvable segment keeps the exclusion — the safe
    miss direction."""
    if target_root is None or dir_name not in PKG_EXEMPTIBLE_BUILD_DIRS:
        return False
    orig_parts = filepath.split(os.sep)
    # Probe EVERY occurrence of the name, not just the first: the walk
    # prunes case-sensitively, so a kept case-variant ancestor (Build/)
    # can precede the inner lowercase dir that actually earned the
    # walk-time keep — exempting on any package occurrence keeps the
    # two layers agreeing.
    idx = -1
    while True:
        try:
            idx = path_parts_lower.index(dir_name, idx + 1)
        except ValueError:
            return False
        if len(orig_parts) < idx + 1:
            return False
        if is_first_party_package_dir(
            Path(target_root).joinpath(*orig_parts[:idx + 1])
        ):
            return True


# Markers that indicate a file is auto-generated (check first few lines)
GENERATED_MARKERS = [
    'auto-generated', 'autogenerated', 'automatically generated',
    'do not edit', 'do not modify', 'generated by', 'generated from',
    '@generated', '// code generated', '# generated', '/* generated',
    'this file was generated', 'machine generated',
]


def is_binary_file(filepath: Path, sample_size: int = 8192) -> bool:
    """Check if file is binary by looking for null bytes.

    Pre-fix the check sampled only the first ``sample_size`` bytes.
    Files with a long ASCII prefix followed by binary content
    (polyglots, malformed source generated by a buggy emitter,
    target-repo files with a text header documenting an embedded
    binary blob, or LLM-generated synthetic-vuln test fixtures
    that paste a large header) escaped detection — the inventory
    then tried to extract functions from a binary tail and
    tree-sitter spent CPU on garbage before erroring.

    Sample BOTH ends: the original head sample plus a tail sample
    of the same size when the file is larger than sample_size.
    Files smaller than sample_size are fully covered by the
    head sample alone.  Single seek + read for the tail keeps
    wallclock minimal.
    """
    try:
        with Path(filepath).open("rb") as f:
            chunk = f.read(sample_size)
            if b'\x00' in chunk:
                return True
            # Tail probe — only worth doing when the file is large
            # enough that the head sample didn't already cover it.
            try:
                f.seek(0, 2)  # SEEK_END
                size = f.tell()
            except OSError:
                return False
            if size > sample_size:
                f.seek(size - sample_size)
                tail = f.read(sample_size)
                if b'\x00' in tail:
                    return True
            return False
    except OSError:
        return True  # Treat unreadable as binary


def is_generated_file(content: str, check_lines: int = 10) -> bool:
    """Check if file appears to be auto-generated.

    Comment-anchored: each marker must appear inside a COMMENT line
    (lines starting with `#`, `//`, `/*`, `*`, `--`, `<!--`,
    optionally with leading whitespace) within the first
    `check_lines` lines.

    Pre-fix the substring scan checked the lowercased header
    text without comment-anchoring, so:

    * A regular Python file containing the string `"automatically
      generated"` in a docstring, error message, or test fixture
      (`"this script generates the report automatically generated
      from..."`) was wrongly classified as auto-generated and
      excluded from the inventory. Real callers had analysis-
      target files dropped silently — coverage stats wrong, sinks
      missed.
    * A SARIF rule description that mentioned "do not edit"
      (e.g. flagging hardcoded credentials with the message
      "do not edit; this credential ...") triggered the marker
      from inside the SARIF JSON.
    * A test file documenting a generator's behaviour ("verify
      that generated files contain the auto-generated marker")
      excluded itself even though it was a test, not generated.

    Anchor to comments: the marker must be inside a recognisable
    comment to count. Generators emit their markers in comment
    headers; the substring-only check matched any prose mention.
    """
    lines = content.split('\n', check_lines)[:check_lines]
    # Comment-line shapes for the languages we extract from.
    # `re.match` against the leading-whitespace + comment-start
    # pattern. If the line isn't a comment, skip it for marker
    # matching (but still consider it as "we've seen check_lines
    # of content"). The comment-prefix list covers C/C++/Java
    # (`//`, `/*`, ` *` continuation), Python/shell/Ruby (`#`),
    # SQL/Lua (`--`), and HTML/XML (`<!--`).
    import re as _re
    comment_re = _re.compile(r'^\s*(#|//|/\*|\*|--|<!--)')
    for raw in lines:
        if not comment_re.match(raw):
            continue
        lowered = raw.lower()
        for marker in GENERATED_MARKERS:
            if marker in lowered:
                return True
    return False


# Path/name shapes that independently support a generated-file claim.
# The in-file marker is TARGET-CONTROLLED text: honouring it alone let
# one comment line self-exclude any file from every analysis tier — a
# self-service evasion channel. A generator's output almost always
# ALSO lands in a generated-shaped location or carries a
# generated-shaped name; requiring that corroboration keeps the
# noise-reduction for real generated code while a hand-planted marker
# on a normal source file no longer buys invisibility.
_GENERATED_PATH_HINTS = (
    "generated", "gen", "autogen", "codegen", "build", "dist",
    "target", "out", "output", "node_modules", "vendor", "third_party",
)
_GENERATED_NAME_RE = re.compile(
    r"(\.generated\.|_generated\.|\.auto\.|_pb2(_grpc)?\.py$"
    r"|\.pb\.(go|cc|h)$|\.min\.(js|css)$|\.bundle\.(js|css)$"
    r"|(^|/)(lex\.yy\.c|y\.tab\.[ch])$|\.tab\.[ch]$"
    r"|_string(er)?\.go$|\.g\.(dart|cs)$|_gen\.(go|py|rs|c|h)$"
    r"|\.pyi$|\.d\.ts$)",
    re.IGNORECASE,
)


def generated_marker_corroborated(filepath: str) -> bool:
    """True when the file's PATH independently supports its
    generated-file marker (see the rationale above)."""
    norm = filepath.replace("\\", "/").lower()
    if _GENERATED_NAME_RE.search(norm):
        return True
    parts = norm.split("/")[:-1]
    return any(part in _GENERATED_PATH_HINTS for part in parts)


def should_exclude(
    filepath: str,
    exclude_patterns: list[str],
    target_root: 'Path | str | None' = None,
) -> bool:
    """Check if file should be excluded based on patterns.

    Returns True if the file matches any exclusion pattern.

    ``target_root`` (optional) enables the first-party package exemption
    for nested build-output dir names (see ``PKG_EXEMPTIBLE_BUILD_DIRS``);
    without it, matching is pure-string and behaves as before.
    """
    return match_exclusion_reason(filepath, exclude_patterns, target_root)[0]


def match_exclusion_reason(
    filepath: str,
    exclude_patterns: list[str],
    target_root: 'Path | str | None' = None,
) -> tuple:
    """Like should_exclude but returns (excluded: bool, reason, pattern_matched).

    Used for exclusion recording in the inventory. ``target_root`` enables
    the same first-party package exemption as ``should_exclude``.
    """
    filepath_lower = filepath.lower()
    path_parts_lower = filepath_lower.split(os.sep)
    # Directory-shaped patterns describe DIRECTORIES. The final path
    # component is the file's basename, so it must never be tested
    # against them — otherwise a FILE named after a build dir (a
    # shebang dispatch script `build`, `script/test`, `pkg.egg-info`)
    # is silently dropped as if it were an excluded directory.
    dir_parts_lower = path_parts_lower[:-1]

    for pattern in exclude_patterns:
        pattern_lower = pattern.lower()
        # Directory pattern (ends with /)
        if pattern.endswith('/'):
            dir_name = pattern_lower[:-1]
            # When the directory pattern contains glob metacharacters
            # (e.g. ``*.egg-info/``, ``cmake-build-*/``), match each path
            # component via fnmatch. Plain ``in`` would only catch a literal
            # path segment named ``*.egg-info``, which never exists.
            if any(c in dir_name for c in "*?["):
                if any(fnmatch.fnmatch(part, dir_name) for part in dir_parts_lower):
                    return True, "pattern_match", pattern
            elif dir_name in ROOT_ANCHORED_EXCLUDE_DIRS:
                # First-party-collision-prone name (examples/ samples/ docs/ …):
                # only a TOP-LEVEL dir of this name is a throwaway demo/docs dir.
                # A nested occurrence is a package/source segment, so matching it
                # anywhere would silently exclude first-party source. Anchor to
                # the first path component (mirrors the walk-time prune).
                if dir_parts_lower and dir_parts_lower[0] == dir_name:
                    return True, "pattern_match", pattern
            elif dir_name in dir_parts_lower:
                if _pkg_exempt(dir_name, filepath, path_parts_lower, target_root):
                    continue
                return True, "pattern_match", pattern
        # Glob pattern
        elif '*' in pattern:
            if fnmatch.fnmatch(os.path.basename(filepath_lower), pattern_lower):
                return True, "pattern_match", pattern
            # Full-path fnmatch only for path-shaped globs (containing a
            # separator): fnmatch's ``*`` crosses ``/``, so testing a
            # basename-shaped glob like ``test_*`` against the whole path
            # would exclude entire first-party top-level trees
            # (``test_utils/prod/main.py``). The basename match above
            # already covers what basename-shaped globs intend.
            if ('/' in pattern or os.sep in pattern) and fnmatch.fnmatch(
                filepath_lower, pattern_lower
            ):
                return True, "pattern_match", pattern
        # Exact filename or path segment match
        elif pattern_lower in path_parts_lower or pattern_lower == os.path.basename(filepath_lower):
            return True, "pattern_match", pattern

    return False, None, None
