#!/usr/bin/env python3
"""
Radare2 Wrapper for Enhanced Binary Analysis

Provides JSON-based API for binary analysis using radare2:
- Disassembly with JSON output
- Decompilation to pseudo-C
- Cross-reference analysis
- Binary metadata extraction
- Function call graph generation

This replaces/enhances objdump usage in crash_analyser.py with:
- Structured JSON output (no text parsing)
- Decompilation capabilities
- Cross-reference tracking
- Richer metadata
"""

import json
import logging
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class Radare2DisasmInstruction:
    """Single disassembled instruction with metadata."""
    offset: str          # Hex address
    opcode: str          # Raw opcode bytes
    disasm: str          # Disassembly string
    type: str            # Instruction type (call, jmp, mov, etc.)
    esil: Optional[str] = None  # ESIL representation
    refs: Optional[List[str]] = None  # Cross-references

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, filtering None values."""
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class Radare2Function:
    """Function metadata from radare2 analysis."""
    name: str
    offset: str          # Hex address
    size: int
    nbbs: int            # Number of basic blocks
    ninstrs: int         # Number of instructions
    calltype: str        # Calling convention
    edges: int = 0       # Control flow edges
    cc: int = 0          # Cyclomatic complexity

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class Radare2Wrapper:
    """
    Wrapper around radare2 for binary analysis.

    Provides high-level JSON-based API for:
    - Function disassembly (pdfj)
    - Decompilation (pdd)
    - Cross-references (axtj, axfj)
    - Binary metadata (iij, iEj)
    - Call graphs (agfj)

    Usage:
        radare2 = Radare2Wrapper("/path/to/binary")
        if radare2.is_available():
            disasm = radare2.disassemble_at_address("0x401000", count=20)
            xrefs = radare2.get_xrefs_to("0x401000")
    """

    def __init__(
        self,
        binary_path: Path,
        radare2_path: str = "radare2",
        analysis_depth: str = "aa",
        timeout: Optional[int] = None
    ):
        """
        Initialize radare2 wrapper.

        Args:
            binary_path: Path to binary to analyze
            radare2_path: Path to radare2 executable (default: "radare2" from PATH)
            analysis_depth: Analysis level (aa, aaa, aaaa) - default: aa (basic, recommended)
            timeout: Default timeout for radare2 commands in seconds (default: auto-scale by size)
        """
        self.binary = Path(binary_path)
        self.radare2_path = radare2_path
        self.analysis_depth = analysis_depth
        self._available = None
        self._analyzed = False

        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary}")

        # Auto-scale timeout based on binary size (if not explicitly set)
        import os
        binary_size = os.path.getsize(self.binary)
        if timeout is None:
            # Scale timeout based on binary size
            if binary_size < 1_000_000:  # <1MB
                self.timeout = 60
            elif binary_size < 10_000_000:  # 1-10MB
                self.timeout = 300
            elif binary_size < 100_000_000:  # 10-100MB
                self.timeout = 600
            else:  # >100MB
                self.timeout = 1200
        else:
            # Use explicit timeout
            self.timeout = timeout

    def is_available(self) -> bool:
        """Check if radare2 is available in PATH."""
        if self._available is None:
            self._available = shutil.which(self.radare2_path) is not None
            if not self._available:
                logger.warning(f"radare2 not found in PATH (looking for '{self.radare2_path}')")
        return self._available

    def _execute_command(
        self,
        command: str,
        json_output: bool = True,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute radare2 command and return result.

        Args:
            command: radare2 command to execute (e.g., "iij", "pdfj @ main")
            json_output: Whether to expect JSON output (default: True)
            timeout: Command timeout in seconds (default: self.timeout)

        Returns:
            Parsed JSON output as dict, or {"raw_output": str, "error": str} on failure
        """
        if not self.is_available():
            return {"error": "radare2 not available", "raw_output": ""}

        timeout = timeout or self.timeout

        # Build radare2 command: -q (quiet), -A (analyze on load if first command), -c (command), file
        # Note: We only run analysis once via separate call to avoid repeated analysis overhead
        cmd = [
            self.radare2_path,
            "-q",           # Quiet mode (no startup banner)
            "-c", command,  # Command to execute
            str(self.binary)
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            if result.returncode != 0:
                logger.debug(f"radare2 command failed (rc={result.returncode}): {command}")
                return {
                    "error": f"radare2 returned exit code {result.returncode}",
                    "raw_output": result.stdout,
                    "stderr": result.stderr
                }

            # Parse JSON output if expected
            if json_output:
                try:
                    return json.loads(result.stdout)
                except json.JSONDecodeError as e:
                    logger.debug(f"Failed to parse JSON from radare2: {e}")
                    return {
                        "error": "Failed to parse JSON output",
                        "raw_output": result.stdout,
                        "parse_error": str(e)
                    }
            else:
                return {"raw_output": result.stdout}

        except subprocess.TimeoutExpired:
            logger.warning(f"radare2 command timed out after {timeout}s: {command}")
            return {"error": f"Command timed out after {timeout}s", "raw_output": ""}
        except Exception as e:
            logger.error(f"radare2 command failed: {e}")
            return {"error": str(e), "raw_output": ""}

    def _sanitize_address(self, address: str) -> str:
        """
        Sanitize address input to prevent command injection.

        Removes radare2 command separators that could be used for command injection:
        - ';' : Command separator
        - '|' : Pipe to shell command
        - '!' : Execute shell command

        Args:
            address: Address string (hex or symbol name)

        Returns:
            Sanitized address with dangerous characters removed

        Security:
            Prevents attacks like: "0x1000; ! rm -rf /"
            Result after sanitization: "0x1000  rm -rf "
        """
        if not address:
            return address

        # Remove radare2 command separators
        sanitized = address.replace(';', '').replace('|', '').replace('!', '')

        if sanitized != address:
            logger.warning(f"Address contained command separators (sanitized): {address} -> {sanitized}")

        return sanitized

    def analyze(self) -> bool:
        """
        Run initial binary analysis (idempotent).

        Returns:
            True if analysis succeeded or already done, False on failure
        """
        # Skip if no analysis requested
        if not self.analysis_depth or self.analysis_depth == "":
            logger.debug("Analysis skipped (analysis_depth empty)")
            return True

        # Skip if already analyzed
        if self._analyzed:
            return True

        logger.info(f"Analyzing binary with radare2 ({self.analysis_depth})...")

        # Run analysis command
        result = self._execute_command(self.analysis_depth, json_output=False, timeout=600)

        if result is None or "error" in result:
            logger.error(f"Analysis failed: {result.get('error', 'Unknown error') if result else 'No result'}")
            return False

        self._analyzed = True
        logger.info("Analysis complete")
        return True

    def get_binary_info(self) -> Dict[str, Any]:
        """
        Get binary metadata (iij - info in JSON).

        Returns:
            Binary info including: arch, bits, os, endian, stripped, checksums, etc.
        """
        return self._execute_command("iij")

    def get_security_info(self) -> Dict[str, bool]:
        """
        Get security mitigation information (fast, no analysis needed).

        Uses `i~` filters to check for security mitigations without analysis.

        Returns:
            Dict with canary, nx, pie, relocs, stripped, static, crypto flags
        """
        # Fast security check using i~ filters
        result = self._execute_command("i~canary,nx,pic,crypto,stripped,static,relocs",
                                       json_output=False)

        if not result or 'raw_output' not in result:
            return {
                'canary': False, 'nx': False, 'pie': False, 'relocs': False,
                'stripped': False, 'static': False, 'crypto': False
            }

        output = result['raw_output'].lower()

        return {
            'canary': 'canary' in output and 'true' in output,
            'nx': 'nx' in output and 'true' in output,
            'pie': 'pic' in output and 'true' in output,
            'relocs': 'relocs' in output,
            'stripped': 'stripped' in output,
            'static': 'static' in output,
            'crypto': 'crypto' in output
        }

    def get_entrypoint(self) -> Dict[str, Any]:
        """
        Get entrypoint information (iEj - entrypoint in JSON).

        Returns:
            Entrypoint address, size, and type
        """
        result = self._execute_command("iEj")
        # iEj returns an array, take first entry
        if isinstance(result, list) and len(result) > 0:
            return result[0]
        return result

    def list_functions(self) -> List[Radare2Function]:
        """
        List all functions found by analysis (aflj - analyze function list JSON).

        Returns:
            List of Radare2Function objects with metadata
        """
        # Run analysis command with aflj to ensure analysis state is available
        # (each _execute_command spawns new radare2 process, so we need to re-analyze)
        if self.analysis_depth and self.analysis_depth != "":
            command = f"{self.analysis_depth}; aflj"
        else:
            command = "aflj"

        result = self._execute_command(command)

        if "error" in result:
            return []

        if not isinstance(result, list):
            return []

        functions = []
        for func_data in result:
            try:
                # radare2 uses "addr" not "offset" in aflj output
                addr = func_data.get("addr", func_data.get("offset", 0))
                # Convert to hex string if integer
                offset_str = hex(addr) if isinstance(addr, int) else str(addr)

                functions.append(Radare2Function(
                    name=func_data.get("name", "unknown"),
                    offset=offset_str,
                    size=func_data.get("size", 0),
                    nbbs=func_data.get("nbbs", 0),
                    ninstrs=func_data.get("ninstrs", 0),
                    calltype=func_data.get("calltype", "unknown"),
                    edges=func_data.get("edges", 0),
                    cc=func_data.get("cc", 0)
                ))
            except (KeyError, TypeError) as e:
                logger.debug(f"Failed to parse function data: {e}")
                continue

        return functions

    def disassemble_function(self, address: str) -> Dict[str, Any]:
        """
        Disassemble entire function at address (pdfj - print disassembly function JSON).

        Args:
            address: Function address (hex string like "0x401000" or symbol name like "main")

        Returns:
            Function disassembly with: name, addr, size, ops (instructions), vars, etc.
        """
        # Sanitize address to prevent command injection
        address = self._sanitize_address(address)

        # Run analysis with pdfj to ensure analysis state is available
        # (each _execute_command spawns new radare2 process, so we need to re-analyze)
        if self.analysis_depth and self.analysis_depth != "":
            command = f"{self.analysis_depth}; pdfj @ {address}"
        else:
            command = f"pdfj @ {address}"

        return self._execute_command(command)

    def disassemble_at_address(
        self,
        address: str,
        count: int = 20,
        backward: int = 0
    ) -> List[Radare2DisasmInstruction]:
        """
        Disassemble instructions at address (pdj - print disassembly JSON).

        Args:
            address: Start address (hex string like "0x401000")
            count: Number of instructions forward (default: 20)
            backward: Number of instructions backward (default: 0)

        Returns:
            List of Radare2DisasmInstruction objects
        """
        # Sanitize address to prevent command injection
        address = self._sanitize_address(address)

        # Build command with backward support
        if backward > 0:
            # Disassemble backward and forward from address
            # pdj -N disassembles N instructions backward
            command = f"s {address}; pdj -{backward}; s {address}; pdj {count}"
        else:
            # Forward only
            command = f"s {address}; pdj {count}"

        result = self._execute_command(command)

        if "error" in result:
            return []

        if not isinstance(result, list):
            return []

        instructions = []
        for insn_data in result:
            try:
                instructions.append(Radare2DisasmInstruction(
                    offset=insn_data.get("offset", "0x0"),
                    opcode=insn_data.get("opcode", ""),
                    disasm=insn_data.get("disasm", ""),
                    type=insn_data.get("type", "unknown"),
                    esil=insn_data.get("esil"),
                    refs=insn_data.get("refs")
                ))
            except (KeyError, TypeError) as e:
                logger.debug(f"Failed to parse instruction data: {e}")
                continue

        return instructions

    def decompile_function(self, address: str) -> str:
        """
        Decompile function to pseudo-C code (pdd - print decompiled).

        Args:
            address: Function address (hex string or symbol name)

        Returns:
            Pseudo-C code as string, or error message
        """
        # Sanitize address to prevent command injection
        address = self._sanitize_address(address)

        result = self._execute_command(f"pdd @ {address}", json_output=False)

        if "error" in result:
            return f"Decompilation failed: {result['error']}"

        return result.get("raw_output", "")

    def get_xrefs_to(self, address: str) -> List[Dict[str, Any]]:
        """
        Get cross-references TO address (axtj - analyze xrefs to JSON).

        Args:
            address: Target address (hex string)

        Returns:
            List of xref dicts with: from, type (call, data, string, etc.)
        """
        # Sanitize address to prevent command injection
        address = self._sanitize_address(address)

        # Run analysis with axtj to ensure analysis state is available
        if self.analysis_depth and self.analysis_depth != "":
            command = f"{self.analysis_depth}; axtj @ {address}"
        else:
            command = f"axtj @ {address}"

        result = self._execute_command(command)

        if "error" in result:
            return []

        if isinstance(result, list):
            return result

        return []

    def get_xrefs_from(self, address: str) -> List[Dict[str, Any]]:
        """
        Get cross-references FROM address (axfj - analyze xrefs from JSON).

        Args:
            address: Source address (hex string)

        Returns:
            List of xref dicts with: to, type (call, data, string, etc.)
        """
        # Sanitize address to prevent command injection
        address = self._sanitize_address(address)

        # Run analysis with axfj to ensure analysis state is available
        if self.analysis_depth and self.analysis_depth != "":
            command = f"{self.analysis_depth}; axfj @ {address}"
        else:
            command = f"axfj @ {address}"

        result = self._execute_command(command)

        if "error" in result:
            return []

        if isinstance(result, list):
            return result

        return []

    def get_strings(self, min_length: int = 8) -> List[Dict[str, Any]]:
        """
        Get strings from binary (izzj - strings in JSON).

        Args:
            min_length: Minimum string length (default: 8)

        Returns:
            List of string dicts with: vaddr, paddr, length, size, string, type
        """
        # Get all strings, filter in Python (radare2 filter syntax unreliable across versions)
        result = self._execute_command("izzj")

        if "error" in result:
            return []

        if not isinstance(result, list):
            return []

        # Filter by minimum length in Python
        filtered = [s for s in result if s.get('length', 0) >= min_length]

        return filtered

    def get_imports(self) -> List[Dict[str, Any]]:
        """
        Get imported functions (iij - imports in JSON).

        Returns:
            List of import dicts with: name, plt (address), bind, type
        """
        result = self._execute_command("iij")

        if "error" in result:
            return []

        if isinstance(result, list):
            return result

        return []

    def get_exports(self) -> List[Dict[str, Any]]:
        """
        Get exported functions (iEj - exports in JSON).

        Returns:
            List of export dicts with: name, vaddr, paddr, bind, type
        """
        result = self._execute_command("iEj")

        if "error" in result:
            return []

        if isinstance(result, list):
            return result

        return []

    def get_call_graph(self, address: str) -> Dict[str, Any]:
        """
        Get function call graph (agcj - analyze graph calls JSON).

        Args:
            address: Function address (hex string or symbol name)

        Returns:
            Call graph with function call relationships
        """
        # Sanitize address to prevent command injection
        address = self._sanitize_address(address)

        # Run analysis with agcj to ensure analysis state is available
        if self.analysis_depth and self.analysis_depth != "":
            command = f"{self.analysis_depth}; agcj @ {address}"
        else:
            command = f"agcj @ {address}"

        return self._execute_command(command)

    def search_bytes(self, hex_bytes: str) -> List[Dict[str, Any]]:
        """
        Search for byte sequence (/ - search).

        Args:
            hex_bytes: Hex bytes to search (e.g., "4883ec08" for "sub rsp, 8")

        Returns:
            List of match locations with addresses
        """
        result = self._execute_command(f"/xj {hex_bytes}")

        if "error" in result:
            return []

        if isinstance(result, list):
            return result

        return []

    def analyze_function_complexity(self, address: str) -> Dict[str, Any]:
        """
        Analyze function complexity metrics.

        Args:
            address: Function address

        Returns:
            Dict with cyclomatic complexity, basic blocks, edges, etc.
        """
        func_info = self.disassemble_function(address)

        if "error" in func_info:
            return func_info

        return {
            "name": func_info.get("name", "unknown"),
            "address": func_info.get("addr", address),
            "size": func_info.get("size", 0),
            "instructions": len(func_info.get("ops", [])),
            "basic_blocks": func_info.get("nbbs", 0),
            "cyclomatic_complexity": func_info.get("cc", 0),
            "locals": len(func_info.get("vars", [])),
        }


def format_disassembly_text(instructions: List[Radare2DisasmInstruction]) -> str:
    """
    Format disassembly instructions as readable text (similar to objdump output).

    Args:
        instructions: List of Radare2DisasmInstruction objects

    Returns:
        Formatted disassembly string
    """
    lines = []
    for insn in instructions:
        # Format: 0x401000:  48 83 ec 08    sub    rsp, 0x8
        lines.append(f"{insn.offset}:  {insn.opcode:15s}  {insn.disasm}")

    return "\n".join(lines)


# Module-level check function for easy availability testing
def is_radare2_available(radare2_path: str = "radare2") -> bool:
    """Check if radare2 is available in PATH."""
    return shutil.which(radare2_path) is not None
