#!/usr/bin/env python3
"""
RAPTOR Crash Analyzer

Analyses crashes from fuzzing to extract exploitability information.
This is so much of a WIP, it's not even funny. However, you can see what we are trying to do and how it could be useful. 
"""

import subprocess
import os
import hashlib
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional
import platform

from core.logging import get_logger

logger = get_logger()


@dataclass
class CrashContext:
    """Complete context for a crash. The more information, the better for LLM analysis."""
    crash_id: str
    binary_path: Path
    input_file: Path
    signal: str

    # From debugger
    stack_trace: str = ""
    registers: Dict[str, str] = field(default_factory=dict)
    crash_instruction: str = ""
    crash_address: str = ""
    stack_hash: str = ""  # Hash of stack trace for deduplication

    # From disassembly
    disassembly: str = ""
    function_name: str = "unknown"
    source_location: str = ""  # file:line from addr2line

    # Binary information
    binary_info: Dict[str, str] = field(default_factory=dict)

    # Analysis results (filled by LLM)
    exploitability: str = "unknown"  # "exploitable", "likely", "unlikely", "not_exploitable"
    crash_type: str = "unknown"      # "heap_overflow", "stack_overflow", "null_deref", etc.
    cvss_estimate: float = 0.0
    analysis: Dict = field(default_factory=dict)

    # Generated artifacts
    exploit_code: Optional[str] = None


class CrashAnalyser:
    """Analyses crashes using debugger and LLM."""

    def __init__(self, binary_path: Path):
        self.binary = Path(binary_path).resolve()
        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        logger.info(f"Crash analyser initialized for: {self.binary}")
        
        # Check tool availability first
        self._available_tools = self._check_tool_availability()
        
        # Cache symbol information for better performance
        self._symbol_cache = self._load_symbol_table()
        self._debugger = self._detect_debugger()

    def _detect_debugger(self) -> str:
        """Detect the appropriate debugger for this platform and binary type."""
        system = platform.system().lower()
        
        # Check binary type first
        try:
            result = subprocess.run(
                ["file", str(self.binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            binary_type = result.stdout.lower()
        except:
            binary_type = ""
        
        # For macOS binaries (Mach-O), prefer LLDB
        if system == "darwin" or "mach-o" in binary_type:
            logger.info(f"Detected macOS/Mach-O binary, trying LLDB. Binary type: {binary_type[:100]}...")
            try:
                result = subprocess.run(["lldb", "--version"], capture_output=True, text=True, timeout=5)
                logger.info(f"LLDB version check result: {result.returncode}, stdout: {result.stdout[:100]}, stderr: {result.stderr[:100]}")
                if result.returncode == 0:
                    logger.info("Using LLDB debugger for macOS/Mach-O binary")
                    return "lldb"
            except Exception as e:
                logger.warning(f"LLDB version check failed: {e}")
            logger.warning("LLDB not available for macOS binary, this may not work well")
        
        # Default to gdb for Linux/Windows or if LLDB fails
        try:
            result = subprocess.run(["gdb", "--version"], capture_output=True, text=True, timeout=2)
            if result.returncode == 0:
                logger.info("Using GDB debugger")
                return "gdb"
        except:
            pass
            
        raise RuntimeError("No suitable debugger found (gdb or lldb)")

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which reverse engineering tools are available on the system. There are many more but this is a start."""
        tools = {
            "nm": "symbol table extraction",
            "addr2line": "address to source resolution", 
            "objdump": "disassembly",
            "readelf": "ELF header analysis",
            "file": "file type identification",
            "strings": "string extraction",
        }
        
        available = {}
        for tool, description in tools.items():
            try:
                result = subprocess.run(
                    [tool, "--version"], 
                    capture_output=True, 
                    text=True, 
                    timeout=2
                )
                available[tool] = result.returncode == 0
            except:
                available[tool] = False
                
        # Log availability
        available_tools = [tool for tool, avail in available.items() if avail]
        missing_tools = [tool for tool, avail in available.items() if not avail]
        
        if available_tools:
            logger.info(f"Available reverse engineering tools: {', '.join(available_tools)}")
        if missing_tools:
            logger.warning(f"Missing reverse engineering tools: {', '.join(missing_tools)}")
            
        return available

    def _load_symbol_table(self) -> Dict[str, str]:
        """Load symbol table from binary for address-to-function mapping."""
        symbols = {}
        
        if not self._available_tools.get("nm", False):
            logger.warning("nm not available - symbol table resolution will be limited")
            return symbols
        
        try:
            # Use nm to get symbol table
            result = subprocess.run(
                ["nm", "-C", str(self.binary)],  # -C demangles C++ symbols
                capture_output=True,
                text=True,
                timeout=10,
            )
            
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            addr = parts[0]
                            sym_type = parts[1]
                            name = " ".join(parts[2:])
                            
                            # Only keep function symbols (T/t for text section)
                            if sym_type in ["T", "t"] and addr.startswith("0"):
                                try:
                                    symbols[int(addr, 16)] = name
                                except ValueError:
                                    pass
                            
        except Exception as e:
            logger.debug(f"Failed to load symbol table with nm: {e}")
            
        logger.info(f"Loaded {len(symbols)} symbols from binary")
        return symbols

    def _resolve_address_to_function(self, address: str) -> str:
        """Resolve a hex address to function name using symbol table."""
        if not address or not address.startswith("0x"):
            return "unknown"
            
        try:
            addr_int = int(address, 16)
            
            # Find the closest symbol before this address
            closest_func = "unknown"
            closest_addr = 0
            
            for sym_addr, sym_name in self._symbol_cache.items():
                if sym_addr <= addr_int and sym_addr > closest_addr:
                    closest_addr = sym_addr
                    closest_func = sym_name
                    
            return closest_func
            
        except (ValueError, TypeError):
            return "unknown"

    def _resolve_address_with_addr2line(self, address: str) -> tuple[str, str]:
        """Use addr2line to resolve address to function and file:line."""
        if not self._available_tools.get("addr2line", False):
            logger.debug("addr2line not available - skipping address resolution")
            return "unknown", "unknown"
            
        if not address or not address.startswith("0x"):
            return "unknown", "unknown"
            
        try:
            result = subprocess.run(
                ["addr2line", "-f", "-C", "-e", str(self.binary), address],
                capture_output=True,
                text=True,
                timeout=5,
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                if len(lines) >= 2:
                    function = lines[0].strip()
                    file_line = lines[1].strip()
                    return function, file_line
                    
        except Exception as e:
            logger.debug(f"addr2line failed: {e}")
            
        return "unknown", "unknown"

    def analyse_crash(self, crash_id: str, input_file: Path, signal: str) -> CrashContext:
        """
        Analyse a crash to extract context.

        Args:
            crash_id: Unique crash identifier
            input_file: Input that triggered the crash
            signal: Signal that caused the crash

        Returns:
            CrashContext with extracted information
        """
        logger.info("=" * 70)
        logger.info(f"Analysing crash: {crash_id}")
        logger.info(f"  Signal: {signal}")
        logger.info(f"  Input: {input_file}")

        context = CrashContext(
            crash_id=crash_id,
            binary_path=self.binary,
            input_file=input_file,
            signal=signal,
        )

        # Get basic binary information
        try:
            context.binary_info = self._get_binary_info()
            logger.info("✓ Binary info extracted")
        except Exception as e:
            logger.error(f"✗ Binary info failed: {e}")

        # Check for ASan instrumentation
        has_asan = self._detect_asan_binary()
        if has_asan:
            logger.info("✓ ASan-instrumented binary detected - using enhanced diagnostics")
            context.binary_info["asan_enabled"] = "true"
            
            # Run ASan analysis for superior crash diagnostics
            try:
                asan_output = self._run_asan_analysis(input_file)
                if asan_output:
                    self._parse_asan_output(context, asan_output)
                    logger.info("✓ ASan diagnostics parsed")
                else:
                    logger.warning("ASan analysis produced no output")
            except Exception as e:
                logger.error(f"✗ ASan analysis failed: {e}")
        else:
            logger.info("ℹ️  Binary not ASan-instrumented - using debugger analysis")
            context.binary_info["asan_enabled"] = "false"

        # Run debugger analysis (fallback or complement to ASan)
        try:
            debugger_output = self._run_gdb_analysis(input_file)
            if self._debugger == "lldb":
                self._parse_lldb_output(context, debugger_output)
            else:
                self._parse_gdb_output(context, debugger_output)
            logger.info("✓ Debugger analysis complete")
        except Exception as e:
            logger.error(f"✗ Debugger analysis failed: {e}")

        # Get disassembly at crash site
        try:
            context.disassembly = self._get_disassembly(context.crash_address)
            logger.info("✓ Disassembly extracted")
        except Exception as e:
            logger.error(f"✗ Disassembly failed: {e}")

        # Get memory layout and protection information
        try:
            memory_info = self._get_memory_layout_info()
            context.binary_info.update(memory_info)
            logger.info("✓ Memory layout and protections analyzed")
        except Exception as e:
            logger.error(f"✗ Memory layout analysis failed: {e}")

        # Detect environmental crashes (debugger artifacts, etc.)
        try:
            env_info = self._detect_environmental_crash(context)
            context.binary_info.update(env_info)
            logger.info("✓ Environmental crash detection complete")
        except Exception as e:
            logger.error(f"✗ Environmental crash detection failed: {e}")

        # Analyze memory regions around crash address
        try:
            region_info = self._analyze_memory_regions(context)
            context.binary_info.update(region_info)
            logger.info("✓ Memory region analysis complete")
        except Exception as e:
            logger.error(f"✗ Memory region analysis failed: {e}")

        # Try to resolve function name if not found in backtrace
        if not context.function_name or context.function_name == "unknown":
            if context.crash_address:
                # Try addr2line first for most accurate result
                func_name, file_line = self._resolve_address_with_addr2line(context.crash_address)
                if func_name != "unknown":
                    context.function_name = func_name
                    context.source_location = file_line
                    logger.info(f"✓ Function resolved with addr2line: {func_name} at {file_line}")
                else:
                    # Fall back to symbol table
                    func_name = self._resolve_address_to_function(context.crash_address)
                    if func_name != "unknown":
                        context.function_name = func_name
                        logger.info(f"✓ Function resolved with symbols: {func_name}")
            
            # Also try to resolve using link register (lr) for return address
            if context.registers and "lr" in context.registers:
                lr_addr = context.registers["lr"]
                if lr_addr and lr_addr.startswith("0x"):
                    func_name, file_line = self._resolve_address_with_addr2line(lr_addr)
                    if func_name != "unknown" and func_name != context.function_name:
                        logger.info(f"✓ Return address resolved: {func_name} at {file_line}")
                        # Update source location if we found a better one
                        if not context.source_location or context.source_location == "unknown":
                            context.source_location = file_line

        # Log extracted information for debugging
        logger.info("Extracted crash information:")
        logger.info(f"  Signal: {context.signal}")
        logger.info(f"  Crash address: {context.crash_address}")
        logger.info(f"  Crash instruction: {context.crash_instruction}")
        logger.info(f"  Function: {context.function_name}")
        if context.source_location:
            logger.info(f"  Source location: {context.source_location}")
        logger.info(f"  Registers: {len(context.registers)} found")
        logger.info(f"  Stack trace: {len(context.stack_trace.split())} frames")
        logger.info(f"  Disassembly: {len(context.disassembly.split()) if context.disassembly else 0} lines")
        logger.info(f"  Binary info: {len(context.binary_info)} fields")
        
        # Log security-relevant information
        if context.binary_info.get("aslr_enabled") != "unknown":
            logger.info(f"  ASLR: {context.binary_info.get('aslr_enabled')}")
        if context.binary_info.get("stack_canaries") != "unknown":
            logger.info(f"  Stack canaries: {context.binary_info.get('stack_canaries')}")
        if context.binary_info.get("nx_enabled") != "unknown":
            logger.info(f"  NX/DEP: {context.binary_info.get('nx_enabled')}")
        if context.binary_info.get("environmental_crash") == "true":
            logger.info(f"  Environmental crash: {context.binary_info.get('reason', 'unknown')}")
        if context.binary_info.get("memory_region"):
            logger.info(f"  Memory region: {context.binary_info.get('memory_region')}")

        # Compute stack hash for deduplication
        context.stack_hash = self._compute_stack_hash(context.stack_trace)
        if context.stack_hash:
            logger.info(f"  Stack hash: {context.stack_hash}")

        return context

    def classify_crash_type(self, context: CrashContext) -> str:
        """
        Classify the type of crash based on available information.
        
        Args:
            context: Crash context with analysis results
            
        Returns:
            Crash type classification string
        """
        # Signal-based classification
        signal = context.signal.lower()
        if signal in ["11", "sigsegv", "segmentation fault"]:
            # Segmentation fault - analyze further
            memory_region = context.binary_info.get("memory_region", "").lower()
            
            if "heap" in memory_region or "malloc" in context.function_name.lower():
                return "heap_overflow"
            elif "stack" in memory_region or any(word in context.function_name.lower() for word in ["strcpy", "strcat", "gets", "sprintf"]):
                return "stack_overflow"
            elif "null" in memory_region or context.crash_address in ["0x0", "0x00000000"]:
                return "null_pointer_dereference"
            else:
                return "memory_access_violation"
                
        elif signal in ["6", "sigabrt", "abort"]:
            # Abort signal - could be ASan, assert, or double-free
            if context.binary_info.get("asan_enabled") == "true":
                return "asan_detected_bug"
            elif "free" in context.function_name.lower() or "double free" in context.stack_trace.lower():
                return "double_free"
            else:
                return "abort_signal"
                
        elif signal in ["8", "sigfpe", "floating point exception"]:
            return "arithmetic_error"
            
        elif signal in ["4", "sigill", "illegal instruction"]:
            return "illegal_instruction"
            
        elif signal in ["13", "sigpipe", "broken pipe"]:
            return "broken_pipe"
            
        elif signal in ["10", "sigbus", "bus error"]:
            return "bus_error"
            
        # Function name based classification
        func_name = context.function_name.lower()
        if any(word in func_name for word in ["malloc", "free", "realloc", "calloc"]):
            return "heap_corruption"
        elif any(word in func_name for word in ["strcpy", "strcat", "strncpy", "memcpy", "memmove"]):
            return "buffer_overflow"
        elif "printf" in func_name or "format" in func_name:
            return "format_string_vulnerability"
            
        # Stack trace based classification
        stack_lower = context.stack_trace.lower()
        if "heap" in stack_lower and "overflow" in stack_lower:
            return "heap_overflow"
        elif "stack" in stack_lower and "overflow" in stack_lower:
            return "stack_overflow"
        elif "use after free" in stack_lower or "double free" in stack_lower:
            return "use_after_free"
            
        # Default classification
        return "unknown_crash"

    def _run_gdb_analysis(self, input_file: Path) -> str:
        """Run debugger to analyze crash."""
        if self._debugger == "lldb":
            return self._run_lldb_analysis(input_file)
        else:
            return self._run_gdb_analysis_internal(input_file)

    def _run_gdb_analysis_internal(self, input_file: Path) -> str:
        """Run GDB to analyze crash."""
        # GDB commands to extract crash information
        gdb_commands = [
            "set pagination off",
            "set confirm off",
            "set print pretty on",
            "handle SIGTRAP stop",  # Stop on traps
            "handle SIGSEGV stop",  # Stop on segfaults
            "handle SIGABRT stop",  # Stop on aborts
            "handle SIGBUS stop",   # Stop on bus errors
            "handle SIGILL stop",   # Stop on illegal instructions
            "handle SIGFPE stop",   # Stop on floating point exceptions
            f"run < '{input_file}'",  # Run with input (quoted for paths with spaces)
            "info registers",       # Get register state
            "backtrace full",       # Get full backtrace
            "x/10i $pc",           # Examine instructions at PC
            "x/20xw $sp",          # Examine stack
            "quit",
        ]

        # Write commands to temporary file (with delete=False to keep it during execution)
        with tempfile.NamedTemporaryFile(mode='w', suffix='_gdb_commands.txt', delete=False) as cmd_f:
            cmd_file = Path(cmd_f.name)
            cmd_f.write("\n".join(gdb_commands))

        try:
            # Run GDB
            result = subprocess.run(
                ["gdb", "-batch", "-x", str(cmd_file), str(self.binary)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        finally:
            # Clean up command file
            try:
                cmd_file.unlink()
            except:
                pass

        # Debug: save GDB output for inspection (using proper temp file)
        with tempfile.NamedTemporaryFile(mode='w', suffix=f'_gdb_{input_file.name}.txt', delete=False) as debug_f:
            debug_file = Path(debug_f.name)
            debug_f.write(result.stdout + "\n--- STDERR ---\n" + result.stderr)

        # Log a summary of what we got
        logger.debug(f"GDB output saved to {debug_file}")
        if result.stdout:
            logger.debug(f"GDB stdout length: {len(result.stdout)} chars")
        if result.stderr:
            logger.debug(f"GDB stderr length: {len(result.stderr)} chars")

        return result.stdout

    def _run_lldb_analysis(self, input_file: Path) -> str:
        """Run LLDB to analyze crash (macOS)."""
        # Create temp files for LLDB stdout/stderr
        lldb_out = tempfile.NamedTemporaryFile(mode='w', suffix='_lldb_out.txt', delete=False)
        lldb_err = tempfile.NamedTemporaryFile(mode='w', suffix='_lldb_err.txt', delete=False)
        lldb_out.close()
        lldb_err.close()

        # LLDB commands - different syntax from GDB
        lldb_commands = [
            "settings set auto-confirm true",
            "process handle SIGTRAP -s true -n true",  # Stop on traps
            "process handle SIGSEGV -s true -n true",  # Stop on segfaults
            "process handle SIGABRT -s true -n true",  # Stop on aborts
            "process handle SIGBUS -s true -n true",   # Stop on bus errors
            "process handle SIGILL -s true -n true",   # Stop on illegal instructions
            "process handle SIGFPE -s true -n true",   # Stop on floating point exceptions
            f"process launch -i {input_file} -o {lldb_out.name} -e {lldb_err.name}",  # Run with input
            "register read",                   # Get register state
            "thread backtrace --extended true", # Get full backtrace
            "disassemble --count 10 --start-address $pc",  # Examine instructions at PC
            "memory read --size 4 --format x --count 20 $sp",  # Examine stack
            "process kill",  # Make sure process is killed
            "quit",
        ]

        # Write commands to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='_lldb_commands.txt', delete=False) as cmd_f:
            cmd_file = Path(cmd_f.name)
            cmd_f.write("\n".join(lldb_commands))

        try:
            # Run LLDB with longer timeout
            try:
                result = subprocess.run(
                    ["lldb", "-s", str(cmd_file), str(self.binary)],
                    capture_output=True,
                    text=True,
                    timeout=60,  # Increased timeout
                )
            except subprocess.TimeoutExpired:
                logger.warning("LLDB analysis timed out - trying fallback approach")
                # Clean up temp files before fallback
                try:
                    Path(lldb_out.name).unlink()
                    Path(lldb_err.name).unlink()
                except:
                    pass
                return self._run_lldb_fallback(input_file)

            # Debug: save LLDB output for inspection
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'_lldb_{input_file.name}.txt', delete=False) as debug_f:
                debug_file = Path(debug_f.name)
                debug_f.write(result.stdout + "\n--- STDERR ---\n" + result.stderr)

            # Log a summary of what we got
            logger.debug(f"LLDB output saved to {debug_file}")
            if result.stdout:
                logger.debug(f"LLDB stdout length: {len(result.stdout)} chars")
            if result.stderr:
                logger.debug(f"LLDB stderr length: {len(result.stderr)} chars")

            return result.stdout
        finally:
            # Clean up temp files
            try:
                cmd_file.unlink()
                Path(lldb_out.name).unlink()
                Path(lldb_err.name).unlink()
            except:
                pass

    def _run_lldb_fallback(self, input_file: Path) -> str:
        """Fallback LLDB analysis with simpler commands."""
        logger.info("Using simplified LLDB analysis")

        # Simpler commands that should complete faster
        lldb_commands = [
            "settings set auto-confirm true",
            f"process launch -i {input_file}",  # LLDB syntax for stdin input
            "bt",  # Simple backtrace
            "register read",  # Registers
            "quit",
        ]

        # Write commands to temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='_lldb_fallback.txt', delete=False) as cmd_f:
            cmd_file = Path(cmd_f.name)
            cmd_f.write("\n".join(lldb_commands))

        try:
            result = subprocess.run(
                ["lldb", "-b", "-s", str(cmd_file), str(self.binary)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.error("LLDB fallback also timed out")
            return "LLDB analysis failed: timeout"
        finally:
            # Clean up temp file
            try:
                cmd_file.unlink()
            except:
                pass

    def _parse_lldb_output(self, context: CrashContext, lldb_output: str) -> None:
        """Parse LLDB output to extract crash information."""
        lines = lldb_output.split("\n")
        
        # First, try to detect the signal that caused the stop
        for line in lines:
            if "stop reason = signal" in line:
                # Extract signal name
                if "SIGSEGV" in line:
                    context.signal = "11"
                elif "SIGABRT" in line:
                    context.signal = "06"
                elif "SIGILL" in line:
                    context.signal = "04"
                elif "SIGFPE" in line:
                    context.signal = "08"
                elif "SIGTRAP" in line:
                    context.signal = "05"
                elif "SIGBUS" in line:
                    context.signal = "07"
                break
            elif "stop reason = EXC_BREAKPOINT" in line:
                # macOS exception for breakpoint (SIGTRAP)
                context.signal = "05"
                break

        # Extract registers (LLDB format: register read output)
        in_registers = False
        for line in lines:
            if "register read" in line.lower() or in_registers:
                in_registers = True
                # LLDB register format: "    x0 = 0x0000000000000000"
                if " = 0x" in line and not line.startswith("General Purpose Registers"):
                    parts = line.strip().split(" = ")
                    if len(parts) == 2:
                        reg_name = parts[0].strip()
                        reg_value = parts[1].strip()
                        context.registers[reg_name] = reg_value
                elif "thread backtrace" in line.lower():
                    in_registers = False

        # Extract stack trace (LLDB format)
        in_backtrace = False
        backtrace_lines = []
        for line in lines:
            if "thread backtrace" in line.lower() or "* thread #" in line:
                in_backtrace = True
            if in_backtrace:
                if line.strip().startswith("*") or line.strip().startswith("frame #"):
                    backtrace_lines.append(line.strip())
                elif "disassemble" in line.lower():
                    break

        context.stack_trace = "\n".join(backtrace_lines)

        # Extract crash instruction and address from disassembly
        crash_instruction_found = False
        for line in lines:
            if "->" in line and "0x" in line and not crash_instruction_found:
                context.crash_instruction = line.strip()
                # Extract address
                if "0x" in line:
                    addr_start = line.index("0x")
                    addr_end = addr_start + 18
                    addr_part = line[addr_start:addr_end].split()[0]
                    if addr_part.startswith("0x"):
                        context.crash_address = addr_part
                crash_instruction_found = True
                logger.debug(f"Found crash instruction: {context.crash_instruction}")

        # If no crash instruction found, try to find PC register value
        if not context.crash_address and context.registers:
            pc_reg = context.registers.get("pc") or context.registers.get("rip")
            if pc_reg and pc_reg.startswith("0x"):
                context.crash_address = pc_reg
                context.crash_instruction = f"PC at crash: {pc_reg}"

        # Extract additional disassembly
        disassembly_lines = []
        in_disassembly = False
        for line in lines:
            if "disassemble" in line.lower():
                in_disassembly = True
                continue
            elif in_disassembly and line.strip() and "0x" in line and ":" in line:
                disassembly_lines.append(line.strip())
                if len(disassembly_lines) >= 10:
                    break

        if disassembly_lines and not context.disassembly:
            context.disassembly = "\n".join(disassembly_lines)

        # Try to extract function name from backtrace
        if backtrace_lines:
            for line in backtrace_lines:
                if "`" in line and "(" in line:
                    func_part = line.split("`")[1].split("(")[0].strip()
                    context.function_name = func_part
                    
                    # Extract source location if available
                    if " at " in line and ".c:" in line or ".cpp:" in line:
                        source_part = line.split(" at ")[1].split()[0].strip()
                        context.source_location = source_part
                        logger.info(f"✓ Source location extracted from backtrace: {source_part}")
                    break
                # Alternative format without backticks
                elif " in " in line:
                    func_part = line.split(" in ")[1]
                    context.function_name = func_part.split()[0].split("(")[0].strip()
                    break

    def _parse_gdb_output(self, context: CrashContext, gdb_output: str) -> None:
        """Parse GDB output to extract crash information."""
        lines = gdb_output.split("\n")
        
        # First, try to detect the signal that caused the stop
        for line in lines:
            if "Program received signal" in line:
                # Extract signal number and name
                if "SIGSEGV" in line:
                    context.signal = "11"
                elif "SIGABRT" in line:
                    context.signal = "06"
                elif "SIGILL" in line:
                    context.signal = "04"
                elif "SIGFPE" in line:
                    context.signal = "08"
                elif "SIGTRAP" in line:
                    context.signal = "05"
                elif "SIGBUS" in line:
                    context.signal = "07"
                elif "SIGUSR1" in line:
                    context.signal = "10"
                elif "SIGUSR2" in line:
                    context.signal = "12"
                elif "SIGPIPE" in line:
                    context.signal = "13"
                elif "SIGALRM" in line:
                    context.signal = "14"
                elif "SIGTERM" in line:
                    context.signal = "15"
                break

        # Extract registers
        in_registers = False
        for line in lines:
            if "info registers" in line.lower() or in_registers:
                in_registers = True
                if "=" in line and any(reg in line for reg in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp", "rip"]):
                    parts = line.split()
                    if len(parts) >= 2:
                        reg_name = parts[0]
                        reg_value = parts[1]
                        context.registers[reg_name] = reg_value
                elif "backtrace" in line.lower():
                    in_registers = False

        # Extract stack trace
        in_backtrace = False
        backtrace_lines = []
        for line in lines:
            if "backtrace" in line.lower() or "#0" in line:
                in_backtrace = True
            if in_backtrace:
                if line.strip().startswith("#"):
                    backtrace_lines.append(line.strip())
                elif "quit" in line.lower():
                    break

        context.stack_trace = "\n".join(backtrace_lines)

        # Extract crash instruction and address
        crash_instruction_found = False
        for line in lines:
            if "=>" in line and "0x" in line and not crash_instruction_found:
                context.crash_instruction = line.strip()
                # Extract address
                if "0x" in line:
                    addr_start = line.index("0x")
                    addr_end = addr_start + 18  # Allow for longer addresses
                    addr_part = line[addr_start:addr_end].split()[0]
                    if addr_part.startswith("0x"):
                        context.crash_address = addr_part
                crash_instruction_found = True
                logger.debug(f"Found crash instruction: {context.crash_instruction}")

        # If no crash instruction found with =>, try to find it from disassembly
        if not crash_instruction_found:
            for line in lines:
                if "0x" in line and any(instr in line.lower() for instr in ["mov", "call", "jmp", "ret", "push", "pop", "add", "sub", "cmp"]):
                    # Look for lines that look like disassembly
                    if ":" in line and not line.startswith("(gdb)"):
                        context.crash_instruction = line.strip()
                        # Extract address
                        if "0x" in line:
                            addr_start = line.index("0x")
                            addr_end = addr_start + 18
                            addr_part = line[addr_start:addr_end].split()[0]
                            if addr_part.startswith("0x"):
                                context.crash_address = addr_part
                        crash_instruction_found = True
                        logger.debug(f"Found crash instruction from disassembly: {context.crash_instruction}")
                        break

        # If no crash instruction found, try to find PC/RIP register value
        if not context.crash_address and context.registers:
            pc_reg = context.registers.get("rip") or context.registers.get("pc") or context.registers.get("eip")
            if pc_reg and pc_reg.startswith("0x"):
                context.crash_address = pc_reg
                context.crash_instruction = f"PC/RIP at crash: {pc_reg}"

        # Extract additional disassembly from x/10i $pc output
        disassembly_lines = []
        in_disassembly = False
        for line in lines:
            if "=>" in line and "0x" in line:
                in_disassembly = True
                continue
            elif in_disassembly and line.strip() and not line.startswith("(gdb)") and "0x" in line:
                disassembly_lines.append(line.strip())
                if len(disassembly_lines) >= 10:  # Limit to 10 instructions
                    break

        if disassembly_lines and not context.disassembly:
            context.disassembly = "\n".join(disassembly_lines)

        # Try to extract function name from backtrace
        if backtrace_lines:
            first_frame = backtrace_lines[0]
            if "in " in first_frame:
                func_part = first_frame.split("in ")[1]
                context.function_name = func_part.split()[0].split("(")[0].strip()  # Handle function(args)
            elif "@" in first_frame:  # Alternative format
                func_part = first_frame.split("@")[0].strip()
                context.function_name = func_part

    def _get_disassembly(self, address: str, num_instructions: int = 20) -> str:
        """Get disassembly around crash address using objdump."""
        if not self._available_tools.get("objdump", False):
            logger.debug("objdump not available - skipping disassembly")
            return "Disassembly unavailable: objdump tool not found"
            
        if not address or address in ("unknown", ""):
            return "No crash address available for disassembly"

        try:
            # Use objdump for simple disassembly with more context
            result = subprocess.run(
                ["objdump", "-d", "--start-address=" + address, "-C", str(self.binary)],  # -C demangles
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return f"Disassembly failed: objdump returned {result.returncode}"

            lines = result.stdout.split("\n")
            # Take first N instructions, but skip header lines
            disasm_lines = []
            in_disassembly = False
            
            for line in lines:
                if "<" in line and ">" in line:  # Function start marker
                    in_disassembly = True
                    continue
                elif in_disassembly and ":" in line and any(c in line for c in ["<", ">", "mov", "call", "jmp", "ret", "push", "pop"]):
                    disasm_lines.append(line.strip())
                    if len(disasm_lines) >= num_instructions:
                        break
                        
            if disasm_lines:
                return "\n".join(disasm_lines)
            else:
                return "No disassembly instructions found"

        except Exception as e:
            logger.debug(f"Disassembly failed: {e}")
            return f"Disassembly unavailable: {e}"

    def _get_binary_info(self) -> Dict[str, str]:
        """Get basic information about the binary."""
        info = {}
        
        if self._available_tools.get("file", False):
            try:
                # Get file type
                result = subprocess.run(
                    ["file", str(self.binary)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    info["file_type"] = result.stdout.strip()
                    
            except Exception as e:
                logger.debug(f"file command failed: {e}")
        else:
            logger.debug("file tool not available - skipping binary type detection")
        
        if self._available_tools.get("readelf", False):
            try:
                # Get ELF header info (will work for ELF binaries, may fail for Mach-O)
                result = subprocess.run(
                    ["readelf", "-h", str(self.binary)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    info["elf_header"] = result.stdout.strip()
                    
            except Exception as e:
                logger.debug(f"readelf failed: {e}")
        else:
            logger.debug("readelf tool not available - skipping ELF header analysis")
            
        return info

    def _get_memory_layout_info(self) -> Dict[str, str]:
        """Get information about memory layout and protections."""
        info = {}
        
        try:
            # Check ASLR status
            result = subprocess.run(
                ["sysctl", "kern.aslr"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                info["aslr_enabled"] = "1" in result.stdout
            else:
                # Try Linux way
                result = subprocess.run(
                    ["cat", "/proc/sys/kernel/randomize_va_space"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    aslr_level = result.stdout.strip()
                    info["aslr_enabled"] = aslr_level != "0"
                    info["aslr_level"] = aslr_level
        except:
            info["aslr_enabled"] = "unknown"
            
        # Check if binary has stack canaries
        try:
            result = subprocess.run(
                ["objdump", "-d", str(self.binary)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "__stack_chk_fail" in result.stdout or "__chk_fail" in result.stdout:
                info["stack_canaries"] = "enabled"
            else:
                info["stack_canaries"] = "not_detected"
        except:
            info["stack_canaries"] = "unknown"
            
        # Check for NX/DEP
        try:
            result = subprocess.run(
                ["otool", "-hv", str(self.binary)],  # macOS
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "NOUNDEFS" in result.stdout or "NO_HEAP_EXECUTION" in result.stdout:
                info["nx_enabled"] = "enabled"
            else:
                info["nx_enabled"] = "not_detected"
        except:
            try:
                # Try Linux way
                result = subprocess.run(
                    ["readelf", "-l", str(self.binary)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if "GNU_STACK" in result.stdout and "RWE" not in result.stdout:
                    info["nx_enabled"] = "enabled"
                else:
                    info["nx_enabled"] = "not_detected"
            except:
                info["nx_enabled"] = "unknown"
                
        return info

    def _detect_environmental_crash(self, context: CrashContext) -> Dict[str, str]:
        """Detect if crash is environmental (debugger artifacts, etc.)."""
        info = {"environmental_crash": "false", "reason": ""}
        
        # Check for SIGTRAP which could be debugger breakpoint
        if context.signal == "05":  # SIGTRAP
            # Look for debugger-related patterns in disassembly
            if context.disassembly:
                disassembly_lower = context.disassembly.lower()
                if "int3" in disassembly_lower or "breakpoint" in disassembly_lower:
                    info["environmental_crash"] = "true"
                    info["reason"] = "debugger_breakpoint"
                elif "trap" in disassembly_lower and "invalid" in disassembly_lower:
                    info["environmental_crash"] = "true"
                    info["reason"] = "invalid_trap_instruction"
                    
        # Check for crashes in debugger/library code
        if context.stack_trace:
            stack_lower = context.stack_trace.lower()
            if any(lib in stack_lower for lib in ["gdb", "lldb", "valgrind", "asan", "ubsan"]):
                info["environmental_crash"] = "true"
                info["reason"] = "debugger_or_sanitizer_artifact"

        # Check for sanitizer crashes only (NOT library functions like malloc/strcpy)
        # NOTE: Crashes in malloc/free/strcpy/memcpy are often EXPLOITABLE (heap overflow, UAF, etc.)
        # and should NOT be marked as environmental
        if context.function_name and any(sanitizer in context.function_name.lower() for sanitizer in [
            "__asan", "__ubsan", "__lsan", "__tsan", "__msan", "__hwasan"
        ]):
            info["environmental_crash"] = "true"
            info["reason"] = "sanitizer_artifact"

        return info

    def _analyze_memory_regions(self, context: CrashContext) -> Dict[str, str]:
        """Analyze memory regions around crash address."""
        info = {}
        
        if not context.crash_address or not context.crash_address.startswith("0x"):
            return info
            
        try:
            crash_addr = int(context.crash_address, 16)
            
            # Check if address is in typical memory regions
            if crash_addr < 0x1000:
                info["memory_region"] = "null_page"
                info["region_analysis"] = "crash_in_null_page_region"
            elif crash_addr < 0x100000:
                info["memory_region"] = "low_memory"
                info["region_analysis"] = "crash_in_low_memory_region"
            elif crash_addr >= 0x7f0000000000 and crash_addr < 0x800000000000:  # Linux mmap region
                info["memory_region"] = "mmap_region"
                info["region_analysis"] = "crash_in_mmap_allocated_region"
            elif crash_addr >= 0x555555554000 and crash_addr < 0x555555558000:  # Common PIE base
                info["memory_region"] = "pie_base"
                info["region_analysis"] = "crash_in_position_independent_executable_region"
            else:
                info["memory_region"] = "unknown"
                info["region_analysis"] = "crash_address_in_unknown_memory_region"
                
            # Check for heap/stack patterns
            if context.registers:
                sp = context.registers.get("rsp") or context.registers.get("sp")
                bp = context.registers.get("rbp") or context.registers.get("fp")
                
                if sp and sp.startswith("0x"):
                    sp_addr = int(sp, 16)
                    if abs(crash_addr - sp_addr) < 0x10000:  # Within 64KB of stack
                        info["relative_to_stack"] = "near_stack_pointer"
                        
                if bp and bp.startswith("0x"):
                    bp_addr = int(bp, 16)
                    if abs(crash_addr - bp_addr) < 0x10000:  # Within 64KB of frame
                        info["relative_to_frame"] = "near_frame_pointer"
                        
        except (ValueError, TypeError):
            pass

        return info

    def _compute_stack_hash(self, stack_trace: str) -> str:
        """
        Compute hash of stack trace for deduplication.

        Extracts function names and addresses from stack trace and hashes them.
        This allows deduplication of crashes with the same root cause.

        Args:
            stack_trace: Raw stack trace string from debugger

        Returns:
            Hex hash string (first 16 chars), or empty string if no stack trace
        """
        if not stack_trace:
            return ""

        # Extract function names from stack trace (ignore addresses for better deduplication)
        # Format: #0  0xaddress in function_name (args) at file:line
        import re

        functions = []
        for line in stack_trace.split('\n'):
            # Match GDB format: #N  0xADDR in function_name
            match = re.search(r'in\s+([^\s(]+)', line)
            if match:
                functions.append(match.group(1))
            # Also match LLDB format: frame #N: 0xADDR function_name
            elif 'frame' in line.lower():
                parts = line.split()
                if len(parts) >= 3:
                    # Take the part after the address
                    for i, part in enumerate(parts):
                        if part.startswith('0x') and i + 1 < len(parts):
                            functions.append(parts[i + 1].split('(')[0])
                            break

        if not functions:
            # Fallback: hash the entire stack trace
            return hashlib.sha256(stack_trace.encode()).hexdigest()[:16]

        # Hash the function names (top 10 frames to avoid overly specific hashes)
        stack_signature = '|'.join(functions[:10])
        return hashlib.sha256(stack_signature.encode()).hexdigest()[:16]

    def _detect_asan_binary(self) -> bool:
        """Detect if binary was compiled with AddressSanitizer."""
        try:
            # Check for ASan symbols
            result = subprocess.run(
                ["nm", str(self.binary)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            asan_symbols = [
                "__asan_", "__sanitizer", "_ZN6__asan", 
                "__asan_report", "__asan_handle"
            ]
            for symbol in asan_symbols:
                if symbol in result.stdout:
                    return True
                    
            # Check for ASan runtime library dependencies
            result = subprocess.run(
                ["otool", "-L", str(self.binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "libclang_rt.asan" in result.stdout or "asan" in result.stdout.lower():
                return True
                
        except Exception as e:
            logger.debug(f"ASan detection failed: {e}")
            
        return False

    def _run_asan_analysis(self, input_file: Path) -> str:
        """Run ASan-instrumented binary to get detailed crash diagnostics."""
        logger.info("Running ASan analysis for enhanced diagnostics")
        
        try:
            # Run the binary with the crash input
            result = subprocess.run(
                [str(self.binary), str(input_file)],
                capture_output=True,
                text=True,
                timeout=30,
                env={**os.environ, "ASAN_OPTIONS": "abort_on_error=0:print_stacktrace=1"},
            )
            
            # Combine stdout and stderr (ASan reports to stderr)
            asan_output = result.stdout + "\n" + result.stderr
            
            if "AddressSanitizer" in asan_output or "runtime error" in asan_output:
                logger.info("✓ ASan diagnostics captured")
                return asan_output
            else:
                logger.debug("No ASan output detected")
                return ""
                
        except subprocess.TimeoutExpired:
            logger.warning("ASan analysis timed out")
            return "ASan analysis timed out"
        except Exception as e:
            logger.debug(f"ASan analysis failed: {e}")
            return f"ASan analysis failed: {e}"

    def _parse_asan_output(self, context: CrashContext, asan_output: str) -> None:
        """Parse ASan output for enhanced crash information."""
        if not asan_output or "AddressSanitizer" not in asan_output:
            return
            
        logger.info("Parsing ASan diagnostics")
        
        # Extract error type
        if "heap-buffer-overflow" in asan_output:
            context.crash_type = "heap_buffer_overflow"
        elif "stack-buffer-overflow" in asan_output:
            context.crash_type = "stack_buffer_overflow"
        elif "use-after-free" in asan_output:
            context.crash_type = "use_after_free"
        elif "double-free" in asan_output:
            context.crash_type = "double_free"
        elif "memory leak" in asan_output:
            context.crash_type = "memory_leak"
            
        # Extract stack trace (ASan provides excellent stack traces)
        lines = asan_output.split("\n")
        in_stack_trace = False
        stack_trace_lines = []
        
        for line in lines:
            if "#0 " in line and " in " in line:  # Start of stack trace
                in_stack_trace = True
                
            if in_stack_trace:
                if line.strip() and not line.startswith("=="):
                    stack_trace_lines.append(line.strip())
                elif line.startswith("=="):  # End of ASan report
                    break
                    
        if stack_trace_lines:
            context.stack_trace = "\n".join(stack_trace_lines)
            logger.info("✓ Enhanced stack trace from ASan")
            
        # Store ASan output in binary_info for LLM analysis
        context.binary_info["asan_output"] = asan_output[:2000]  # Truncate if too long
        """Heuristically classify crash type based on available information."""
        # Simple heuristics based on signal and crash info
        if context.signal == "11":  # SIGSEGV
            if "rsp" in context.registers and "rip" in context.registers:
                rsp = context.registers.get("rsp", "")
                rip = context.registers.get("rip", "")

                if rsp and "0x00000" in rsp:
                    return "null_pointer_dereference"
                elif "call" in context.crash_instruction.lower():
                    return "call_to_invalid_address"
                else:
                    return "memory_access_violation"

        elif context.signal == "06":  # SIGABRT
            if "malloc" in context.stack_trace or "free" in context.stack_trace:
                return "heap_corruption"
            else:
                return "assertion_failure"

        elif context.signal == "04":  # SIGILL
            return "invalid_instruction"

        elif context.signal == "08":  # SIGFPE
            return "arithmetic_error"

        elif context.signal == "05":  # SIGTRAP
            if context.crash_instruction and ("int3" in context.crash_instruction.lower() or "breakpoint" in context.crash_instruction.lower()):
                return "debug_breakpoint"
            elif context.stack_trace and "assert" in context.stack_trace.lower():
                return "assertion_failure"
            elif context.stack_trace and ("sanitizer" in context.stack_trace.lower() or "asan" in context.stack_trace.lower()):
                return "sanitizer_violation"
            elif "__chk_fail" in context.stack_trace or "buffer overflow" in str(context.registers):
                return "stack_buffer_overflow"
            else:
                return "trap_signal"

        elif context.signal == "07":  # SIGBUS
            return "bus_error"

        elif context.signal == "10":  # SIGUSR1
            return "user_signal"

        elif context.signal == "12":  # SIGUSR2
            return "user_signal"

        elif context.signal == "13":  # SIGPIPE
            return "broken_pipe"

        elif context.signal == "14":  # SIGALRM
            return "alarm_timeout"

        elif context.signal == "15":  # SIGTERM
            return "termination_signal"

        # Fallback classification based on crash instruction or stack trace
        if context.crash_instruction:
            instr = context.crash_instruction.lower()
            if "div" in instr and ("zero" in instr or "/ 0" in instr):
                return "division_by_zero"
            elif "int3" in instr or "breakpoint" in instr:
                return "debug_breakpoint"
            elif "call" in instr and ("0x0" in instr or "null" in instr):
                return "call_to_null"

        if context.stack_trace:
            trace = context.stack_trace.lower()
            if "sanitizer" in trace or "asan" in trace:
                return "sanitizer_violation"
            elif "assert" in trace:
                return "assertion_failure"
            elif "malloc" in trace or "free" in trace:
                return "heap_issue"

        return "unknown_crash_type"
