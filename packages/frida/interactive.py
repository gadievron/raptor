#!/usr/bin/env python3
"""
RAPTOR Interactive Frida Session

For manual app exploration with live instrumentation.
Start hooks, interact with the app, stop when done.

Usage:
    python3 interactive.py --target /path/to/app --goal "Find auth bypass"
    python3 interactive.py --attach 1234 --goal "Monitor network traffic"
    python3 interactive.py --attach "Safari" --goal "Capture credentials"
"""

import json
import sys
import signal
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging
import time

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import frida
except ImportError:
    print("✗ Frida not installed. Install with: pip install frida-tools")
    sys.exit(1)

try:
    from packages.llm_analysis.llm.client import LLMClient
except ImportError:
    LLMClient = None

from packages.frida.scanner import FridaScanner

logger = logging.getLogger("frida.interactive")


class InteractiveFridaSession:
    """
    Interactive Frida session for manual app exploration.

    Workflow:
    1. Start hooks (spawn or attach)
    2. User manually interacts with the application
    3. Hooks capture runtime behavior in real-time
    4. User stops when done exploring
    5. Generate findings report
    """

    def __init__(self, target: str, goal: str = "Monitor runtime behavior",
                 attach: bool = False, target_args: List[str] = None):
        """
        Initialize interactive session.

        Args:
            target: Binary path, process name, or PID
            goal: What to look for (guides hook generation)
            attach: True to attach to running process, False to spawn
            target_args: Arguments if spawning
        """
        self.target = target
        self.goal = goal
        self.attach_mode = attach
        self.target_args = target_args or []

        self.llm_client = LLMClient() if LLMClient else None
        self.scanner = FridaScanner()

        self.running = False
        self.findings: List[Dict] = []
        self.start_time = None
        self.finding_count = 0

        # For graceful shutdown
        self._shutdown_event = threading.Event()

    def _generate_hooks(self) -> str:
        """Generate Frida hooks based on goal using methodology engine."""
        if not self.llm_client:
            return self._default_hooks()

        # Use methodology-driven prompt
        try:
            from packages.frida.methodology import generate_methodology_prompt
            prompt = generate_methodology_prompt(self.goal, "interactive")
        except ImportError:
            # Fallback prompt
            prompt = f"""
Generate Frida JavaScript hooks for exploitation-focused security analysis.

GOAL: {self.goal}
MODE: Interactive (user manually explores the app)

EXPLOITATION MINDSET:
- What can be stolen? (credentials, keys, tokens)
- What can be corrupted? (memory, files, state)
- What can be controlled? (execution flow, data)
- What can be bypassed? (auth, validation, checks)

Generate hooks that work on ANY target (no app-specific assumptions).
Focus on exploitation primitives, not just logging.
"""

        prompt += """

INTERACTIVE MODE REQUIREMENTS:
- Hooks fire in real-time as user interacts with app
- Extract actual data that could be weaponized
- Rate by exploitability: critical/high/medium/low/info
- No app-specific assumptions

Use these helpers (already defined):
- findSymbol(name, preferredModule) - resolve function
- sendFinding(title, severity, details, data) - report finding
- log(msg, level) - debug logging

Generate ONLY JavaScript code. No markdown.
"""

        try:
            response = self.llm_client.generate(prompt)
            content = response.content

            # Extract code from response
            if '```' in content:
                start = content.find('```') + 3
                if content[start:start+10].startswith('javascript'):
                    start += 10
                elif content[start:start+2].startswith('js'):
                    start += 2
                end = content.find('```', start)
                code = content[start:end].strip()
            else:
                code = content.strip()

            logger.info(f"LLM generated {len(code)} bytes of hook code")
            return code

        except Exception as e:
            logger.warning(f"LLM hook generation failed: {e}, using defaults")
            return self._default_hooks()

    def _default_hooks(self) -> str:
        """Default hooks when LLM unavailable."""
        return """
// Default interactive hooks - monitoring common security-relevant APIs

// Network connections
try {
    var connect_ptr = findSymbol('connect', null);  // Let findSymbol search
    if (connect_ptr) {
        Interceptor.attach(connect_ptr, {
            onEnter: function(args) {
                var sockaddr = args[1];
                var family = sockaddr.readU16();
                if (family == 2) {  // AF_INET
                    var port = (sockaddr.add(2).readU8() << 8) | sockaddr.add(3).readU8();
                    var ip = sockaddr.add(4).readU8() + "." + sockaddr.add(5).readU8() + "." +
                             sockaddr.add(6).readU8() + "." + sockaddr.add(7).readU8();
                    sendFinding('Network Connection', 'info',
                        'Outbound connection detected', ip + ':' + port);
                }
            }
        });
        log('connect() hooked', 'info');
    }
} catch(e) { log('connect hook error: ' + e.message, 'error'); }

// File operations
try {
    var open_ptr = findSymbol('open', null);  // Cross-platform
    if (open_ptr) {
        Interceptor.attach(open_ptr, {
            onEnter: function(args) {
                var path = args[0].readUtf8String();
                if (path && (path.indexOf('password') !== -1 ||
                            path.indexOf('credential') !== -1 ||
                            path.indexOf('token') !== -1 ||
                            path.indexOf('secret') !== -1 ||
                            path.indexOf('.pem') !== -1 ||
                            path.indexOf('.key') !== -1)) {
                    sendFinding('Sensitive File Access', 'high',
                        'Access to potentially sensitive file', path);
                }
            }
        });
        log('open() hooked', 'info');
    }
} catch(e) { log('open hook error: ' + e.message, 'error'); }

// HTTP/Auth data in writes
try {
    var write_ptr = findSymbol('write', null);  // Cross-platform
    if (write_ptr) {
        Interceptor.attach(write_ptr, {
            onEnter: function(args) {
                var fd = args[0].toInt32();
                var len = args[2].toInt32();
                if (fd > 2 && len > 0 && len < 8192) {
                    try {
                        var data = args[1].readUtf8String(Math.min(len, 1000));
                        if (data) {
                            if (data.indexOf('Authorization:') !== -1) {
                                sendFinding('Auth Header Detected', 'high',
                                    'Authorization header in outbound data',
                                    data.substring(0, 500));
                            }
                            if (data.indexOf('password') !== -1 ||
                                data.indexOf('passwd') !== -1) {
                                sendFinding('Password in Transit', 'critical',
                                    'Password detected in data stream',
                                    data.substring(0, 500));
                            }
                        }
                    } catch(e) {}
                }
            }
        });
        log('write() hooked', 'info');
    }
} catch(e) { log('write hook error: ' + e.message, 'error'); }

log('Interactive hooks loaded - explore the app!', 'info');
"""

    def _build_full_script(self, hook_code: str) -> str:
        """Build complete Frida script with utilities + hooks."""
        return f"""
// RAPTOR Interactive Frida Session
// Goal: {self.goal}

// === UTILITIES ===
function log(msg, level) {{
    send({{ level: level || 'info', message: msg }});
}}

function sendFinding(title, severity, details, data) {{
    send({{
        type: 'finding',
        level: severity,
        title: title,
        details: details,
        data: data || null,
        timestamp: Date.now()
    }});
}}

function getExport(modName, funcName) {{
    try {{
        return Process.getModuleByName(modName).getExportByName(funcName);
    }} catch(e) {{ return null; }}
}}

// Platform detection
var PLATFORM = (function() {{
    var p = Process.platform;
    if (p === 'darwin') {{
        try {{ Module.findBaseAddress('UIKit'); return 'ios'; }}
        catch(e) {{ return 'macos'; }}
    }}
    if (p === 'linux') {{
        try {{ Module.findBaseAddress('libandroid_runtime.so'); return 'android'; }}
        catch(e) {{ return 'linux'; }}
    }}
    if (p === 'windows') return 'windows';
    return 'unknown';
}})();

var PLATFORM_LIBS = {{
    'linux': ['libc.so.6', 'libpthread.so.0', 'libdl.so.2', 'libssl.so'],
    'macos': ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libSystem.B.dylib'],
    'ios': ['libsystem_kernel.dylib', 'libsystem_c.dylib', 'libSystem.B.dylib'],
    'windows': ['ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'ws2_32.dll', 'msvcrt.dll'],
    'android': ['libc.so', 'libdl.so', 'libssl.so']
}};

function findSymbol(name, preferredModule) {{
    if (preferredModule) {{
        var ptr = getExport(preferredModule, name);
        if (ptr) return ptr;
    }}
    var libs = PLATFORM_LIBS[PLATFORM] || PLATFORM_LIBS['linux'];
    for (var i = 0; i < libs.length; i++) {{
        var ptr = getExport(libs[i], name);
        if (ptr) return ptr;
    }}
    try {{ return Module.findExportByName(null, name); }}
    catch(e) {{ return null; }}
}}

function findFunction(name) {{ return findSymbol(name, null); }}

log('RAPTOR Interactive Session Started', 'info');
log('Goal: {self.goal}', 'info');

// === HOOKS ===
{hook_code}
"""

    def _print_banner(self):
        """Print interactive session banner."""
        print("\n" + "="*60)
        print("  RAPTOR Interactive Frida Session")
        print("="*60)
        print(f"  Target: {self.target}")
        print(f"  Goal:   {self.goal}")
        print(f"  Mode:   {'Attach' if self.attach_mode else 'Spawn'}")
        print("="*60)
        print("\n  ► Hooks are active - interact with the application")
        print("  ► Findings will appear in real-time below")
        print("  ► Press ENTER to stop and generate report")
        print("  ► Press Ctrl+C to abort\n")
        print("-"*60)

    def _print_finding(self, finding: Dict):
        """Print a finding in real-time."""
        level = finding.get('level', 'info').upper()
        title = finding.get('title', 'Unknown')

        # Color codes
        colors = {
            'CRITICAL': '\033[91m',  # Red
            'HIGH': '\033[93m',      # Yellow
            'MEDIUM': '\033[94m',    # Blue
            'LOW': '\033[96m',       # Cyan
            'INFO': '\033[92m',      # Green
        }
        reset = '\033[0m'
        color = colors.get(level, '')

        self.finding_count += 1
        print(f"{color}[{level}] #{self.finding_count}: {title}{reset}")

        details = finding.get('details', '')
        if details:
            print(f"        {details[:80]}")

        data = finding.get('data')
        if data:
            data_str = str(data)[:100]
            print(f"        Data: {data_str}")

    def start(self) -> bool:
        """
        Start the interactive session.

        Returns:
            True if started successfully
        """
        print("\n[*] Generating hooks based on goal...")

        # Generate hooks
        hook_code = self._generate_hooks()
        full_script = self._build_full_script(hook_code)

        # Start Frida
        try:
            if self.attach_mode:
                print(f"[*] Attaching to: {self.target}")
                self.scanner.attach_to_process(self.target)
            else:
                print(f"[*] Spawning: {self.target}")
                self.scanner.spawn_process(self.target, self.target_args)

            # Load script
            print("[*] Loading hooks...")
            self.scanner.load_script(full_script, "interactive")

            # Resume if spawned
            if not self.attach_mode:
                self.scanner.resume_process()

            self.running = True
            self.start_time = time.time()
            return True

        except Exception as e:
            print(f"\n[!] Failed to start session: {e}")
            return False

    def wait_for_user(self):
        """Wait for user to finish exploring."""
        self._print_banner()

        try:
            input()  # Wait for Enter
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")

        self.stop()

    def stop(self):
        """Stop the session and generate report."""
        if not self.running:
            return

        print("\n" + "-"*60)
        print("[*] Stopping session...")

        self.running = False
        duration = time.time() - self.start_time if self.start_time else 0

        # Collect findings from scanner
        self.findings = self.scanner.findings.copy()

        # Detach
        try:
            self.scanner.detach()
        except:
            pass

        # Generate report
        self._generate_report(duration)

    def _generate_report(self, duration: float):
        """Generate findings report."""
        print("\n" + "="*60)
        print("  SESSION REPORT")
        print("="*60)
        print(f"  Duration: {duration:.1f} seconds")
        print(f"  Findings: {len(self.findings)}")
        print("="*60)

        if not self.findings:
            print("\n  No security findings captured.")
            print("  Try interacting with more features of the app.")
        else:
            # Group by severity
            by_severity = {'critical': [], 'high': [], 'medium': [], 'low': [], 'info': []}
            for f in self.findings:
                sev = f.get('level', 'info').lower()
                if sev in by_severity:
                    by_severity[sev].append(f)
                else:
                    by_severity['info'].append(f)

            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if by_severity[sev]:
                    print(f"\n  [{sev.upper()}] ({len(by_severity[sev])})")
                    for f in by_severity[sev][:5]:  # Show top 5 per category
                        print(f"    • {f.get('title', 'Unknown')}")
                        if f.get('data'):
                            print(f"      {str(f.get('data'))[:60]}")

        # Save full report
        self.scanner.findings = self.findings
        report_path = self.scanner.generate_report()
        print(f"\n  Full report: {report_path}")
        print("="*60 + "\n")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Interactive Frida Session - Manual App Exploration"
    )

    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--target', '-t',
                              help='Binary path to spawn')
    target_group.add_argument('--attach', '-a',
                              help='Process name or PID to attach to')

    parser.add_argument('--goal', '-g', default='Monitor security-relevant behavior',
                        help='What to look for (guides hook generation)')
    parser.add_argument('--args', nargs='*', default=[],
                        help='Arguments for spawned process')

    args = parser.parse_args()

    # Determine target and mode
    if args.attach:
        target = args.attach
        attach_mode = True
    else:
        target = args.target
        attach_mode = False

    # Create and run session
    session = InteractiveFridaSession(
        target=target,
        goal=args.goal,
        attach=attach_mode,
        target_args=args.args
    )

    if session.start():
        session.wait_for_user()

    return 0


if __name__ == "__main__":
    sys.exit(main())
