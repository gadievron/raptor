#!/usr/bin/env python3
"""
RAPTOR Frida Dynamic Instrumentation Scanner

Features:
- Attach to running processes or spawn new ones
- Load custom Frida scripts or use built-in templates
- API hooking, SSL unpinning, memory analysis
- LLM-powered analysis of runtime behavior
- Integration with RAPTOR reporting

Usage:
    python3 scanner.py --target <pid|process_name|binary_path> [options]
    python3 scanner.py --spawn /path/to/binary [options]
    python3 scanner.py --attach 1234 --script custom.js
    python3 scanner.py --target com.example.app --template ssl-unpin
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

try:
    import frida
except ImportError:
    print("✗ Frida not installed. Install with: pip install frida-tools")
    sys.exit(1)

# Setup logging
script_root = Path(__file__).parent.parent.parent
log_dir = script_root / "out" / "logs"
log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_dir / f"raptor_frida_{int(time.time())}.log")
    ]
)
logger = logging.getLogger("frida")


class FridaScanner:
    """RAPTOR Frida scanner for dynamic instrumentation."""

    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize Frida scanner.

        Args:
            output_dir: Directory for output files
        """
        self.script_root = Path(__file__).parent.parent.parent
        self.templates_dir = Path(__file__).parent / "templates"
        self.output_dir = output_dir or (self.script_root / "out" / f"frida_scan_{int(time.time())}")
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.findings: List[Dict[str, Any]] = []

        logger.info("Frida scanner initialized")
        logger.info(f"Output directory: {self.output_dir}")

    def attach_to_process(self, target: str) -> frida.core.Session:
        """
        Attach to a running process.

        Args:
            target: Process ID (int) or process name (str)

        Returns:
            Frida session
        """
        try:
            # Try as PID first
            if target.isdigit():
                pid = int(target)
                logger.info(f"Attaching to PID {pid}...")
                self.session = frida.attach(pid)
            else:
                # Try as process name
                logger.info(f"Attaching to process '{target}'...")
                self.session = frida.attach(target)

            logger.info(f"✓ Attached to process successfully")
            return self.session

        except frida.ProcessNotFoundError:
            logger.error(f"✗ Process not found: {target}")
            raise
        except Exception as e:
            logger.error(f"✗ Failed to attach: {e}")
            raise

    def spawn_process(self, binary_path: str, args: List[str] = None) -> frida.core.Session:
        """
        Spawn a new process and attach.

        Args:
            binary_path: Path to binary to spawn
            args: Command-line arguments for the binary

        Returns:
            Frida session
        """
        try:
            logger.info(f"Spawning process: {binary_path}")
            if args:
                logger.info(f"Arguments: {' '.join(args)}")

            pid = frida.spawn([binary_path] + (args or []))
            self.session = frida.attach(pid)
            logger.info(f"✓ Spawned process (PID {pid})")

            return self.session

        except Exception as e:
            logger.error(f"✗ Failed to spawn process: {e}")
            raise

    def load_script(self, script_source: str, script_name: str = "custom") -> frida.core.Script:
        """
        Load and run a Frida script.

        Args:
            script_source: JavaScript source code
            script_name: Name for the script (for logging)

        Returns:
            Loaded Frida script
        """
        if not self.session:
            raise RuntimeError("No active session. Attach to a process first.")

        try:
            logger.info(f"Loading script: {script_name}")
            self.script = self.session.create_script(script_source)
            self.script.on('message', self._on_message)
            self.script.load()
            logger.info(f"✓ Script loaded and running")

            return self.script

        except Exception as e:
            logger.error(f"✗ Failed to load script: {e}")
            raise

    def load_template(self, template_name: str) -> frida.core.Script:
        """
        Load a built-in Frida script template.

        Args:
            template_name: Name of the template (without .js extension)

        Returns:
            Loaded Frida script
        """
        template_path = self.templates_dir / f"{template_name}.js"

        if not template_path.exists():
            available = [f.stem for f in self.templates_dir.glob("*.js")]
            logger.error(f"✗ Template not found: {template_name}")
            logger.info(f"Available templates: {', '.join(available)}")
            raise FileNotFoundError(f"Template not found: {template_name}")

        script_source = template_path.read_text()
        return self.load_script(script_source, script_name=template_name)

    def _on_message(self, message: Dict, data: Optional[bytes]):
        """
        Handle messages from Frida script.

        Args:
            message: Message dict from Frida
            data: Optional binary data
        """
        msg_type = message.get('type')

        if msg_type == 'send':
            payload = message.get('payload', {})

            # Log the message
            if isinstance(payload, dict):
                level = payload.get('level', 'info')
                text = payload.get('message', str(payload))

                if level == 'error':
                    logger.error(f"[Script] {text}")
                elif level == 'warning':
                    logger.warning(f"[Script] {text}")
                else:
                    logger.info(f"[Script] {text}")

                # Store findings
                if payload.get('type') == 'finding':
                    self.findings.append(payload)
                    logger.info(f"✓ Finding recorded: {payload.get('title', 'Unnamed')}")
            else:
                logger.info(f"[Script] {payload}")

        elif msg_type == 'error':
            stack = message.get('stack', 'No stack trace')
            logger.error(f"[Script Error] {message.get('description', 'Unknown error')}")
            logger.error(f"Stack trace:\n{stack}")

    def resume_process(self):
        """Resume a spawned process."""
        if self.session:
            try:
                device = frida.get_local_device()
                device.resume(self.session._impl.pid)
                logger.info("✓ Process resumed")
            except Exception as e:
                logger.warning(f"Could not resume process: {e}")

    def detach(self):
        """Detach from the process."""
        if self.script:
            try:
                self.script.unload()
                logger.info("✓ Script unloaded")
            except:
                pass

        if self.session:
            try:
                self.session.detach()
                logger.info("✓ Detached from process")
            except:
                pass

    def generate_report(self) -> Path:
        """
        Generate a JSON report of findings.

        Returns:
            Path to the report file
        """
        report_path = self.output_dir / "frida_report.json"

        report = {
            "tool": "RAPTOR Frida Scanner",
            "version": "1.0.0",
            "timestamp": time.time(),
            "findings_count": len(self.findings),
            "findings": self.findings
        }

        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"✓ Report saved: {report_path}")
        return report_path

    def print_summary(self):
        """Print scan summary."""
        print("\n" + "="*70)
        print("FRIDA SCAN COMPLETE")
        print("="*70)
        print(f"✓ Findings: {len(self.findings)}")
        print(f"✓ Output: {self.output_dir}")
        print("="*70 + "\n")


def main():
    """Main entry point for Frida scanner."""
    parser = argparse.ArgumentParser(
        description="RAPTOR Frida Dynamic Instrumentation Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Attach to running process by PID
  python3 scanner.py --attach 1234 --template api-trace

  # Attach to process by name
  python3 scanner.py --attach Safari --template ssl-unpin

  # Spawn and instrument a binary
  python3 scanner.py --spawn /usr/local/bin/myapp --template memory-scan

  # Use custom script
  python3 scanner.py --attach 1234 --script my_hook.js

  # Mobile app instrumentation
  python3 scanner.py --attach com.example.app --template mobile-basics

Available Templates:
  api-trace       - Trace API calls
  ssl-unpin       - SSL certificate pinning bypass
  memory-scan     - Memory scanning and dumping
  crypto-trace    - Cryptographic operations tracing
  mobile-basics   - Basic mobile app instrumentation
  anti-debug      - Anti-debugging bypass
        """
    )

    # Target selection
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--attach', metavar='TARGET',
                             help='Attach to running process (PID or name)')
    target_group.add_argument('--spawn', metavar='BINARY',
                             help='Spawn new process from binary')

    # Script selection
    script_group = parser.add_mutually_exclusive_group()
    script_group.add_argument('--template', metavar='NAME',
                             help='Use built-in template script')
    script_group.add_argument('--script', metavar='PATH',
                             help='Load custom Frida script')

    # Options
    parser.add_argument('--args', nargs='+',
                       help='Arguments for spawned process')
    parser.add_argument('--duration', type=int, default=30,
                       help='Run duration in seconds (default: 30)')
    parser.add_argument('--out', metavar='DIR',
                       help='Output directory')
    parser.add_argument('--no-resume', action='store_true',
                       help='Don\'t resume spawned process')

    args = parser.parse_args()

    # Initialize scanner
    output_dir = Path(args.out) if args.out else None
    scanner = FridaScanner(output_dir=output_dir)

    try:
        # Attach or spawn
        if args.attach:
            scanner.attach_to_process(args.attach)
        else:
            scanner.spawn_process(args.spawn, args.args or [])

        # Load script
        if args.template:
            scanner.load_template(args.template)
        elif args.script:
            script_path = Path(args.script)
            if not script_path.exists():
                logger.error(f"✗ Script not found: {script_path}")
                return 1
            script_source = script_path.read_text()
            scanner.load_script(script_source, script_name=script_path.name)
        else:
            # Default: basic tracing
            logger.info("No script specified, using basic API tracing")
            scanner.load_template('api-trace')

        # Resume if spawned
        if args.spawn and not args.no_resume:
            scanner.resume_process()

        # Run for specified duration
        logger.info(f"Running for {args.duration} seconds...")
        logger.info("Press Ctrl+C to stop early")
        time.sleep(args.duration)

    except KeyboardInterrupt:
        logger.info("\n✓ Stopped by user")
    except Exception as e:
        logger.error(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        scanner.detach()
        scanner.generate_report()
        scanner.print_summary()

    return 0


if __name__ == "__main__":
    sys.exit(main())
