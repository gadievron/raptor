#!/usr/bin/env python3
"""
RAPTOR Doctor - Dependency Checker and Auto-Installer

Checks all RAPTOR dependencies:
- Python packages
- External tools (Semgrep, CodeQL, AFL++, Frida, etc.)
- API keys
- System requirements
- File permissions

Offers to install missing dependencies automatically.
"""

import sys
import subprocess
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import os
import json

# Color codes for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'


class Dependency:
    """Represents a single dependency."""

    def __init__(self, name: str, check_command: List[str],
                 install_command: Optional[List[str]] = None,
                 required: bool = True, category: str = "tool"):
        self.name = name
        self.check_command = check_command
        self.install_command = install_command
        self.required = required
        self.category = category
        self.installed = False
        self.version = None
        self.error = None


class RAPTORDoctor:
    """Checks and installs RAPTOR dependencies."""

    def __init__(self, auto_install: bool = False):
        self.auto_install = auto_install
        self.dependencies: Dict[str, Dependency] = {}
        self.results = {
            'passed': [],
            'failed': [],
            'warnings': []
        }

        self._define_dependencies()

    def _define_dependencies(self):
        """Define all RAPTOR dependencies."""

        # Python packages - use sys.executable to check in same Python environment
        python_exe = sys.executable

        # Version check script that handles packages without __version__
        version_check = '''
import sys
try:
    import {module}
    # Try __version__ first
    if hasattr({module}, "__version__"):
        print({module}.__version__)
    else:
        # Fall back to importlib.metadata
        try:
            from importlib.metadata import version
            print(version("{package}"))
        except:
            print("installed")
except ImportError:
    sys.exit(1)
'''

        python_packages = [
            ('requests', [python_exe, '-c', version_check.format(module='requests', package='requests')],
             [python_exe, '-m', 'pip', 'install', 'requests'], True),
            ('litellm', [python_exe, '-c', version_check.format(module='litellm', package='litellm')],
             [python_exe, '-m', 'pip', 'install', 'litellm'], True),
            ('instructor', [python_exe, '-c', version_check.format(module='instructor', package='instructor')],
             [python_exe, '-m', 'pip', 'install', 'instructor'], True),
            ('pydantic', [python_exe, '-c', version_check.format(module='pydantic', package='pydantic')],
             [python_exe, '-m', 'pip', 'install', 'pydantic'], True),
            ('frida-tools', [python_exe, '-c', version_check.format(module='frida', package='frida-tools')],
             [python_exe, '-m', 'pip', 'install', 'frida-tools'], True),
            ('beautifulsoup4', [python_exe, '-c', version_check.format(module='bs4', package='beautifulsoup4')],
             [python_exe, '-m', 'pip', 'install', 'beautifulsoup4'], False),
            ('playwright', [python_exe, '-c', version_check.format(module='playwright', package='playwright')],
             [python_exe, '-m', 'pip', 'install', 'playwright'], False),
        ]

        for pkg_name, check_cmd, install_cmd, required in python_packages:
            self.dependencies[f'python-{pkg_name}'] = Dependency(
                pkg_name, check_cmd, install_cmd, required, 'python'
            )

        # External tools
        self.dependencies['semgrep'] = Dependency(
            'Semgrep',
            ['semgrep', '--version'],
            ['brew', 'install', 'semgrep'] if sys.platform == 'darwin' else ['pip', 'install', 'semgrep'],
            required=True,
            category='static-analysis'
        )

        self.dependencies['codeql'] = Dependency(
            'CodeQL',
            ['codeql', 'version'],
            ['brew', 'install', 'codeql'] if sys.platform == 'darwin' else None,
            required=False,
            category='static-analysis'
        )

        self.dependencies['afl++'] = Dependency(
            'AFL++',
            ['afl-fuzz', '-h'],
            ['brew', 'install', 'afl++'] if sys.platform == 'darwin' else None,
            required=False,
            category='fuzzing'
        )

        self.dependencies['frida-server'] = Dependency(
            'Frida (CLI)',
            ['frida', '--version'],
            None,  # Installed with frida-tools Python package
            required=True,
            category='dynamic'
        )

        self.dependencies['ollama'] = Dependency(
            'Ollama',
            ['ollama', '--version'],
            ['brew', 'install', 'ollama'] if sys.platform == 'darwin' else None,
            required=False,
            category='llm'
        )

        self.dependencies['nmap'] = Dependency(
            'Nmap',
            ['nmap', '--version'],
            ['brew', 'install', 'nmap'] if sys.platform == 'darwin' else None,
            required=False,
            category='network'
        )

        self.dependencies['binwalk'] = Dependency(
            'Binwalk',
            ['binwalk', '-h'],
            ['brew', 'install', 'binwalk'] if sys.platform == 'darwin' else None,
            required=False,
            category='binary-analysis'
        )

        # System tools (usually pre-installed)
        self.dependencies['git'] = Dependency(
            'Git',
            ['git', '--version'],
            None,
            required=True,
            category='system'
        )

        self.dependencies['python3'] = Dependency(
            'Python 3',
            ['python3', '--version'],
            None,
            required=True,
            category='system'
        )

    def check_dependency(self, dep: Dependency) -> bool:
        """
        Check if a dependency is installed.

        Args:
            dep: Dependency to check

        Returns:
            True if installed, False otherwise
        """
        try:
            result = subprocess.run(
                dep.check_command,
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                # Extract version from output
                output = result.stdout.strip() or result.stderr.strip()
                dep.version = output.split('\n')[0] if output else 'installed'
                dep.installed = True
                return True
            else:
                dep.installed = False
                dep.error = "Command failed"
                return False

        except FileNotFoundError:
            dep.installed = False
            dep.error = "Command not found"
            return False
        except subprocess.TimeoutExpired:
            dep.installed = False
            dep.error = "Command timeout"
            return False
        except Exception as e:
            dep.installed = False
            dep.error = str(e)
            return False

    def install_dependency(self, dep: Dependency) -> bool:
        """
        Install a missing dependency.

        Args:
            dep: Dependency to install

        Returns:
            True if installation succeeded, False otherwise
        """
        if not dep.install_command:
            print(f"{Colors.YELLOW}⚠ No auto-install available for {dep.name}{Colors.END}")
            return False

        print(f"{Colors.BLUE}📦 Installing {dep.name}...{Colors.END}")

        try:
            result = subprocess.run(
                dep.install_command,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes max
            )

            if result.returncode == 0:
                print(f"{Colors.GREEN}✓ {dep.name} installed successfully{Colors.END}")
                # Re-check to confirm
                return self.check_dependency(dep)
            else:
                print(f"{Colors.RED}✗ Failed to install {dep.name}{Colors.END}")
                print(f"  Error: {result.stderr}")
                return False

        except Exception as e:
            print(f"{Colors.RED}✗ Error installing {dep.name}: {e}{Colors.END}")
            return False

    def check_api_keys(self) -> Dict[str, bool]:
        """Check for required API keys in environment."""
        keys = {
            'ANTHROPIC_API_KEY': os.getenv('ANTHROPIC_API_KEY'),
            'OPENAI_API_KEY': os.getenv('OPENAI_API_KEY'),
            'OLLAMA_HOST': os.getenv('OLLAMA_HOST')
        }

        results = {}
        for key, value in keys.items():
            results[key] = value is not None and len(value) > 0

        return results

    def check_permissions(self) -> Dict[str, bool]:
        """Check file permissions for RAPTOR directories."""
        raptor_root = Path(__file__).parent

        checks = {
            'raptor_readable': os.access(raptor_root, os.R_OK),
            'raptor_writable': os.access(raptor_root, os.W_OK),
            'out_dir_exists': (raptor_root / 'out').exists(),
            'out_dir_writable': os.access(raptor_root / 'out', os.W_OK) if (raptor_root / 'out').exists() else False
        }

        return checks

    def check_python_version(self) -> Tuple[bool, str]:
        """Check if Python version is sufficient."""
        version = sys.version_info

        if version.major < 3 or (version.major == 3 and version.minor < 8):
            return False, f"{version.major}.{version.minor}.{version.micro}"

        return True, f"{version.major}.{version.minor}.{version.micro}"

    def run_health_check(self) -> Dict[str, any]:
        """
        Run complete health check.

        Returns:
            Health check results
        """
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}RAPTOR Doctor - Dependency Health Check{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

        # Check Python version
        print(f"{Colors.BOLD}1. Python Version{Colors.END}")
        py_ok, py_version = self.check_python_version()
        if py_ok:
            print(f"{Colors.GREEN}✓ Python {py_version} (sufficient){Colors.END}")
        else:
            print(f"{Colors.RED}✗ Python {py_version} (need >= 3.8){Colors.END}")

        # Check dependencies by category
        categories = {
            'python': 'Python Packages',
            'static-analysis': 'Static Analysis Tools',
            'dynamic': 'Dynamic Analysis Tools',
            'fuzzing': 'Fuzzing Tools',
            'llm': 'LLM Tools',
            'network': 'Network Tools',
            'binary-analysis': 'Binary Analysis Tools',
            'system': 'System Tools'
        }

        for category, title in categories.items():
            deps_in_category = [d for d in self.dependencies.values() if d.category == category]
            if not deps_in_category:
                continue

            print(f"\n{Colors.BOLD}2. {title}{Colors.END}")

            for dep in deps_in_category:
                is_installed = self.check_dependency(dep)

                if is_installed:
                    print(f"{Colors.GREEN}✓ {dep.name:20} {dep.version}{Colors.END}")
                    self.results['passed'].append(dep.name)
                else:
                    if dep.required:
                        print(f"{Colors.RED}✗ {dep.name:20} NOT FOUND (REQUIRED){Colors.END}")
                        self.results['failed'].append(dep.name)

                        # Offer to install
                        if self.auto_install and dep.install_command:
                            self.install_dependency(dep)
                    else:
                        print(f"{Colors.YELLOW}⚠ {dep.name:20} NOT FOUND (optional){Colors.END}")
                        self.results['warnings'].append(dep.name)

        # Check API keys
        print(f"\n{Colors.BOLD}3. API Keys{Colors.END}")
        api_keys = self.check_api_keys()

        for key, present in api_keys.items():
            if present:
                # Mask the key
                value = os.getenv(key)
                masked = value[:10] + '...' + value[-4:] if len(value) > 14 else '***'
                print(f"{Colors.GREEN}✓ {key:25} {masked}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}⚠ {key:25} NOT SET{Colors.END}")

        # Check permissions
        print(f"\n{Colors.BOLD}4. File Permissions{Colors.END}")
        perms = self.check_permissions()

        for check, result in perms.items():
            status = f"{Colors.GREEN}✓" if result else f"{Colors.RED}✗"
            print(f"{status} {check:25}{Colors.END}")

        # Summary
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.BOLD}Summary{Colors.END}")
        print(f"{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.GREEN}✓ Passed: {len(self.results['passed'])}{Colors.END}")
        print(f"{Colors.YELLOW}⚠ Warnings: {len(self.results['warnings'])}{Colors.END}")
        print(f"{Colors.RED}✗ Failed: {len(self.results['failed'])}{Colors.END}")

        if self.results['failed']:
            print(f"\n{Colors.RED}Required dependencies missing!{Colors.END}")
            print(f"Run with --install to auto-install missing dependencies")
            return {'status': 'failed', 'results': self.results}
        elif self.results['warnings']:
            print(f"\n{Colors.YELLOW}Some optional dependencies missing{Colors.END}")
            print(f"RAPTOR will work but some features may be unavailable")
            return {'status': 'warnings', 'results': self.results}
        else:
            print(f"\n{Colors.GREEN}✓ All required dependencies satisfied!{Colors.END}")
            return {'status': 'passed', 'results': self.results}

    def generate_install_script(self, output_path: Path):
        """Generate a shell script to install all missing dependencies."""
        missing = [dep for dep in self.dependencies.values()
                  if not dep.installed and dep.install_command]

        if not missing:
            print(f"{Colors.GREEN}No missing dependencies to install{Colors.END}")
            return

        script_lines = [
            "#!/bin/bash",
            "# RAPTOR Dependency Installation Script",
            "# Generated by raptor_doctor.py",
            "",
            "set -e  # Exit on error",
            "",
            "echo 'Installing RAPTOR dependencies...'",
            ""
        ]

        for dep in missing:
            script_lines.append(f"# Install {dep.name}")
            script_lines.append(f"echo 'Installing {dep.name}...'")
            script_lines.append(' '.join(dep.install_command))
            script_lines.append("")

        script_lines.append("echo '✓ All dependencies installed!'")

        output_path.write_text('\n'.join(script_lines))
        output_path.chmod(0o755)  # Make executable

        print(f"{Colors.GREEN}✓ Install script saved to: {output_path}{Colors.END}")
        print(f"Run: ./{output_path.name}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Doctor - Check and install dependencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check dependencies
  python3 raptor_doctor.py

  # Auto-install missing dependencies
  python3 raptor_doctor.py --install

  # Generate install script
  python3 raptor_doctor.py --generate-script install_deps.sh

  # JSON output for automation
  python3 raptor_doctor.py --json
        """
    )

    parser.add_argument('--install', action='store_true',
                       help='Automatically install missing dependencies')
    parser.add_argument('--generate-script', metavar='FILE',
                       help='Generate install script instead of running checks')
    parser.add_argument('--json', action='store_true',
                       help='Output results as JSON')

    args = parser.parse_args()

    doctor = RAPTORDoctor(auto_install=args.install)

    if args.generate_script:
        doctor.run_health_check()
        doctor.generate_install_script(Path(args.generate_script))
        return 0

    results = doctor.run_health_check()

    if args.json:
        print(json.dumps(results, indent=2))

    # Exit code based on results
    if results['status'] == 'failed':
        return 1
    elif results['status'] == 'warnings':
        return 0  # Warnings are OK
    else:
        return 0


if __name__ == "__main__":
    sys.exit(main())
