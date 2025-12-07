# Automatic radare2 Installation

RAPTOR automatically installs radare2 when not found on your system.

## Supported Platforms

- **macOS**: Homebrew (brew install radare2)
- **Ubuntu/Debian**: apt (sudo apt install radare2)
- **Fedora/RHEL**: dnf (sudo dnf install radare2)
- **Arch Linux**: pacman (sudo pacman -S radare2)

## Installation Modes

### Background Installation
If objdump is available as a fallback, radare2 installs in the background:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)
# Uses objdump temporarily while radare2 installs in background
# Check if ready: analyser.is_radare2_ready()
# Reload after install: analyser.reload_radare2()
```

### Foreground Installation
If no fallback is available, installation runs synchronously:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)
# Blocks until radare2 is installed (30-300 seconds)
```

## Disabling Auto-Install

Set environment variable to disable automatic installation:

```bash
export RAPTOR_NO_AUTO_INSTALL=1
```

Or install radare2 manually before running RAPTOR:

```bash
# macOS
brew install radare2

# Ubuntu/Debian
sudo apt install -y radare2

# Fedora/RHEL
sudo dnf install -y radare2

# Arch Linux
sudo pacman -S radare2
```

## CI/CD Integration

Automatic installation is automatically disabled in CI environments when sudo is required.

### GitHub Actions

```yaml
- name: Install radare2
  run: brew install radare2  # macOS
  # or: sudo apt-get install -y radare2  # Linux

- name: Run tests
  env:
    RAPTOR_NO_AUTO_INSTALL: 1
  run: pytest
```

### GitLab CI

```yaml
before_script:
  - apt-get update && apt-get install -y radare2

test:
  variables:
    RAPTOR_NO_AUTO_INSTALL: "1"
  script:
    - pytest
```

### Docker

```dockerfile
# Install radare2 in Dockerfile
RUN apt-get update && apt-get install -y radare2

# Disable auto-install
ENV RAPTOR_NO_AUTO_INSTALL=1
```

## API Reference

### is_radare2_ready()
Check if radare2 is available and initialized:
```python
if analyser.is_radare2_ready():
    # Use radare2 features
else:
    # Wait or use fallback
```

### reload_radare2()
Attempt to initialize radare2 after background installation:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)
time.sleep(60)  # Wait for background install

if analyser.reload_radare2():
    # radare2 now available
    print("Enhanced features enabled")
```

### get_install_status()
Get detailed installation status information:
```python
status = analyser.get_install_status()

# Status dictionary contains:
# - in_progress (bool): Installation currently running
# - success (bool|None): True if succeeded, False if failed, None if not attempted
# - error (str|None): Error message if failed
# - timestamp (float|None): When installation started (Unix timestamp)
# - duration (float|None): How long installation took/is taking (seconds)

if status["in_progress"]:
    print(f"Installing... ({status['duration']:.1f}s elapsed)")
elif status["success"]:
    print(f"Installed successfully in {status['duration']:.1f}s")
elif status["success"] is False:
    print(f"Installation failed: {status['error']}")
else:
    print("No installation attempted")
```

### cancel_install()
Cancel background installation if running:
```python
analyser = CrashAnalyser(binary_path, use_radare2=True)

# Wait a bit
time.sleep(5)

# User decides to cancel
if analyser.cancel_install():
    print("Installation cancelled")

# Check status
status = analyser.get_install_status()
if status["error"] == "Cancelled by user":
    print("Confirmed: installation was cancelled")
```

Returns `True` if cancellation was initiated, `False` if nothing to cancel.

**Note:** Cancellation is graceful and thread-safe. The installation thread checks the cancellation flag before major operations and exits cleanly.

## Troubleshooting

### Installation Fails

Check:
1. Internet connection available
2. Package manager is installed and working (brew, apt, dnf, pacman)
3. Sufficient disk space (500MB minimum)
4. sudo password entered if prompted (Linux only)

### Installation Hangs in CI

Solution: Install radare2 manually in your CI setup and set RAPTOR_NO_AUTO_INSTALL=1

### radare2 Installed But Not Detected

Solution: Ensure radare2 (or r2) is in your PATH:
```bash
which r2  # Should show path to radare2
echo $PATH  # Should include /usr/local/bin or similar
```

### Cancellation Not Working

If `cancel_install()` returns `False` when you expect it to work:

1. Check installation status first:
```python
status = analyser.get_install_status()
if not status["in_progress"]:
    print("No installation running to cancel")
```

2. Cancellation only works during **background installation**:
   - **Background installation** (can cancel): When objdump is available as fallback, installation runs in a separate thread
   - **Foreground installation** (cannot cancel): When no fallback tool available, installation blocks synchronously (no thread to cancel)

3. The installation thread may have already completed between checking status and calling cancel.

## Security Considerations

### Sudo Usage (Linux)

Automatic installation on Linux requires sudo privileges:
```bash
sudo apt install -y radare2  # Prompts for password
```

If you don't want to provide sudo access:
1. Install radare2 manually before running RAPTOR
2. Disable auto-install: export RAPTOR_NO_AUTO_INSTALL=1

### CI/CD Safety

In CI environments, sudo installation is automatically skipped to prevent:
- Password prompts that hang the pipeline
- Unexpected privilege escalation
- Installation failures in restricted environments

Detected CI environments:
- GitHub Actions (GITHUB_ACTIONS)
- GitLab CI (GITLAB_CI)
- CircleCI (CIRCLECI)
- Travis CI (TRAVIS)
- Jenkins (JENKINS_HOME)
- And others (CI, CONTINUOUS_INTEGRATION)

## Implementation Details

### Installation Process

1. Platform detection (macOS, Linux, Windows)
2. Package manager detection (brew, apt, dnf, pacman)
3. CI environment check (skip sudo if CI detected)
4. Installation execution (with 5-minute timeout)
5. Verification (r2 -v check)

### Code Duplication Eliminated

All platform-specific installation logic uses a single `_install_package()` helper method, reducing duplication from 80% to near 0%.

### Error Handling

- Timeouts after 5 minutes
- Graceful fallback to objdump
- Clear error messages with manual installation URLs
- No crashes on installation failure

## Test Coverage

Comprehensive test suite (34 tests) covering:
- Environment variable handling (RAPTOR_NO_AUTO_INSTALL)
- CI detection (GitHub Actions, GitLab CI, CircleCI, etc.)
- Package installation (brew, apt, dnf, pacman)
- Installation verification
- Reload functionality
- Background vs foreground modes
- Error scenarios (timeout, failure, no package manager)
- Installation status API (get_install_status)
- Cancellation API (cancel_install)
- State tracking and transitions
- Duration calculation

Run tests:
```bash
pytest test/test_crash_analyser_install.py -v
```
